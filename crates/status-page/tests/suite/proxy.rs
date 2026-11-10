use crate::harness::{call, published_state, request, state_with};
use crate::types::{Server, TestResult};
use axum::http::StatusCode;
use ipnet::IpNet;
use ppp::v2::{Builder, Command, Protocol, Version};
use status_page::limiter::wide_key;
use status_page::model::{PageSettings, PageState, ProxyOutcome};
use status_page::proxy::{is_trusted, parse_header, read_header};
use status_page::serve::{admit_connection, serve};
use status_page::server::status_router;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;


const PROXY_COMMAND: u8 = 0x21;


const LOCAL_COMMAND: u8 = 0x20;


const UNSPECIFIED_FAMILY: u8 = 0x00;


const IPV4_STREAM: u8 = 0x11;


const MAX_HEADER: usize = 512;


const WIDE_BITS: u8 = 48;


const FULL_BITS: u8 = 64;


const SECOND: usize = 2;


const THIRD: usize = 3;


const CLIENT_PORT: u16 = 1000;


const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";


const SETTLE_ROUNDS: usize = 1000;


const SHORT_SECONDS: u64 = 2;


const LONG_SECONDS: u64 = 1000;


const HUGE_LENGTH: u16 = 60_000;


const WIDE_MULTIPLIER: u32 = 2;


const GARBAGE_BYTES: usize = 40;


fn trusting(extra: PageSettings) -> Result<PageSettings, Box<dyn std::error::Error>> {
    Ok(PageSettings {
        trusted_proxies: vec!["127.0.0.0/8".parse::<IpNet>()?],
        ..extra
    })
}


fn proxy_header(client: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let source = SocketAddr::new(client.parse()?, CLIENT_PORT);
    let destination: SocketAddr = if source.is_ipv4() {
        "192.0.2.1:443".parse()?
    } else {
        "[2001:db8::1]:443".parse()?
    };
    Ok(Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, (source, destination)).build()?)
}


async fn start(settings: PageSettings) -> Result<Server, Box<dyn std::error::Error>> {
    let (state, _clock) = published_state(settings, "proxied")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let shutdown = Box::pin(async {
        stopped.await.inspect_err(|error| tracing::warn!(%error, "stop signal dropped")).ok();
    });
    tokio::spawn(serve(
        Box::pin(TcpListenerStream::new(listener)),
        status_router(Arc::clone(&state)),
        Arc::clone(&state),
        shutdown,
    ));
    Ok((address, state, stop))
}


async fn exchange(address: SocketAddr, prefix: &[u8], text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(prefix).await?;
    stream.write_all(text.as_bytes()).await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .await
        .inspect_err(|error| tracing::warn!(%error, "read ended early"))
        .ok();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


async fn settle(state: &PageState, wanted: usize) {
    for _round in 0..SETTLE_ROUNDS {
        if state.active.load(Ordering::SeqCst) != wanted {
            tokio::task::yield_now().await;
        }
    }
}


#[test]
fn trust_follows_the_cidr_list_and_unmaps_ipv4() -> TestResult {
    let proxies: Vec<IpNet> = vec!["10.0.0.0/8".parse()?, "2001:db8::/32".parse()?];
    assert!(is_trusted(&proxies, "10.1.2.3".parse()?));
    assert!(is_trusted(&proxies, "::ffff:10.1.2.3".parse()?));
    assert!(is_trusted(&proxies, "2001:db8::5".parse()?));
    assert!(!is_trusted(&proxies, "192.0.2.1".parse()?));
    assert!(!is_trusted(&[], "10.1.2.3".parse()?));
    Ok(())
}


#[test]
fn a_complete_header_gives_the_client_or_is_malformed() -> TestResult {
    assert_eq!(
        parse_header(&proxy_header("198.51.100.7")?),
        ProxyOutcome::Client("198.51.100.7".parse()?)
    );
    assert_eq!(
        parse_header(&proxy_header("2001:db8:1:2::9")?),
        ProxyOutcome::Client("2001:db8:1:2::9".parse()?)
    );
    assert_eq!(
        parse_header(&Builder::new(LOCAL_COMMAND, UNSPECIFIED_FAMILY).build()?),
        ProxyOutcome::Local
    );
    assert_eq!(
        parse_header(&Builder::new(PROXY_COMMAND, UNSPECIFIED_FAMILY).build()?),
        ProxyOutcome::Malformed
    );
    assert_eq!(parse_header(b"GET / HTTP/1.1\r\n"), ProxyOutcome::Malformed);
    assert_eq!(parse_header(b""), ProxyOutcome::Malformed);
    Ok(())
}


#[tokio::test]
async fn the_header_is_bounded_before_the_rest_is_read() -> TestResult {
    let good = proxy_header("198.51.100.7")?;
    let mut reader = good.as_slice();
    assert_eq!(read_header(&mut reader, good.len()).await?, ProxyOutcome::Client("198.51.100.7".parse()?));
    let mut tight = good.as_slice();
    assert_eq!(read_header(&mut tight, good.len() - 1).await?, ProxyOutcome::Malformed);
    let huge = Builder::new(PROXY_COMMAND, IPV4_STREAM).set_length(HUGE_LENGTH).build()?;
    let mut hugely = huge.as_slice();
    assert_eq!(read_header(&mut hugely, MAX_HEADER).await?, ProxyOutcome::Malformed);
    let mut text = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".as_slice();
    assert_eq!(read_header(&mut text, MAX_HEADER).await?, ProxyOutcome::Malformed);
    let mut short = good.get(..good.len() - 1).ok_or("short")?;
    assert!(read_header(&mut short, MAX_HEADER).await.is_err());
    let mut nothing = b"".as_slice();
    assert!(read_header(&mut nothing, MAX_HEADER).await.is_err());
    Ok(())
}


#[test]
fn the_wide_key_groups_ipv6_by_the_named_prefix_and_leaves_ipv4_alone() -> TestResult {
    let one: IpAddr = "2001:db8:1:1::1".parse()?;
    let two: IpAddr = "2001:db8:1:ffff::2".parse()?;
    let other: IpAddr = "2001:db8:2::1".parse()?;
    assert_eq!(wide_key(one, WIDE_BITS), wide_key(two, WIDE_BITS));
    assert_ne!(wide_key(one, WIDE_BITS), wide_key(other, WIDE_BITS));
    assert_ne!(wide_key(one, FULL_BITS), wide_key(two, FULL_BITS));
    assert_eq!(wide_key(one, 0), Some("::".parse()?));
    assert_eq!(wide_key("::ffff:192.0.2.1".parse()?, WIDE_BITS), None);
    assert_eq!(wide_key("192.0.2.1".parse()?, WIDE_BITS), None);
    Ok(())
}


#[tokio::test]
async fn a_trusted_proxy_names_the_client_whose_bucket_is_used() -> TestResult {
    let settings = trusting(PageSettings {
        rate_per_second: 1,
        burst: 1,
        ..PageSettings::default()
    })?;
    let (address, _state, _stop) = start(settings).await?;
    let first = exchange(address, &proxy_header("198.51.100.1")?, GET).await?;
    let again = exchange(address, &proxy_header("198.51.100.1")?, GET).await?;
    let other = exchange(address, &proxy_header("198.51.100.2")?, GET).await?;
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert!(again.starts_with("HTTP/1.1 429"), "{again}");
    assert!(other.starts_with("HTTP/1.1 200"), "{other}");
    let same_prefix = exchange(address, &proxy_header("2001:db8:0:1::1")?, GET).await?;
    let same_prefix_again = exchange(address, &proxy_header("2001:db8:0:1::ffff")?, GET).await?;
    assert!(same_prefix.starts_with("HTTP/1.1 200"));
    assert!(same_prefix_again.starts_with("HTTP/1.1 429"));
    Ok(())
}


#[tokio::test]
async fn a_forged_header_from_an_untrusted_peer_is_just_garbage() -> TestResult {
    let settings = PageSettings {
        rate_per_second: 1,
        burst: 1,
        ..PageSettings::default()
    };
    let (address, state, _stop) = start(settings).await?;
    let forged = exchange(address, &proxy_header("198.51.100.1")?, GET).await?;
    assert!(!forged.contains("200 OK"), "{forged}");
    let spoofed = exchange(
        address,
        b"",
        "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let spoofed_again = exchange(
        address,
        b"",
        "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.8\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(spoofed.starts_with("HTTP/1.1 200") || spoofed.starts_with("HTTP/1.1 429"));
    assert!(spoofed_again.starts_with("HTTP/1.1 429"), "{spoofed_again}");
    assert_eq!(state.proxy_malformed.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_trusted_proxy_health_check_is_served_under_the_proxy_address() -> TestResult {
    let (address, _state, _stop) = start(trusting(PageSettings::default())?).await?;
    let local = Builder::new(LOCAL_COMMAND, UNSPECIFIED_FAMILY).build()?;
    assert!(exchange(address, &local, GET).await?.starts_with("HTTP/1.1 200"));
    Ok(())
}


#[tokio::test]
async fn a_malformed_or_oversized_header_from_a_trusted_proxy_is_counted_and_closed() -> TestResult {
    let (address, state, _stop) = start(trusting(PageSettings::default())?).await?;
    let garbage = "x".repeat(GARBAGE_BYTES);
    assert_eq!(exchange(address, b"", &garbage).await?, "");
    assert_eq!(state.proxy_malformed.load(Ordering::SeqCst), 1);
    let huge = Builder::new(PROXY_COMMAND, IPV4_STREAM).set_length(HUGE_LENGTH).build()?;
    assert_eq!(exchange(address, &huge, GET).await?, "");
    assert_eq!(state.proxy_malformed.load(Ordering::SeqCst), SECOND);
    let unspecified = Builder::new(PROXY_COMMAND, UNSPECIFIED_FAMILY).build()?;
    assert_eq!(exchange(address, &unspecified, GET).await?, "");
    assert_eq!(state.proxy_malformed.load(Ordering::SeqCst), THIRD);
    settle(&state, 0).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_proxy_that_hangs_up_inside_the_header_is_dropped_without_a_count() -> TestResult {
    let (address, state, _stop) = start(trusting(PageSettings::default())?).await?;
    let header = proxy_header("198.51.100.1")?;
    let half = header.get(..header.len() / SECOND).ok_or("short")?;
    assert_eq!(exchange(address, half, "").await?, "");
    settle(&state, 0).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.proxy_malformed.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_trusted_proxy_that_never_sends_the_header_is_cut_at_the_deadline() -> TestResult {
    let settings = trusting(PageSettings {
        header_read_timeout_seconds: SHORT_SECONDS,
        connection_timeout_seconds: LONG_SECONDS,
        ..PageSettings::default()
    })?;
    let (address, state, _stop) = start(settings).await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .await
        .inspect_err(|error| tracing::warn!(%error, "read ended early"))
        .ok();
    assert!(started.elapsed() >= Duration::from_secs(SHORT_SECONDS));
    assert!(started.elapsed() < Duration::from_secs(LONG_SECONDS));
    settle(&state, 0).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn waiting_for_a_header_counts_against_the_global_cap_only() -> TestResult {
    let settings = trusting(PageSettings {
        max_connections: SECOND,
        max_connections_per_source: 1,
        ..PageSettings::default()
    })?;
    let (address, state, _stop) = start(settings).await?;
    let first = TcpStream::connect(address).await?;
    let second = TcpStream::connect(address).await?;
    settle(&state, SECOND).await;
    assert_eq!(state.active.load(Ordering::SeqCst), SECOND);
    assert_eq!(exchange(address, &proxy_header("198.51.100.1")?, GET).await?, "");
    drop(first);
    drop(second);
    settle(&state, 0).await;
    assert!(exchange(address, &proxy_header("198.51.100.1")?, GET).await?.starts_with("HTTP/1.1 200"));
    Ok(())
}


#[tokio::test]
async fn the_per_source_connection_cap_follows_the_derived_client() -> TestResult {
    let settings = trusting(PageSettings {
        max_connections_per_source: 1,
        ..PageSettings::default()
    })?;
    let (address, state, _stop) = start(settings).await?;
    let mut holder = TcpStream::connect(address).await?;
    holder.write_all(&proxy_header("198.51.100.1")?).await?;
    holder.write_all(b"GET / HT").await?;
    settle(&state, 1).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 1);
    assert_eq!(exchange(address, &proxy_header("198.51.100.1")?, GET).await?, "");
    assert!(exchange(address, &proxy_header("198.51.100.2")?, GET).await?.starts_with("HTTP/1.1 200"));
    Ok(())
}


#[test]
fn one_wide_prefix_cannot_fill_the_pool_from_many_64s() -> TestResult {
    let settings = PageSettings {
        max_connections_per_source: 1,
        wide_multiplier: WIDE_MULTIPLIER,
        ..PageSettings::default()
    };
    let (state, _clock) = state_with(settings.clone());
    let first = admit_connection(&state, "2001:db8:1:1::1".parse()?, &settings);
    let second = admit_connection(&state, "2001:db8:1:2::1".parse()?, &settings);
    assert!(first.is_some() && second.is_some());
    assert!(admit_connection(&state, "2001:db8:1:3::1".parse()?, &settings).is_none());
    let elsewhere = admit_connection(&state, "2001:db8:2:1::1".parse()?, &settings);
    assert!(elsewhere.is_some());
    assert_eq!(state.wide_sources.lock().map_err(|error| error.to_string())?.len(), SECOND);
    drop(first);
    assert!(admit_connection(&state, "2001:db8:1:3::1".parse()?, &settings).is_some());
    Ok(())
}


#[tokio::test]
async fn one_wide_prefix_shares_a_larger_bucket() -> TestResult {
    let settings = PageSettings {
        rate_per_second: 1,
        burst: 1,
        wide_multiplier: WIDE_MULTIPLIER,
        ..PageSettings::default()
    };
    let (state, _clock) = published_state(settings, "wide")?;
    let router = status_router(state);
    let statuses = [
        "2001:db8:1:1::1",
        "2001:db8:1:2::1",
        "2001:db8:1:3::1",
        "2001:db8:2:1::1",
        "2001:db8:1:1::1",
    ];
    let mut seen = Vec::new();
    for source in statuses {
        seen.push(call(&router, request("GET", "/", Some(source), &[])?).await?.status());
    }
    assert_eq!(
        seen,
        vec![
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    Ok(())
}

use crate::harness::{published_state, small_settings, state_with};
use crate::types::TestResult;
use status_page::model::PageSettings;
use status_page::serve::{accept_connection, serve};
use status_page::server::status_router;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;


const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";


const SETTLE_ROUNDS: usize = 1000;


const FLOOD_BURST: u32 = 2;


const FLOOD_SOURCES: usize = 10;


const SHORT_SECONDS: u64 = 2;


const LONG_SECONDS: u64 = 1000;


const EXTRA_HEADERS: usize = 40;


const HUGE_HEADER: usize = 40_000;


async fn start(
    settings: PageSettings,
) -> Result<(SocketAddr, crate::types::Clock, Arc<status_page::model::PageState>, oneshot::Sender<()>), Box<dyn std::error::Error>> {
    let (state, clock) = published_state(settings, "loop")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let shutdown = Box::pin(async {
        stopped.await.unwrap_or_default();
    });
    tokio::spawn(serve(
        Box::pin(TcpListenerStream::new(listener)),
        status_router(Arc::clone(&state)),
        Arc::clone(&state),
        shutdown,
    ));
    Ok((address, clock, state, stop))
}


async fn exchange(address: SocketAddr, text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(text.as_bytes()).await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap_or_default();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


async fn settle(state: &status_page::model::PageState, wanted: usize) {
    for _round in 0..SETTLE_ROUNDS {
        if state.active.load(Ordering::SeqCst) != wanted {
            tokio::task::yield_now().await;
        }
    }
}


#[tokio::test]
async fn a_loopback_client_gets_the_page() -> TestResult {
    let (address, _clock, state, _stop) = start(PageSettings::default()).await?;
    let answer = exchange(address, GET).await?;
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    assert!(answer.contains("<html>loop</html>"));
    settle(&state, 0).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_loopback_flood_is_limited_per_source() -> TestResult {
    let (address, _clock, _state, _stop) = start(small_settings(1, FLOOD_BURST, FLOOD_SOURCES)).await?;
    let first = exchange(address, GET).await?;
    let second = exchange(address, GET).await?;
    let third = exchange(address, GET).await?;
    assert!(first.starts_with("HTTP/1.1 200"));
    assert!(second.starts_with("HTTP/1.1 200"));
    assert!(third.starts_with("HTTP/1.1 429"), "{third}");
    assert!(third.to_lowercase().contains("retry-after: 1"));
    Ok(())
}


#[tokio::test]
async fn the_connection_cap_refuses_the_next_connection_and_releases() -> TestResult {
    let settings = PageSettings {
        max_connections: 1,
        ..PageSettings::default()
    };
    let (address, _clock, state, _stop) = start(settings).await?;
    let mut holder = TcpStream::connect(address).await?;
    settle(&state, 1).await;
    assert_eq!(state.active.load(Ordering::SeqCst), 1);
    let refused = exchange(address, GET).await?;
    assert_eq!(refused, "");
    holder.write_all(GET.as_bytes()).await?;
    let mut bytes = Vec::new();
    holder.read_to_end(&mut bytes).await?;
    assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 200"));
    settle(&state, 0).await;
    assert!(exchange(address, GET).await?.starts_with("HTTP/1.1 200"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_slow_loris_is_dropped_by_the_header_deadline() -> TestResult {
    let settings = PageSettings {
        header_read_timeout_seconds: SHORT_SECONDS,
        connection_timeout_seconds: LONG_SECONDS,
        ..PageSettings::default()
    };
    let (address, _clock, _state, _stop) = start(settings).await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(b"GET / HT").await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap_or_default();
    assert!(!String::from_utf8_lossy(&bytes).contains("200 OK"));
    assert!(started.elapsed() < Duration::from_secs(LONG_SECONDS));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_idle_connection_is_dropped() -> TestResult {
    let settings = PageSettings {
        header_read_timeout_seconds: SHORT_SECONDS,
        connection_timeout_seconds: LONG_SECONDS,
        ..PageSettings::default()
    };
    let (address, _clock, _state, _stop) = start(settings).await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap_or_default();
    assert!(started.elapsed() < Duration::from_secs(LONG_SECONDS));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_total_deadline_cuts_a_connection_kept_alive() -> TestResult {
    let settings = PageSettings {
        header_read_timeout_seconds: LONG_SECONDS,
        connection_timeout_seconds: SHORT_SECONDS,
        ..PageSettings::default()
    };
    let (address, _clock, state, _stop) = start(settings).await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap_or_default();
    assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 200"));
    assert!(started.elapsed() >= Duration::from_secs(SHORT_SECONDS));
    assert!(started.elapsed() < Duration::from_secs(LONG_SECONDS));
    settle(&state, 0).await;
    Ok(())
}


#[tokio::test]
async fn garbage_and_oversized_headers_never_get_the_page() -> TestResult {
    let (address, _clock, _state, _stop) = start(PageSettings::default()).await?;
    let garbage = exchange(address, "\u{1}\u{2} not http\r\n\r\n").await?;
    assert!(!garbage.contains("200 OK"));
    let many: String = (0..EXTRA_HEADERS).map(|number| format!("X-Extra-{number}: 1\r\n")).collect();
    let crowded = exchange(address, &format!("GET / HTTP/1.1\r\nHost: x\r\n{many}Connection: close\r\n\r\n")).await?;
    assert!(!crowded.contains("200 OK"), "{crowded}");
    let wide = "a".repeat(HUGE_HEADER);
    let heavy = exchange(
        address,
        &format!("GET / HTTP/1.1\r\nHost: x\r\nX-Big: {wide}\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert!(!heavy.contains("200 OK"));
    Ok(())
}


#[tokio::test]
async fn an_unknown_peer_address_drops_the_connection() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let router = status_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let client = TcpStream::connect(address).await?;
    let (server_side, _peer) = listener.accept().await?;
    accept_connection(server_side, Err(io::Error::other("no peer")), &router, &state);
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    drop(client);
    Ok(())
}


#[tokio::test]
async fn an_accept_error_is_logged_and_the_loop_goes_on() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let router = status_router(Arc::clone(&state));
    let incoming = tokio_stream::iter(vec![Err::<TcpStream, io::Error>(io::Error::other("accept failed"))]);
    serve(Box::pin(incoming), router, state, Box::pin(std::future::pending())).await;
    Ok(())
}

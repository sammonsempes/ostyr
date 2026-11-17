#[path = "common/engine.rs"]
mod engine;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use dns_rpz::limits::{REPORT_INTERVAL_SECONDS, UNKNOWN_DOMAIN_EN};
use dns_rpz::model::{ConnectionClass, ServeState};
use dns_rpz::policy::{load_fixed_listen, open_serving_policy, open_with_listen, validate_policy, Policy, SinkholeServer};
use dns_rpz::serve::{accept_connection, accept_one, admit, connection_class, count_class, host_of, report_due, serve, source_key};
use engine::{audit, context, policy_text, replace_file};
use hyper::header::{HeaderValue, HOST};
use hyper::{HeaderMap, Method};
use logging::init_logging;
use sample::sample_policy;
use std::future::pending;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot::{channel, Sender};
use tokio::task::JoinHandle;
use tokio::time::{advance, timeout};
use types::TestResult;


const LISTEN: &str = "127.0.0.1:9";


const BIG_TIMEOUT_MS: u64 = 60_000;


const SHORT_TIMEOUT_MS: u64 = 50;


const BIG_CAP: usize = 100;


const HUGE_LENGTH: &str = "1000000000";


const HEADER_FLOOD: usize = 40;


const BIG_HEADER_BYTES: usize = 20_000;


const THREE: usize = 3;


const NOMINAL_PORT: u16 = 9;


const DUPLEX_BYTES: usize = 1024;


const CHANGED_CAP: usize = 7;


const TWO: u64 = 2;


const SERVER_BLOCK: &str =
    "sinkhole_server:\n  listen: \"127.0.0.1:9\"\n  max_connections: 100\n  max_connections_per_source: 100\n  header_read_timeout_ms: \
                            60000\n  response_timeout_ms: 60000\n";


fn page_block(contact: &str) -> String {
    format!("sinkhole_page:\n  contact: {contact}\n  organisation: Example Org\n")
}


fn server(maximum: usize, per_source: usize, header_ms: u64) -> SinkholeServer {
    SinkholeServer {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, NOMINAL_PORT)),
        max_connections: maximum,
        max_connections_per_source: per_source,
        header_read_timeout_ms: header_ms,
        response_timeout_ms: BIG_TIMEOUT_MS,
    }
}


struct Running {
    address: SocketAddr,
    state: Arc<ServeState>,
    engine: Arc<ReloadEngine<Policy>>,
    stop: Sender<()>,
    task: JoinHandle<()>,
}


async fn start(path: &Path) -> Result<Running, Box<dyn std::error::Error>> {
    init_logging();
    let engine = Arc::new(open_serving_policy(path.to_path_buf(), audit(), context())?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let state = Arc::new(ServeState::default());
    let (stop, shutdown) = channel();
    let task = tokio::spawn(serve(listener, Arc::clone(&engine), Arc::clone(&state), shutdown));
    Ok(Running {
        address,
        state,
        engine,
        stop,
        task,
    })
}


async fn finish(running: Running) -> TestResult {
    running.stop.send(()).map_err(|()| "server already stopped")?;
    running.task.await?;
    Ok(())
}


fn tolerated(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted)
}


async fn read_all(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    match stream.read_to_end(&mut buffer).await {
        Ok(_) => Ok(String::from_utf8_lossy(&buffer).into_owned()),
        Err(error) if tolerated(error.kind()) => Ok(String::from_utf8_lossy(&buffer).into_owned()),
        Err(error) => Err(error.into()),
    }
}


async fn send(stream: &mut TcpStream, bytes: &[u8]) -> TestResult {
    match stream.write_all(bytes).await {
        Err(error) if !tolerated(error.kind()) => Err(error.into()),
        _ => Ok(()),
    }
}


async fn exchange(address: SocketAddr, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    send(&mut stream, request).await?;
    read_all(&mut stream).await
}


fn get(host: &str) -> String {
    format!("GET /any/path?x=1 HTTP/1.1\r\nHost: {host}\r\n\r\n")
}


fn write_policy(directory: &Path, extra: &str) -> Result<std::path::PathBuf, io::Error> {
    let path = directory.join("policy.yaml");
    std::fs::write(&path, policy_text(extra))?;
    Ok(path)
}


async fn loopback_pair() -> Result<(TcpStream, TcpStream), io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (accepted, _) = listener.accept().await?;
    Ok((client, accepted))
}


#[tokio::test]
async fn a_get_for_any_path_gets_the_page_with_every_header() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(
        directory.path(),
        &format!("{SERVER_BLOCK}{}", page_block("help@example.org")),
    )?)
    .await?;
    let text = exchange(running.address, get("Blocked.Example.org").as_bytes()).await?;
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.contains("<strong>blocked.example.org</strong>") && text.contains("help@example.org"));
    let lower = text.to_ascii_lowercase();
    for header in [
        "content-type: text/html; charset=utf-8",
        "content-security-policy: default-src 'none'",
        "x-content-type-options: nosniff",
        "referrer-policy: no-referrer",
        "cache-control: no-store",
        "connection: close",
    ] {
        assert!(lower.contains(header), "missing {header}");
    }
    finish(running).await
}


#[tokio::test]
async fn head_has_the_headers_and_no_body() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(directory.path(), SERVER_BLOCK)?).await?;
    let text = exchange(running.address, b"HEAD / HTTP/1.1\r\nHost: blocked.example.org\r\n\r\n").await?;
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.to_ascii_lowercase().contains("content-security-policy"));
    assert!(text.ends_with("\r\n\r\n") && !text.contains("<html"));
    finish(running).await
}


#[tokio::test]
async fn another_method_gets_a_bodyless_405_with_the_headers() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(directory.path(), SERVER_BLOCK)?).await?;
    let text = exchange(
        running.address,
        b"POST / HTTP/1.1\r\nHost: blocked.example.org\r\nContent-Length: 0\r\n\r\n",
    )
    .await?;
    assert!(text.starts_with("HTTP/1.1 405"));
    assert!(text.to_ascii_lowercase().contains("allow: get, head") && text.to_ascii_lowercase().contains("content-security-policy"));
    assert!(text.ends_with("\r\n\r\n"));
    finish(running).await
}


#[tokio::test]
async fn a_body_is_never_read() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(directory.path(), SERVER_BLOCK)?).await?;
    let announced = format!("GET / HTTP/1.1\r\nHost: blocked.example.org\r\nContent-Length: {HUGE_LENGTH}\r\n\r\n");
    assert!(exchange(running.address, announced.as_bytes())
        .await?
        .contains("<strong>blocked.example.org</strong>"));
    let chunked = "GET / HTTP/1.1\r\nHost: blocked.example.org\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(exchange(running.address, chunked.as_bytes())
        .await?
        .contains("<strong>blocked.example.org</strong>"));
    let expecting = format!("POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: {HUGE_LENGTH}\r\nExpect: 100-continue\r\n\r\n");
    let answer = exchange(running.address, expecting.as_bytes()).await?;
    assert!(answer.starts_with("HTTP/1.1 405") && !answer.contains("100 Continue"));
    finish(running).await
}


#[tokio::test]
async fn a_smuggling_pair_and_an_http2_preface_never_get_the_page_twice() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(directory.path(), SERVER_BLOCK)?).await?;
    let pair = "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: b.example\r\n\r\n";
    let answer = exchange(running.address, pair.as_bytes()).await?;
    assert!(answer.matches("HTTP/1.1 ").count() <= 1 && !answer.contains("b.example"));
    let preface = exchange(running.address, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
    assert!(!preface.contains("<html"));
    finish(running).await
}


#[tokio::test]
async fn an_oversized_head_is_refused_without_the_page() -> TestResult {
    let directory = tempdir()?;
    let running = start(&write_policy(directory.path(), SERVER_BLOCK)?).await?;
    let line = format!("GET / HTTP/1.1\r\nHost: a.example\r\nX-Big: {}\r\n\r\n", "a".repeat(BIG_HEADER_BYTES));
    assert!(!exchange(running.address, line.as_bytes()).await?.contains("<html"));
    let many: String = (0..HEADER_FLOOD).map(|index| format!("X-{index}: 1\r\n")).collect();
    let flood = format!("GET / HTTP/1.1\r\nHost: a.example\r\n{many}\r\n");
    assert!(!exchange(running.address, flood.as_bytes()).await?.contains("<html"));
    finish(running).await
}


#[tokio::test]
async fn a_slow_head_is_closed_and_nothing_is_rendered() -> TestResult {
    let directory = tempdir()?;
    let block =
        format!("sinkhole_server:\n  listen: \"{LISTEN}\"\n  header_read_timeout_ms: {SHORT_TIMEOUT_MS}\n  response_timeout_ms: {BIG_TIMEOUT_MS}\n");
    let running = start(&write_policy(directory.path(), &block)?).await?;
    let mut stream = TcpStream::connect(running.address).await?;
    send(&mut stream, b"GET / HTTP/1.1\r\nHo").await?;
    assert!(!read_all(&mut stream).await?.contains("<html"));
    finish(running).await
}


#[tokio::test]
async fn the_global_cap_closes_the_next_connection_unread() -> TestResult {
    let directory = tempdir()?;
    let block = format!("sinkhole_server:\n  listen: \"{LISTEN}\"\n  max_connections: 1\n  max_connections_per_source: 5\n");
    let running = start(&write_policy(directory.path(), &block)?).await?;
    let held = TcpStream::connect(running.address).await?;
    let mut refused = TcpStream::connect(running.address).await?;
    send(&mut refused, get("a.example").as_bytes()).await?;
    assert_eq!(read_all(&mut refused).await?, "");
    assert!(running.state.refused.load(Ordering::Relaxed) >= 1);
    drop(held);
    finish(running).await
}


#[tokio::test]
async fn the_source_cap_closes_the_next_connection_from_that_source_unread() -> TestResult {
    let directory = tempdir()?;
    let block = format!("sinkhole_server:\n  listen: \"{LISTEN}\"\n  max_connections: 10\n  max_connections_per_source: 1\n");
    let running = start(&write_policy(directory.path(), &block)?).await?;
    let held = TcpStream::connect(running.address).await?;
    let mut refused = TcpStream::connect(running.address).await?;
    send(&mut refused, get("a.example").as_bytes()).await?;
    assert_eq!(read_all(&mut refused).await?, "");
    drop(held);
    finish(running).await
}


#[tokio::test]
async fn a_settings_swap_applies_to_the_next_connection_only() -> TestResult {
    let directory = tempdir()?;
    let path = write_policy(directory.path(), &format!("{SERVER_BLOCK}{}", page_block("first@example.org")))?;
    let running = start(&path).await?;
    let mut early = TcpStream::connect(running.address).await?;
    let probe = exchange(running.address, get("a.example").as_bytes()).await?;
    assert!(probe.contains("first@example.org"));
    replace_file(&path, &policy_text(&format!("{SERVER_BLOCK}{}", page_block("second@example.org"))))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    send(&mut early, get("a.example").as_bytes()).await?;
    assert!(read_all(&mut early).await?.contains("first@example.org"));
    assert!(exchange(running.address, get("a.example").as_bytes())
        .await?
        .contains("second@example.org"));
    finish(running).await
}


#[tokio::test]
async fn a_start_only_listen_change_is_refused_and_the_old_policy_stays() -> TestResult {
    let directory = tempdir()?;
    let path = write_policy(directory.path(), SERVER_BLOCK)?;
    let opened = open_serving_policy(path.clone(), audit(), context())?;
    replace_file(&path, &policy_text(&SERVER_BLOCK.replace("127.0.0.1:9", "127.0.0.1:10")))?;
    assert!(matches!(reload(&opened), ReloadOutcome::Refused { .. }));
    replace_file(&path, &policy_text(""))?;
    assert!(matches!(reload(&opened), ReloadOutcome::Refused { .. }));
    assert!(current_config(&opened).sinkhole_server.is_some());
    replace_file(
        &path,
        &policy_text(&SERVER_BLOCK.replace("max_connections: 100", &format!("max_connections: {CHANGED_CAP}"))),
    )?;
    assert!(matches!(reload(&opened), ReloadOutcome::Applied { .. }));
    assert_eq!(
        current_config(&opened).sinkhole_server.map(|block| block.max_connections),
        Some(CHANGED_CAP)
    );
    Ok(())
}


#[test]
fn the_first_load_must_match_the_baseline_and_be_valid() -> TestResult {
    let directory = tempdir()?;
    let path = write_policy(directory.path(), SERVER_BLOCK)?;
    assert!(load_fixed_listen(&path, Some(SocketAddr::from((Ipv4Addr::LOCALHOST, NOMINAL_PORT)))).is_ok());
    assert!(load_fixed_listen(&path, None).is_err());
    assert!(engine::engine_for(&path).is_ok());
    assert!(open_with_listen(path.clone(), None, audit(), context()).is_err());
    let invalid = write_policy(directory.path(), &SERVER_BLOCK.replace("max_connections: 100", "max_connections: 0"))?;
    assert!(open_serving_policy(invalid, audit(), context()).is_err());
    assert!(open_serving_policy(directory.path().join("missing.yaml"), audit(), context()).is_err());
    Ok(())
}


#[test]
fn every_bound_of_the_block_is_validated() -> TestResult {
    let good = server(1, 1, 1);
    let policy = |block: SinkholeServer| Policy {
        sinkhole_server: Some(block),
        ..sample_policy()
    };
    assert!(validate_policy(&policy(good)).is_ok());
    for bad in [
        SinkholeServer { max_connections: 0, ..good },
        SinkholeServer {
            max_connections: usize::MAX,
            ..good
        },
        SinkholeServer {
            max_connections_per_source: 0,
            ..good
        },
        SinkholeServer {
            max_connections_per_source: usize::MAX,
            ..good
        },
        SinkholeServer {
            header_read_timeout_ms: 0,
            ..good
        },
        SinkholeServer {
            header_read_timeout_ms: u64::MAX,
            ..good
        },
        SinkholeServer {
            header_read_timeout_ms: TWO,
            response_timeout_ms: 1,
            ..good
        },
        SinkholeServer {
            response_timeout_ms: u64::MAX,
            ..good
        },
    ] {
        assert!(validate_policy(&policy(bad)).is_err());
    }
    Ok(())
}


#[test]
fn caps_count_global_and_per_source_and_a_slot_is_released_on_drop() -> TestResult {
    let state = ServeState::default();
    let block = server(THREE, TWO as usize, 1);
    let first: IpAddr = "192.0.2.1".parse()?;
    let second: IpAddr = "192.0.2.2".parse()?;
    let one = admit(&state, first, &block);
    let two = admit(&state, first, &block);
    assert!(one.is_some() && two.is_some());
    assert!(admit(&state, first, &block).is_none());
    let other = admit(&state, second, &block);
    assert!(other.is_some());
    assert!(admit(&state, second, &block).is_none());
    drop(two);
    assert!(admit(&state, first, &block).is_some());
    drop(one);
    drop(other);
    assert!(admit(&state, second, &block).is_some());
    assert_eq!(state.refused.load(Ordering::Relaxed), TWO);
    Ok(())
}


#[test]
fn two_addresses_of_one_slash_64_count_together_and_two_slash_64s_apart() -> TestResult {
    let state = ServeState::default();
    let block = server(BIG_CAP, 1, 1);
    let parse = |text: &str| text.parse::<IpAddr>();
    let held = admit(&state, parse("2001:db8:0:1::1")?, &block);
    assert!(held.is_some());
    assert!(admit(&state, parse("2001:db8:0:1:ffff::2")?, &block).is_none());
    assert!(admit(&state, parse("2001:db8:0:2::1")?, &block).is_some());
    assert_eq!(source_key(parse("::ffff:192.0.2.7")?), parse("192.0.2.7")?);
    assert_eq!(source_key(parse("192.0.2.7")?), parse("192.0.2.7")?);
    Ok(())
}


#[test]
fn the_host_is_used_only_when_exactly_one_header_names_it() -> TestResult {
    let mut headers = HeaderMap::new();
    assert!(host_of(&headers).is_none());
    headers.append(HOST, HeaderValue::from_static("a.example"));
    assert_eq!(host_of(&headers), Some(b"a.example".as_slice()));
    headers.append(HOST, HeaderValue::from_static("b.example"));
    assert!(host_of(&headers).is_none());
    let page = dns_rpz::serve::handle(&sample_policy(), &Method::GET, &headers)?;
    assert_eq!(page.status(), hyper::StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn outcomes_are_classified_and_counted() -> TestResult {
    let state = ServeState::default();
    let elapsed = timeout(Duration::ZERO, pending::<()>()).await.err().ok_or("no timeout")?;
    let (mut client, accepted) = tokio::io::duplex(DUPLEX_BYTES);
    client.write_all(b"not http\r\n\r\n").await?;
    let service = hyper::service::service_fn(|_request: hyper::Request<hyper::body::Incoming>| {
        std::future::ready(dns_rpz::serve::handle(&sample_policy(), &Method::GET, &HeaderMap::new()))
    });
    let failure = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(accepted), service)
        .await
        .err()
        .ok_or("garbage was accepted")?;
    assert_eq!(connection_class(Ok(Ok(()))), ConnectionClass::Closed);
    assert_eq!(connection_class(Ok(Err(failure))), ConnectionClass::Failed);
    assert_eq!(connection_class(Err(elapsed)), ConnectionClass::Deadline);
    assert_eq!(count_class(&state, ConnectionClass::Closed), ConnectionClass::Closed);
    assert_eq!(state.cut.load(Ordering::Relaxed), 0);
    assert_eq!(count_class(&state, ConnectionClass::Deadline), ConnectionClass::Deadline);
    assert_eq!(state.cut.load(Ordering::Relaxed), 1);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn counters_are_reported_once_per_interval() -> TestResult {
    init_logging();
    let state = ServeState::default();
    assert!(report_due(&state));
    [&state.refused, &state.cut, &state.failed]
        .into_iter()
        .for_each(|counter| counter.store(THREE as u64, Ordering::Relaxed));
    assert!(!report_due(&state));
    assert_eq!(state.cut.load(Ordering::Relaxed), THREE as u64);
    advance(Duration::from_secs(REPORT_INTERVAL_SECONDS)).await;
    assert!(report_due(&state));
    assert_eq!(
        state.refused.load(Ordering::Relaxed) + state.cut.load(Ordering::Relaxed) + state.failed.load(Ordering::Relaxed),
        0
    );
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failed_accept_is_counted_and_a_policy_without_the_block_refuses() -> TestResult {
    init_logging();
    let directory = tempdir()?;
    let path = write_policy(directory.path(), "")?;
    let opened = open_serving_policy(path, audit(), context())?;
    let state = Arc::new(ServeState::default());
    accept_one(Err(io::Error::other("accept failed")), &opened, &state).await;
    assert_eq!(state.failed.load(Ordering::Relaxed), 1);
    let (client, accepted) = loopback_pair().await?;
    accept_one(Ok(accepted), &opened, &state).await;
    assert_eq!(state.refused.load(Ordering::Relaxed), 1);
    drop(client);
    let (other, accepted_other) = loopback_pair().await?;
    accept_connection(
        accepted_other,
        Err(io::Error::other("no peer")),
        Arc::new(Policy {
            sinkhole_server: Some(server(1, 1, 1)),
            ..sample_policy()
        }),
        &state,
    );
    assert_eq!(state.failed.load(Ordering::Relaxed), THREE as u64 - 1);
    drop(other);
    Ok(())
}


#[test]
fn the_unknown_domain_text_is_what_the_page_shows_without_a_host() -> TestResult {
    let page = dns_rpz::sinkhole::render_page(None, None);
    assert!(page.html.contains(UNKNOWN_DOMAIN_EN));
    Ok(())
}

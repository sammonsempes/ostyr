#[path = "san/mod.rs"]
mod san;
#[path = "common/types.rs"]
mod types;


use hardware_health::error::{transport_kind, GetError, TransportKind};
use hardware_health::model::{FetchSession, RedfishDevice};
use hardware_health::redfish_fetch::{basic_header, build_agent, get_body};
use san::{chain, held_server, hostile_server, is_clean, plain_server, MARKER, PLAIN_MARKER};
use std::error::Error;
use std::io::ErrorKind;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use types::TestResult;


const LEFT_SECONDS: u64 = 20;


const SHORT_MILLIS: u64 = 300;


const MAX_BYTES: u64 = 1024;


const TIMEOUT_MS: u64 = 5000;


fn failure_for(port: u16, ca_pem: &str, left: Duration) -> Result<GetError, Box<dyn Error>> {
    Ok(failure_and_raw(port, ca_pem, left)?.0)
}


fn failure_and_raw(port: u16, ca_pem: &str, left: Duration) -> Result<(GetError, String), Box<dyn Error>> {
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca_pem)?;
    let device = RedfishDevice {
        name: "bmc1".to_owned(),
        base_url: format!("https://127.0.0.1:{port}"),
        ca_file: Some(ca_path.display().to_string()),
        insecure_skip_verify: false,
        username: "monitor".to_owned(),
        password_file: dir.path().join("password").display().to_string(),
        timeout_ms: TIMEOUT_MS,
    };
    let session = FetchSession {
        agent: build_agent(&device)?,
        auth: basic_header("monitor", b"pw"),
        base: device.base_url.clone(),
        deadline: Instant::now() + left,
        max_bytes: MAX_BYTES,
    };
    let url = format!("{}/x", session.base);
    let raw = session
        .agent
        .get(&url)
        .config()
        .timeout_global(Some(left))
        .build()
        .call()
        .err()
        .ok_or("connected")?;
    Ok((get_body(&session, &url, left).err().ok_or("connected")?, chain(&raw)))
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_error() -> TestResult {
    let server = hostile_server()?;
    let (error, raw) = failure_and_raw(server.port, &server.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
    assert!(raw.contains(MARKER), "the control: ureq itself carries the peer text");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(matches!(error, GetError::Transport(TransportKind::Tls)));
    assert!(std::error::Error::source(&error).is_none());
    Ok(())
}


#[test]
fn an_unknown_issuer_is_a_fixed_tls_failure() -> TestResult {
    let server = hostile_server()?;
    let other = hostile_server()?;
    let error = failure_for(server.port, &other.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
    assert!(matches!(error, GetError::Transport(TransportKind::Tls)));
    assert!(is_clean(&chain(&error)));
    Ok(())
}


#[test]
fn a_silent_server_is_a_fixed_timeout() -> TestResult {
    let held = held_server()?;
    let other = hostile_server()?;
    let error = failure_for(held.port, &other.ca_pem, Duration::from_millis(SHORT_MILLIS))?;
    held.release.send(())?;
    assert!(matches!(error, GetError::Transport(TransportKind::Timeout)), "{error:?}");
    Ok(())
}


#[test]
fn a_close_or_plain_http_on_the_tls_port_has_fixed_text() -> TestResult {
    let other = hostile_server()?;
    let closing = plain_server(b"")?;
    let plain = plain_server(format!("HTTP/1.1 200 OK\r\nX: {PLAIN_MARKER}\r\n\r\n").leak().as_bytes())?;
    [closing, plain].iter().try_for_each(|port| -> TestResult {
        let error = failure_for(*port, &other.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
        assert!(matches!(error, GetError::Transport(_)));
        assert!(is_clean(&chain(&error)), "{}", chain(&error));
        Ok(())
    })
}


#[test]
fn every_ureq_error_maps_to_a_fixed_kind() -> TestResult {
    let io = |kind: ErrorKind| ureq::Error::Io(std::io::Error::new(kind, "peer text"));
    assert_eq!(transport_kind(&ureq::Error::Timeout(ureq::Timeout::Global)), TransportKind::Timeout);
    assert_eq!(transport_kind(&ureq::Error::Tls("peer text")), TransportKind::Tls);
    assert_eq!(transport_kind(&io(ErrorKind::InvalidData)), TransportKind::Tls);
    assert_eq!(
        transport_kind(&io(ErrorKind::BrokenPipe)),
        TransportKind::Io { kind: ErrorKind::BrokenPipe }
    );
    assert_eq!(transport_kind(&ureq::Error::HostNotFound), TransportKind::Connect);
    assert_eq!(transport_kind(&ureq::Error::ConnectionFailed), TransportKind::Connect);
    assert_eq!(transport_kind(&ureq::Error::BadUri("peer text".to_owned())), TransportKind::Protocol);
    assert!(!TransportKind::Io { kind: ErrorKind::BrokenPipe }.to_string().contains("peer text"));
    Ok(())
}

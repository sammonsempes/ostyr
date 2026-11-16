#[path = "san/mod.rs"]
mod san;
#[path = "common/types.rs"]
mod types;


use k8s_inventory::error::{transport_kind, FetchError, TransportKind};
use k8s_inventory::fetch::{bearer_of, get_reply, new_agent, post_reply, Session};
use san::{chain, held_server, hostile_server, is_clean, plain_server, MARKER, PLAIN_MARKER};
use std::error::Error;
use std::io::ErrorKind;
use std::time::{Duration, Instant};
use types::TestResult;


const LEFT_SECONDS: u64 = 20;


const SHORT_MILLIS: u64 = 300;


const CAP: u64 = 1024;


fn session_for(port: u16, ca_pem: &str, left: Duration) -> Result<Session, Box<dyn Error>> {
    Ok(Session {
        agent: new_agent(ca_pem.as_bytes())?,
        api_url: format!("https://127.0.0.1:{port}"),
        bearer: bearer_of(b"tok")?,
        started: Instant::now(),
        timeout: left,
        bytes_left: CAP,
    })
}


fn failure_and_raw(port: u16, ca_pem: &str, left: Duration) -> Result<(FetchError, String), Box<dyn Error>> {
    let probe = session_for(port, ca_pem, left)?;
    let url = format!("{}/x", probe.api_url);
    let raw = probe
        .agent
        .get(&url)
        .config()
        .timeout_global(Some(left))
        .build()
        .call()
        .err()
        .ok_or("connected")?;
    let mut session = session_for(port, ca_pem, left)?;
    Ok((get_reply(&mut session, "/x", &[], CAP).err().ok_or("connected")?, chain(&raw)))
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_error() -> TestResult {
    let server = hostile_server()?;
    let (error, raw) = failure_and_raw(server.port, &server.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
    assert!(raw.contains(MARKER), "the control: ureq itself carries the peer text");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(matches!(error, FetchError::Transport(TransportKind::Tls)));
    assert!(error.source().is_none());
    let mut session = session_for(server.port, &server.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
    let posted = post_reply(&mut session, "/x", "{}", CAP).err().ok_or("connected")?;
    assert!(is_clean(&chain(&posted)), "{}", chain(&posted));
    Ok(())
}


#[test]
fn an_unknown_issuer_is_a_fixed_tls_failure() -> TestResult {
    let server = hostile_server()?;
    let other = hostile_server()?;
    let (error, _) = failure_and_raw(server.port, &other.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
    assert!(matches!(error, FetchError::Transport(TransportKind::Tls)));
    assert!(is_clean(&chain(&error)));
    Ok(())
}


#[test]
fn a_silent_server_is_a_fixed_timeout() -> TestResult {
    let held = held_server()?;
    let other = hostile_server()?;
    let (error, _) = failure_and_raw(held.port, &other.ca_pem, Duration::from_millis(SHORT_MILLIS))?;
    held.release.send(())?;
    assert!(matches!(error, FetchError::Transport(TransportKind::Timeout)), "{error:?}");
    Ok(())
}


#[test]
fn a_close_or_plain_http_on_the_tls_port_has_fixed_text() -> TestResult {
    let other = hostile_server()?;
    let closing = plain_server(b"")?;
    let plain = plain_server(format!("HTTP/1.1 200 OK\r\nX: {PLAIN_MARKER}\r\n\r\n").leak().as_bytes())?;
    [closing, plain].iter().try_for_each(|port| -> TestResult {
        let (error, _) = failure_and_raw(*port, &other.ca_pem, Duration::from_secs(LEFT_SECONDS))?;
        assert!(matches!(error, FetchError::Transport(_)));
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

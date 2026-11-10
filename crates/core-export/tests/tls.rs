#[path = "common/pki.rs"]
mod pki;
#[path = "common/slow_tls_sink.rs"]
mod slow_tls_sink;
#[path = "common/tls_sink.rs"]
mod tls_sink;
#[path = "common/types.rs"]
mod types;


use core_export::error::ExportError;
use core_export::syslog::write_frames;
use core_export::tls::{client_config, close, close_within, open_stream, root_store};
use std::time::Duration;
use types::TestResult;


const EVENT_COUNT: u32 = 10000;


const CLOSE_TEST_TIMEOUT_MS: u64 = 50;


const BAD_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";


#[test]
fn without_a_ca_bundle_the_public_roots_are_trusted() -> TestResult {
    assert!(!root_store(None)?.is_empty());
    Ok(())
}


#[test]
fn a_ca_bundle_replaces_the_public_roots() -> TestResult {
    let authority = pki::test_pki()?;
    assert_eq!(root_store(Some(authority.ca_pem.as_bytes()))?.len(), 1);
    Ok(())
}


#[test]
fn a_bad_ca_bundle_is_rejected() -> TestResult {
    assert!(matches!(root_store(Some(b"not a pem")), Err(ExportError::Certificate(_))));
    assert!(matches!(root_store(Some(BAD_CERTIFICATE.as_bytes())), Err(ExportError::Tls(_))));
    assert!(client_config(Some(b"not a pem")).is_err());
    Ok(())
}


#[test]
fn an_invalid_server_name_is_rejected_before_connecting() -> TestResult {
    let config = client_config(None)?;
    assert!(matches!(open_stream("bad host:1", config), Err(ExportError::ServerName { .. })));
    Ok(())
}


#[test]
fn a_closed_port_is_an_io_error() -> TestResult {
    let config = client_config(None)?;
    assert!(matches!(open_stream("127.0.0.1:1", config), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn frames_reach_a_tls_receiver_that_trusts_the_ca() -> TestResult {
    let authority = pki::test_pki()?;
    let tls_sink::TlsSink { address, received } = tls_sink::spawn_tls_sink(authority.server_config.clone())?;
    let mut stream = open_stream(&address, client_config(Some(authority.ca_pem.as_bytes()))?)?;
    write_frames(&mut stream, &["ab".to_string(), "c".to_string()])?;
    close(&mut stream)?;
    let bytes = received.join().map_err(|_panic| "sink thread panicked")??;
    assert_eq!(String::from_utf8(bytes)?, "2 ab1 c");
    Ok(())
}


#[test]
fn a_receiver_with_an_unknown_certificate_is_refused() -> TestResult {
    let authority = pki::test_pki()?;
    let tls_sink::TlsSink { address, received } = tls_sink::spawn_tls_sink(authority.server_config.clone())?;
    let mut stream = open_stream(&address, client_config(None)?)?;
    assert!(matches!(write_frames(&mut stream, &["x".to_string()]), Err(ExportError::Io { .. })));
    assert!(received.join().map_err(|_panic| "sink thread panicked")?.is_err());
    Ok(())
}


#[test]
fn closing_a_silent_peer_gives_up_after_the_timeout() -> TestResult {
    let authority = pki::test_pki()?;
    let tls_sink::TlsSink { address, received } = tls_sink::spawn_tls_sink(authority.server_config.clone())?;
    let mut stream = open_stream(&address, client_config(Some(authority.ca_pem.as_bytes()))?)?;
    write_frames(&mut stream, &["a".to_string()])?;
    close_within(&mut stream, Duration::from_millis(CLOSE_TEST_TIMEOUT_MS))?;
    assert_eq!(String::from_utf8(received.join().map_err(|_panic| "sink thread panicked")??)?, "1 a");
    Ok(())
}


#[test]
fn an_invalid_timeout_is_logged_not_returned() -> TestResult {
    let authority = pki::test_pki()?;
    let tls_sink::TlsSink { address, received } = tls_sink::spawn_tls_sink(authority.server_config.clone())?;
    let mut stream = open_stream(&address, client_config(Some(authority.ca_pem.as_bytes()))?)?;
    write_frames(&mut stream, &["a".to_string()])?;
    close_within(&mut stream, Duration::ZERO)?;
    assert!(received.join().map_err(|_panic| "sink thread panicked")?.is_ok());
    Ok(())
}


#[test]
fn ten_thousand_frames_survive_a_slow_tls_13_receiver_with_tickets() -> TestResult {
    let authority = pki::test_pki()?;
    let tls_sink::TlsSink { address, received } = slow_tls_sink::spawn_slow_tls_sink(authority.server_config.clone())?;
    let messages = (0..EVENT_COUNT).map(|sequence| format!("seq={sequence}")).collect::<Vec<_>>();
    let mut stream = open_stream(&address, client_config(Some(authority.ca_pem.as_bytes()))?)?;
    write_frames(&mut stream, &messages)?;
    close(&mut stream)?;
    let bytes = received.join().map_err(|_panic| "sink thread panicked")??;
    let expected = messages.iter().map(|message| format!("{} {message}", message.len())).collect::<String>();
    assert_eq!(String::from_utf8(bytes)?, expected);
    Ok(())
}

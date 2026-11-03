#[path = "common/pki.rs"]
mod pki;
#[path = "common/tls_sink.rs"]
mod tls_sink;
#[path = "common/types.rs"]
mod types;


use core_export::error::ExportError;
use core_export::syslog::write_frames;
use core_export::tls::{client_config, close, open_stream, root_store};
use std::net::TcpListener;
use types::TestResult;


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
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let config = client_config(None)?;
    assert!(matches!(open_stream(&format!("localhost:{port}"), config), Err(ExportError::Io { .. })));
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

#[path = "san/mod.rs"]
mod san;
#[path = "common/types.rs"]
mod types;


use oncall::error::{transport_kind, TransportError, TransportKind};
use oncall::model::{Channel, ChannelKind, Message};
use oncall::settings::{SmtpSettings, SmtpTls, TransportSettings};
use oncall::smtp::send_mail;
use oncall::transport::{build_agent, send_one};
use san::{chain, held_server, hostile_server, is_clean, plain_server, starttls_server, MARKER, PLAIN_MARKER};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::ErrorKind;
use tempfile::tempdir;
use types::TestResult;


const LONG_MILLIS: u64 = 20_000;


const SHORT_MILLIS: u64 = 300;


fn failure_and_raw(port: u16, ca_pem: &str, timeout_millis: u64) -> Result<(TransportError, String), Box<dyn Error>> {
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca_pem)?;
    let settings = TransportSettings {
        timeout_millis,
        ca_file: Some(ca_path.display().to_string()),
        secret_dirs: BTreeMap::new(),
        smtp: None,
    };
    let target = format!("https://127.0.0.1:{port}/hook");
    let raw = build_agent(&settings)?.post(&target).send("x").err().ok_or("connected")?;
    let channel = Channel {
        name: "pager".to_owned(),
        tenant: "acme".to_owned(),
        kind: ChannelKind::Webhook,
        target,
        secret_file: None,
    };
    let message = Message {
        subject: "s".to_owned(),
        body: "b".to_owned(),
    };
    Ok((send_one(&settings, &channel, &message).err().ok_or("sent")?, chain(&raw)))
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_error() -> TestResult {
    let server = hostile_server()?;
    let (error, raw) = failure_and_raw(server.port, &server.ca_pem, LONG_MILLIS)?;
    assert!(raw.contains(MARKER), "the control: ureq itself carries the peer text");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(matches!(error, TransportError::Request(TransportKind::Tls)));
    assert!(error.source().is_none());
    Ok(())
}


#[test]
fn an_unknown_issuer_is_a_fixed_tls_failure() -> TestResult {
    let server = hostile_server()?;
    let other = hostile_server()?;
    let (error, _) = failure_and_raw(server.port, &other.ca_pem, LONG_MILLIS)?;
    assert!(matches!(error, TransportError::Request(TransportKind::Tls)));
    assert!(is_clean(&chain(&error)));
    Ok(())
}


#[test]
fn a_silent_server_is_a_fixed_timeout() -> TestResult {
    let held = held_server()?;
    let other = hostile_server()?;
    let (error, _) = failure_and_raw(held.port, &other.ca_pem, SHORT_MILLIS)?;
    held.release.send(())?;
    assert!(matches!(error, TransportError::Request(TransportKind::Timeout)), "{error:?}");
    Ok(())
}


#[test]
fn a_close_or_plain_http_on_the_tls_port_has_fixed_text() -> TestResult {
    let other = hostile_server()?;
    let closing = plain_server(b"")?;
    let plain = plain_server(format!("HTTP/1.1 200 OK\r\nX: {PLAIN_MARKER}\r\n\r\n").leak().as_bytes())?;
    [closing, plain].iter().try_for_each(|port| -> TestResult {
        let (error, _) = failure_and_raw(*port, &other.ca_pem, LONG_MILLIS)?;
        assert!(matches!(error, TransportError::Request(_)));
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


fn mail_failure(port: u16, ca_pem: &str, tls: SmtpTls) -> Result<TransportError, Box<dyn Error>> {
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca_pem)?;
    let settings = TransportSettings {
        timeout_millis: LONG_MILLIS,
        ca_file: Some(ca_path.display().to_string()),
        secret_dirs: BTreeMap::new(),
        smtp: Some(SmtpSettings {
            host: "localhost".to_owned(),
            port,
            tls,
            from: "ostyr@example.org".to_owned(),
            username: None,
        }),
    };
    let channel = Channel {
        name: "mail".to_owned(),
        tenant: "acme".to_owned(),
        kind: ChannelKind::Smtp,
        target: "oncall@example.org".to_owned(),
        secret_file: None,
    };
    let message = Message {
        subject: "s".to_owned(),
        body: "b".to_owned(),
    };
    Ok(send_mail(&settings, &channel, &message).err().ok_or("sent")?)
}


#[test]
fn a_hostile_certificate_name_never_reaches_an_implicit_smtp_error() -> TestResult {
    let server = hostile_server()?;
    let error = mail_failure(server.port, &server.ca_pem, SmtpTls::Implicit)?;
    assert!(matches!(error, TransportError::Handshake), "{error:?}");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(error.source().is_none());
    Ok(())
}


#[test]
fn a_hostile_certificate_name_never_reaches_a_starttls_smtp_error() -> TestResult {
    let server = starttls_server()?;
    let error = mail_failure(server.port, &server.ca_pem, SmtpTls::Starttls)?;
    assert!(matches!(error, TransportError::Handshake), "{error:?}");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(error.source().is_none());
    Ok(())
}

use crate::support::{start_live_named, TestResult};
use rcgen::string::Ia5String;
use rcgen::SanType;
use std::error::Error;
use std::io::{ErrorKind, Write};
use std::net::TcpListener;
use std::thread::spawn;
use xdrctl::error::{transport_kind, ClientError, TransportKind};
use xdrctl::http::send_request;
use xdrctl::model::{HttpMethod, HttpRequest};


const MARKER: &str = "peer-san-marker";


const PLAIN_MARKER: &str = "plain-http-marker";


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 60_000;


const CONNECTIONS: usize = 4;


const MAX_SHOWN_BYTES: usize = 1024;


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn is_clean(shown: &str) -> bool {
    !shown.contains(MARKER) && !shown.contains(PLAIN_MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}") && shown.len() < MAX_SHOWN_BYTES
}


fn plain_server(reply: &'static [u8]) -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    spawn(move || {
        listener
            .incoming()
            .take(CONNECTIONS)
            .try_for_each(|incoming| incoming.and_then(|mut stream| stream.write_all(reply)))
    });
    Ok(port)
}


fn request_to(port: u16) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: format!("https://127.0.0.1:{port}/auth/me"),
        token: None,
        body: String::new(),
    }
}


fn port_of(url: &str) -> Result<u16, Box<dyn Error>> {
    Ok(url.rsplit(':').next().ok_or("no port")?.parse()?)
}


fn hostile_names() -> Result<Vec<SanType>, Box<dyn Error>> {
    let long = "a".repeat(LONG_NAME_BYTES);
    Ok(vec![
        SanType::DnsName(Ia5String::try_from(format!("{MARKER}.example"))?),
        SanType::URI(Ia5String::try_from(format!("urn:{MARKER}{ESCAPE}[31m{long}"))?),
    ])
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_error() -> TestResult {
    let live = start_live_named(hostile_names()?)?;
    let port = port_of(&live.url)?;
    let error = send_request(Some(&live.ca_file), &request_to(port)).err().ok_or("connected")?;
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    assert!(matches!(error, ClientError::Transport(TransportKind::Tls)), "{error:?}");
    assert!(error.source().is_none());
    Ok(())
}


#[test]
fn an_unknown_issuer_is_a_fixed_tls_failure() -> TestResult {
    let live = start_live_named(hostile_names()?)?;
    let other = start_live_named(hostile_names()?)?;
    let error = send_request(Some(&other.ca_file), &request_to(port_of(&live.url)?))
        .err()
        .ok_or("connected")?;
    assert!(matches!(error, ClientError::Transport(TransportKind::Tls)), "{error:?}");
    assert!(is_clean(&chain(&error)));
    Ok(())
}


#[test]
fn a_close_or_plain_http_on_the_tls_port_has_fixed_text() -> TestResult {
    let other = start_live_named(hostile_names()?)?;
    let closing = plain_server(b"")?;
    let plain = plain_server(format!("HTTP/1.1 200 OK\r\nX: {PLAIN_MARKER}\r\n\r\n").leak().as_bytes())?;
    [closing, plain].iter().try_for_each(|port| -> TestResult {
        let error = send_request(Some(&other.ca_file), &request_to(*port)).err().ok_or("connected")?;
        assert!(matches!(error, ClientError::Transport(_)), "{error:?}");
        assert!(is_clean(&chain(&error)), "{}", chain(&error));
        Ok(())
    })
}


#[test]
fn a_refused_ca_certificate_keeps_its_local_cause() -> TestResult {
    let live = start_live_named(hostile_names()?)?;
    let broken = live.dir.path().join("broken.pem");
    std::fs::write(&broken, "not a certificate")?;
    let error = send_request(Some(&broken), &request_to(1)).err().ok_or("accepted")?;
    assert!(matches!(error, ClientError::CaInvalid(_)));
    assert_eq!(error.to_string(), "the CA certificate is refused");
    assert!(error.source().is_some());
    Ok(())
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

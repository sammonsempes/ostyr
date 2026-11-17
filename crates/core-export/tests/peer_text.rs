#[path = "common/types.rs"]
mod types;


use core_export::error::{peer_failure, transport_kind, without_peer_text, ExportError, TransportKind};
use core_export::http::{build_agent, post_json};
use core_export::syslog::write_frames;
use core_export::tls::{client_config, open_stream};
use core_export::types::BoxError;
use core_export::webhook::{deliver, RetryPolicy};
use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::error::Error;
use std::io::{ErrorKind, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::spawn;
use types::TestResult;


const MARKER: &str = "peer-san-marker";


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 20_000;


const CONNECTIONS: usize = 4;


const MAX_SHOWN_BYTES: usize = 1024;


const STATUS_UNAVAILABLE: u16 = 503;


struct Hostile {
    port: u16,
    ca_pem: String,
}


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn is_clean(shown: &str) -> bool {
    !shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}") && shown.len() < MAX_SHOWN_BYTES
}


fn hostile_server() -> Result<Hostile, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from(format!("{MARKER}.example"))?),
        SanType::URI(Ia5String::try_from(format!("urn:{MARKER}{ESCAPE}[31m{}", "a".repeat(LONG_NAME_BYTES)))?),
    ];
    let certificate = params.signed_by(&key, &Issuer::new(ca_params, ca_key))?;
    let private = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)?,
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    spawn(move || {
        listener.incoming().take(CONNECTIONS).for_each(|incoming| {
            let outcome = incoming.and_then(|mut stream| {
                let mut connection = ServerConnection::new(Arc::clone(&config)).map_err(std::io::Error::other)?;
                connection.complete_io(&mut stream).map(|_| ())
            });
            if let Err(error) = outcome {
                tracing::debug!("hostile server ended: {error}");
            }
        });
    });
    Ok(Hostile { port, ca_pem: ca.pem() })
}


#[test]
fn a_hostile_certificate_name_never_reaches_a_webhook_error() -> TestResult {
    let server = hostile_server()?;
    let agent = build_agent(Some(server.ca_pem.as_bytes()))?;
    let url = format!("https://127.0.0.1:{}/hook", server.port);
    let raw = agent.post(&url).send("x").err().ok_or("connected")?;
    assert!(
        format!("{raw} {raw:?}").contains(MARKER),
        "the control: ureq itself carries the peer text"
    );
    let error = post_json(&agent, &url, None, "x").err().ok_or("posted")?;
    assert!(is_clean(&chain(error.as_ref())), "{}", chain(error.as_ref()));
    assert_eq!(error.downcast_ref::<TransportKind>(), Some(&TransportKind::Tls));
    Ok(())
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_exhausted_error() -> TestResult {
    let server = hostile_server()?;
    let agent = build_agent(Some(server.ca_pem.as_bytes()))?;
    let url = format!("https://127.0.0.1:{}/hook", server.port);
    let policy = RetryPolicy {
        max_attempts: 1,
        ..RetryPolicy::default()
    };
    let exhausted = deliver(&policy, &mut |body| post_json(&agent, &url, None, body), &mut |_pause| {}, "x")
        .err()
        .ok_or("delivered")?;
    assert!(matches!(exhausted, ExportError::Exhausted { .. }));
    assert!(is_clean(&chain(&exhausted)), "{}", chain(&exhausted));
    Ok(())
}


#[test]
fn a_hostile_certificate_name_never_reaches_a_syslog_error() -> TestResult {
    let server = hostile_server()?;
    let config = client_config(Some(server.ca_pem.as_bytes()))?;
    let address = format!("localhost:{}", server.port);
    let mut raw_stream = open_stream(&address, Arc::clone(&config))?;
    let raw = raw_stream.write_all(b"x").err().ok_or("written")?;
    assert!(chain(&raw).contains(MARKER), "the control: rustls itself carries the peer text");
    let mut stream = open_stream(&address, config)?;
    let error = write_frames(&mut stream, &["x".to_string()]).err().ok_or("written")?;
    assert!(matches!(error, ExportError::Io { .. }));
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    Ok(())
}


#[test]
fn every_ureq_error_maps_to_a_fixed_kind() -> TestResult {
    let io = |kind: ErrorKind| ureq::Error::Io(std::io::Error::new(kind, "peer text"));
    assert_eq!(transport_kind(&ureq::Error::Timeout(ureq::Timeout::Global)), TransportKind::Timeout);
    assert_eq!(transport_kind(&ureq::Error::Tls("peer text")), TransportKind::Tls);
    assert_eq!(
        transport_kind(&ureq::Error::Rustls(rustls::Error::HandshakeNotComplete)),
        TransportKind::Tls
    );
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


#[test]
fn a_status_answer_keeps_its_number_and_other_text_is_dropped() -> TestResult {
    let status: BoxError = peer_failure(ureq::Error::StatusCode(STATUS_UNAVAILABLE));
    assert!(matches!(
        status.downcast_ref::<ureq::Error>(),
        Some(ureq::Error::StatusCode(STATUS_UNAVAILABLE))
    ));
    let other = peer_failure(ureq::Error::BadUri("peer text".to_owned()));
    assert!(!other.to_string().contains("peer text"));
    Ok(())
}


#[test]
fn an_io_error_with_rustls_inside_loses_its_text_and_any_other_is_kept() -> TestResult {
    let wrapped = std::io::Error::new(ErrorKind::InvalidData, rustls::Error::General(MARKER.to_string()));
    let fixed = without_peer_text(wrapped);
    assert_eq!(fixed.kind(), ErrorKind::InvalidData);
    assert!(is_clean(&chain(&fixed)));
    let nested = std::io::Error::other(std::io::Error::new(ErrorKind::InvalidData, rustls::Error::General(MARKER.to_string())));
    let nested_fixed = without_peer_text(nested);
    assert_eq!(nested_fixed.kind(), ErrorKind::Other);
    assert!(is_clean(&chain(&nested_fixed)));
    let plain = std::io::Error::new(ErrorKind::BrokenPipe, "kept text");
    assert!(without_peer_text(plain).to_string().contains("kept text"));
    let bare = std::io::Error::from(ErrorKind::BrokenPipe);
    assert_eq!(without_peer_text(bare).kind(), ErrorKind::BrokenPipe);
    Ok(())
}

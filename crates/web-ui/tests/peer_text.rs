#[path = "support/types.rs"]
mod types;


use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::error::Error;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::spawn;
use tempfile::tempdir;
use types::TestResult;
use web_ui::api::get_case;
use web_ui::client::build_client;
use web_ui::error::{class_of, handshake_class, rustls_in, unavailable, ApiFailure, TlsClass};
use web_ui::model::ApiSection;
use web_ui::model::Language;
use web_ui::routes::{api_refusal, failure_class};


const MARKER: &str = "peer-san-marker";


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 20_000;


const CONNECTIONS: usize = 4;


const MAX_SHOWN_BYTES: usize = 1024;


const CONNECTION_LIMIT: usize = 4;


const TIMEOUT_SECONDS: u64 = 30;


const SOURCE: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn is_clean(shown: &str) -> bool {
    !shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}") && shown.len() < MAX_SHOWN_BYTES
}


fn hostile_server() -> Result<(u16, String), Box<dyn Error>> {
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
                let mut connection = ServerConnection::new(Arc::clone(&config)).map_err(io::Error::other)?;
                connection.complete_io(&mut stream).map(|_| ())
            });
            if let Err(error) = outcome {
                tracing::debug!("hostile server ended: {error}");
            }
        });
    });
    Ok((port, ca.pem()))
}


#[tokio::test]
async fn a_hostile_certificate_name_never_reaches_the_api_failure() -> TestResult {
    let (port, ca_pem) = hostile_server()?;
    let dir = tempdir()?;
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ca_pem)?;
    let client = build_client(&ApiSection {
        base_url: format!("https://localhost:{port}/"),
        ca: Some(ca),
        timeout_seconds: TIMEOUT_SECONDS,
        max_connections: CONNECTION_LIMIT,
    })?;
    let raw = client
        .http
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .err()
        .ok_or("connected")?;
    assert!(chain(&raw).contains(MARKER), "the control: reqwest itself carries the peer text");
    let token = secrecy::SecretString::from("t".to_owned());
    let failure = get_case(&client, SOURCE, &token, "ok-1").await.err().ok_or("answered")?;
    assert!(matches!(failure, ApiFailure::Handshake(TlsClass::Certificate)), "{failure:?}");
    assert!(is_clean(&chain(&failure)), "{}", chain(&failure));
    assert_eq!(failure_class(&failure), "handshake");
    assert!(api_refusal(Language::English, None, &failure).status().is_server_error());
    Ok(())
}


#[tokio::test]
async fn a_failure_without_tls_stays_unavailable() -> TestResult {
    let client = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: CONNECTION_LIMIT,
    })?;
    let raw = client.http.get("http://127.0.0.1:1/").send().await.err().ok_or("connected")?;
    assert!(handshake_class(&raw).is_none());
    assert!(matches!(unavailable(raw), ApiFailure::Unavailable(_)));
    Ok(())
}


#[test]
fn rustls_errors_are_classed_without_their_text() -> TestResult {
    assert_eq!(
        class_of(&rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        TlsClass::Certificate
    );
    assert_eq!(class_of(&rustls::Error::NoCertificatesPresented), TlsClass::Certificate);
    assert_eq!(
        class_of(&rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)),
        TlsClass::Alert
    );
    assert_eq!(class_of(&rustls::Error::HandshakeNotComplete), TlsClass::Protocol);
    assert!(rustls_in(&rustls::Error::HandshakeNotComplete).is_some());
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::NoCertificatesPresented);
    assert_eq!(handshake_class(&wrapped), Some(TlsClass::Certificate));
    assert_eq!(handshake_class(&io::Error::from(io::ErrorKind::BrokenPipe)), None);
    assert_eq!(handshake_class(&io::Error::new(io::ErrorKind::BrokenPipe, "text")), None);
    assert!(!TlsClass::Alert.to_string().is_empty() && !TlsClass::Protocol.to_string().is_empty());
    Ok(())
}

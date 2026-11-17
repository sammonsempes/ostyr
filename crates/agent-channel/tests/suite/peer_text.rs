use crate::harness::{attempt_with, bounded, client_paths, custom_client, finish, init_logging, make_platform, server_paths, start_single, Platform};
use crate::pki::{agent_spec, issue, make_authority, write_leaf, LeafSpec, AGENT_URI, SERVER_NAME};
use crate::types::TestResult;
use agent_channel::client::connect_channel;
use agent_channel::error::{class_of, error_class, rustls_in, without_peer_text, ChannelError, TlsClass};
use agent_channel::tls::{parse_private_key, provider, read_certificates, read_private_key, root_store};
use agent_channel::types::SharedClientConfig;
use rustls::version::TLS13;
use rustls::{AlertDescription, CertificateError, ClientConfig, ServerConfig};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};


const MARKER: &str = "peer-san-marker";


const ESCAPE: char = '\u{1b}';


const LONG_NAME_BYTES: usize = 20_000;


const MAX_SHOWN_BYTES: usize = 1024;


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn is_clean(shown: &str) -> bool {
    !shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}") && shown.len() < MAX_SHOWN_BYTES
}


fn hostile_spec() -> LeafSpec {
    LeafSpec {
        uris: vec![format!("urn:{MARKER}{ESCAPE}[31m{}", "a".repeat(LONG_NAME_BYTES))],
        dns: vec![format!("{MARKER}.example")],
        expired: false,
    }
}


#[test]
fn the_class_of_a_rustls_error_is_fixed() -> TestResult {
    assert_eq!(
        class_of(&rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
        TlsClass::Certificate
    );
    assert_eq!(class_of(&rustls::Error::NoCertificatesPresented), TlsClass::Certificate);
    assert_eq!(
        class_of(&rustls::Error::AlertReceived(AlertDescription::HandshakeFailure)),
        TlsClass::Alert
    );
    assert_eq!(class_of(&rustls::Error::HandshakeNotComplete), TlsClass::Protocol);
    Ok(())
}


#[test]
fn a_rustls_error_is_found_directly_inside_an_io_error_or_not_at_all() -> TestResult {
    let bare = rustls::Error::HandshakeNotComplete;
    assert!(rustls_in(&bare).is_some());
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::NoCertificatesPresented);
    assert!(rustls_in(&wrapped).is_some());
    assert_eq!(error_class(&wrapped), TlsClass::Certificate);
    let plain = io::Error::new(io::ErrorKind::BrokenPipe, "peer text");
    assert!(rustls_in(&plain).is_none());
    assert_eq!(error_class(&plain), TlsClass::Other);
    let bare_io = io::Error::from(io::ErrorKind::BrokenPipe);
    assert!(rustls_in(&bare_io).is_none());
    assert_eq!(TlsClass::Other.to_string(), "the connection failed");
    Ok(())
}


#[test]
fn an_io_error_loses_its_text_and_keeps_its_kind() -> TestResult {
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::General(format!("{MARKER}{ESCAPE}")));
    let fixed = without_peer_text(wrapped);
    assert_eq!(fixed.kind(), io::ErrorKind::InvalidData);
    assert!(is_clean(&chain(&fixed)), "{}", chain(&fixed));
    Ok(())
}


async fn hostile_server(dir: &Path, platform: &Platform) -> Result<SocketAddr, Box<dyn Error>> {
    let files = write_leaf(dir, "hostile", &issue(&platform.platform_ca, &hostile_spec())?)?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            read_certificates(&files.certificate)?,
            parse_private_key(&read_private_key(&files.key)?, &files.key)?,
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Err(error) = acceptor.accept(stream).await {
                tracing::debug!(%error, "hostile server ended");
            }
        }
    });
    Ok(address)
}


fn agent_config(dir: &Path, platform: &Platform) -> Result<SharedClientConfig, Box<dyn Error>> {
    let paths = client_paths(dir, "agent", platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    custom_client(&paths, &[&TLS13], true)
}


#[tokio::test]
async fn a_hostile_server_certificate_name_never_reaches_the_client_error() -> TestResult {
    init_logging()?;
    let dir = tempdir()?;
    let platform = make_platform()?;
    let address = hostile_server(dir.path(), &platform).await?;
    let error = connect_channel(address, agent_config(dir.path(), &platform)?, SERVER_NAME)
        .await
        .err()
        .ok_or("connected")?;
    assert!(matches!(error, ChannelError::Transport(_)), "{error:?}");
    assert!(is_clean(&chain(&error)), "{}", chain(&error));
    Ok(())
}


#[tokio::test]
async fn raw_rustls_still_carries_the_peer_name_so_the_test_proves_something() -> TestResult {
    init_logging()?;
    let dir = tempdir()?;
    let platform = make_platform()?;
    let address = hostile_server(dir.path(), &platform).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])?
        .with_root_certificates(root_store(&paths.platform_ca)?)
        .with_no_client_auth();
    let tcp = TcpStream::connect(address).await?;
    let raw = TlsConnector::from(Arc::new(config))
        .connect(SERVER_NAME.to_string().try_into()?, tcp)
        .await
        .err()
        .ok_or("connected")?;
    assert!(chain(&raw).contains(MARKER));
    Ok(())
}


#[tokio::test]
async fn a_hostile_client_certificate_never_reaches_the_server_error() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let rogue = make_authority()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &rogue, &hostile_spec())?;
    let outcome = bounded(attempt_with(server.address, custom_client(&paths, &[&TLS13], true)?)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?.err().ok_or("served")?;
    assert!(matches!(served, ChannelError::Handshake(TlsClass::Certificate)), "{served:?}");
    assert!(is_clean(&chain(&served)), "{}", chain(&served));
    Ok(())
}

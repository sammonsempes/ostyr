#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/types.rs"]
mod types;


use core_api::error::StartupError;
use core_api::middleware::rate_key;
use core_api::model::{ApiConfig, TlsFiles};
use core_api::server::{admit_connection, check_transport, listening_address, new_listener, run_module, serve, stop_listener, tls_server_config};
use core_api::types::{ConnectionTable, ServerHandle};
use fixture::{extra_access, extra_router, fixture, private_file, set_mode};
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use rustls_pki_types::ServerName;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use types::{TestError, TestResult};


const WORLD_READABLE: u32 = 0o644;


const LOCALHOST_NAME: &str = "localhost";


const HEALTH_REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";


struct Pki {
    certificate: String,
    key: String,
    der: rustls_pki_types::CertificateDer<'static>,
}


fn pki() -> Result<Pki, TestError> {
    let generated = generate_simple_self_signed(vec![LOCALHOST_NAME.to_owned()])?;
    Ok(Pki {
        certificate: generated.cert.pem(),
        key: generated.signing_key.serialize_pem(),
        der: generated.cert.der().clone(),
    })
}


fn tls_files_in(dir: &Path, pki: &Pki) -> Result<TlsFiles, TestError> {
    let files = TlsFiles {
        certificate: dir.join("server.pem"),
        key: dir.join("server.key"),
    };
    fs::write(&files.certificate, &pki.certificate)?;
    private_file(&files.key, pki.key.as_bytes())?;
    Ok(files)
}


fn client_config(pki: &Pki, version: &'static rustls::SupportedProtocolVersion) -> Result<ClientConfig, TestError> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.der.clone())?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[version])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}


async fn read_response<Stream: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: Stream) -> Result<String, TestError> {
    stream.write_all(HEALTH_REQUEST.as_bytes()).await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


fn start(config: &ApiConfig, router: axum::Router) -> (ServerHandle, JoinHandle<Result<(), StartupError>>) {
    let handle = ServerHandle::new();
    let owned = config.clone();
    let running = handle.clone();
    (handle, tokio::spawn(async move { serve(&owned, router, running).await }))
}


async fn listening(handle: &ServerHandle) -> Result<SocketAddr, TestError> {
    Ok(handle.listening().await.ok_or("server did not start")?)
}


#[test]
fn plain_http_is_refused_off_loopback() -> TestResult {
    let tls = TlsFiles {
        certificate: "c".into(),
        key: "k".into(),
    };
    assert!(check_transport("127.0.0.1:1".parse()?, None).is_ok());
    assert!(check_transport("[::1]:1".parse()?, None).is_ok());
    assert!(check_transport("0.0.0.0:1".parse()?, Some(&tls)).is_ok());
    let refused = check_transport("0.0.0.0:1".parse()?, None);
    assert!(matches!(refused, Err(StartupError::PlainHttpRefused(_))));
    assert!(refused.is_err_and(|error| error.to_string().contains("0.0.0.0:1")));
    Ok(())
}


#[tokio::test]
async fn serve_refuses_plain_http_off_loopback() -> TestResult {
    let fx = fixture()?;
    let config = ApiConfig {
        address: "0.0.0.0:0".parse()?,
        ..fx.config.clone()
    };
    let result = serve(&config, fx.router.clone(), ServerHandle::new()).await;
    assert!(matches!(result, Err(StartupError::PlainHttpRefused(_))));
    Ok(())
}


#[tokio::test]
async fn serve_refuses_unreadable_tls_files() -> TestResult {
    let fx = fixture()?;
    let config = ApiConfig {
        tls: Some(TlsFiles {
            certificate: fx.dir.path().join("none.pem"),
            key: fx.dir.path().join("none.key"),
        }),
        ..fx.config.clone()
    };
    let result = serve(&config, fx.router.clone(), ServerHandle::new()).await;
    assert!(matches!(result, Err(StartupError::Io(_))));
    Ok(())
}


#[tokio::test]
async fn plain_http_serves_on_loopback() -> TestResult {
    let fx = fixture()?;
    let (handle, running) = start(&fx.config, fx.router.clone());
    let address = listening(&handle).await?;
    let reply = read_response(TcpStream::connect(address).await?).await?;
    assert!(reply.starts_with("HTTP/1.1 200 OK"));
    assert!(reply.contains("\"status\":\"ok\""));
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn tls_serves_versions_one_two_and_one_three() -> TestResult {
    let fx = fixture()?;
    let pki = pki()?;
    let config = ApiConfig {
        tls: Some(tls_files_in(fx.dir.path(), &pki)?),
        ..fx.config.clone()
    };
    let (handle, running) = start(&config, fx.router.clone());
    let address = listening(&handle).await?;
    let name = ServerName::try_from(LOCALHOST_NAME)?;
    let versions = vec![(&TLS12, ProtocolVersion::TLSv1_2), (&TLS13, ProtocolVersion::TLSv1_3)];
    for (allowed, expected) in versions {
        let connector = TlsConnector::from(Arc::new(client_config(&pki, allowed)?));
        let stream = connector.connect(name.clone(), TcpStream::connect(address).await?).await?;
        assert_eq!(stream.get_ref().1.protocol_version(), Some(expected));
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
        assert!(read_response(stream).await?.starts_with("HTTP/1.1 200 OK"));
    }
    let refused = TcpStream::connect(address).await?;
    assert!(read_response(refused).await.map_or(true, |reply| !reply.starts_with("HTTP/1.1 200")));
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[test]
fn tls_material_is_validated() -> TestResult {
    let dir = tempdir()?;
    let pki = pki()?;
    let files = tls_files_in(dir.path(), &pki)?;
    assert!(tls_server_config(&files).is_ok());

    set_mode(&files.key, WORLD_READABLE)?;
    assert_eq!(matches!(tls_server_config(&files), Err(StartupError::InsecureFile { .. })), cfg!(unix));
    set_mode(&files.key, fixture::OWNER_ONLY)?;

    let missing_key = TlsFiles {
        key: dir.path().join("absent.key"),
        ..files.clone()
    };
    assert!(matches!(tls_server_config(&missing_key), Err(StartupError::Io(_))));

    let missing_certificate = TlsFiles {
        certificate: dir.path().join("absent.pem"),
        ..files.clone()
    };
    assert!(matches!(tls_server_config(&missing_certificate), Err(StartupError::Io(_))));

    let other = pki_pair()?;
    let other_key = dir.path().join("other.key");
    private_file(&other_key, other.as_bytes())?;
    let mismatched = TlsFiles {
        key: other_key,
        ..files.clone()
    };
    assert!(matches!(tls_server_config(&mismatched), Err(StartupError::Tls(_))));

    let garbage_key = dir.path().join("garbage.key");
    private_file(&garbage_key, b"not a key")?;
    let unreadable = TlsFiles { key: garbage_key, ..files };
    assert!(matches!(tls_server_config(&unreadable), Err(StartupError::Pem(_))));
    Ok(())
}


fn pki_pair() -> Result<String, TestError> {
    Ok(generate_simple_self_signed(vec![LOCALHOST_NAME.to_owned()])?.signing_key.serialize_pem())
}


fn module_yaml(dir: &Path, listen: &str) -> Result<String, TestError> {
    let key_file = dir.join("store.key");
    private_file(&key_file, &[fixture::KEY_FILL; fixture::KEY_BYTES])?;
    let compromised = dir.join("compromised.txt");
    fs::write(&compromised, "passwordpassword\n")?;
    let yaml = format!(
        "name: example\nversion: 1.0.0\nlisten: \"{listen}\"\nsettings:\n  accounts_store: {}\n  audit_log: {}\n  key_file: {}\n  compromised_list: {}\n",
        dir.join("accounts.json").display(),
        dir.join("audit.log").display(),
        key_file.display(),
        compromised.display(),
    );
    let path = dir.join("module.yaml");
    fs::write(&path, yaml)?;
    Ok(path.display().to_string())
}


#[tokio::test]
async fn a_module_runs_from_its_configuration_file() -> TestResult {
    let dir = tempdir()?;
    let path = module_yaml(dir.path(), "127.0.0.1:0")?;
    let listener = new_listener();
    let running = listener.clone();
    let task = tokio::spawn(async move { run_module(&[path], extra_router(), extra_access(), vec![], running, None).await });
    let address = listening_address(&listener).await.ok_or("server did not start")?;
    assert!(read_response(TcpStream::connect(address).await?).await?.starts_with("HTTP/1.1 200 OK"));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn run_module_reports_startup_problems() -> TestResult {
    let dir = tempdir()?;
    let usage = run_module(&[], extra_router(), extra_access(), vec![], new_listener(), None).await;
    assert!(matches!(usage, Err(StartupError::Usage(_))));
    let absent = run_module(
        &[dir.path().join("none.yaml").display().to_string()],
        extra_router(),
        extra_access(),
        vec![],
        new_listener(),
        None,
    )
    .await;
    assert!(matches!(absent, Err(StartupError::Config(_))));
    let exposed = module_yaml(dir.path(), "0.0.0.0:8443")?;
    let plain = run_module(&[exposed], extra_router(), extra_access(), vec![], new_listener(), None).await;
    assert!(matches!(plain, Err(StartupError::PlainHttpRefused(_))));
    let local = module_yaml(dir.path(), "127.0.0.1:0")?;
    fs::remove_file(dir.path().join("compromised.txt"))?;
    let broken = run_module(&[local], extra_router(), extra_access(), vec![], new_listener(), None).await;
    assert!(matches!(broken, Err(StartupError::Io(_))));
    Ok(())
}


const PARTIAL_HEADERS: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\n";


const HANG_GUARD: Duration = Duration::from_secs(120);


const TABLE_LIMIT: usize = 2;


const SETTLE_PAUSE: Duration = Duration::from_millis(200);


const LONG_HEADER_TIMEOUT: Duration = Duration::from_secs(30);


async fn read_until_closed(stream: &mut TcpStream) -> Result<String, TestError> {
    let mut bytes = Vec::new();
    tokio::time::timeout(HANG_GUARD, stream.read_to_end(&mut bytes)).await??;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


#[tokio::test]
async fn a_client_sending_headers_slowly_is_disconnected() -> TestResult {
    let fx = fixture()?;
    let (handle, running) = start(&fx.config, fx.router.clone());
    let address = listening(&handle).await?;
    let mut slow = TcpStream::connect(address).await?;
    slow.write_all(PARTIAL_HEADERS.as_bytes()).await?;
    let reply = read_until_closed(&mut slow).await?;
    assert!(!reply.starts_with("HTTP/1.1 200"));
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn connections_per_source_are_limited_and_released() -> TestResult {
    let fx = fixture()?;
    let config = ApiConfig {
        header_read_timeout: LONG_HEADER_TIMEOUT,
        ..fx.config.clone()
    };
    let (handle, running) = start(&config, fx.router.clone());
    let address = listening(&handle).await?;
    let mut held = Vec::new();
    for _ in 0..config.limits.max_connections_per_source {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(PARTIAL_HEADERS.as_bytes()).await?;
        held.push(stream);
    }
    tokio::time::sleep(SETTLE_PAUSE).await;
    let mut excess = TcpStream::connect(address).await?;
    let reply = read_until_closed(&mut excess).await?;
    assert!(reply.is_empty());
    held.clear();
    tokio::time::sleep(SETTLE_PAUSE).await;
    assert!(read_response(TcpStream::connect(address).await?).await?.starts_with("HTTP/1.1 200 OK"));
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[test]
fn the_connection_table_counts_folds_and_forgets_sources() -> TestResult {
    let table = ConnectionTable::default();
    let first = "2001:db8:1:2::1".parse()?;
    let same_prefix = "2001:db8:1:2:ffff::9".parse()?;
    let one = admit_connection(&table, first, TABLE_LIMIT).ok_or("first refused")?;
    let two = admit_connection(&table, same_prefix, TABLE_LIMIT).ok_or("second refused")?;
    assert!(admit_connection(&table, first, TABLE_LIMIT).is_none());
    assert_eq!(table.lock().map_err(|_| "poisoned")?.get(&rate_key(first)), Some(&TABLE_LIMIT));
    drop(one);
    assert_eq!(table.lock().map_err(|_| "poisoned")?.get(&rate_key(first)), Some(&1));
    drop(two);
    assert!(table.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_dual_stack_listener_keys_an_ipv4_client_by_its_ipv4_address() -> TestResult {
    let fx = fixture()?;
    let pki = pki()?;
    let config = ApiConfig {
        address: "[::]:0".parse()?,
        tls: Some(tls_files_in(fx.dir.path(), &pki)?),
        ..fx.config.clone()
    };
    let (handle, running) = start(&config, fx.router.clone());
    let address = listening(&handle).await?;
    let connector = TlsConnector::from(Arc::new(client_config(&pki, &TLS13)?));
    let stream = connector
        .connect(
            ServerName::try_from(LOCALHOST_NAME)?,
            TcpStream::connect(("127.0.0.1", address.port())).await?,
        )
        .await?;
    assert!(read_response(stream).await?.starts_with("HTTP/1.1 200 OK"));
    let keys: Vec<String> = fx.state.limiter.lock().map_err(|_| "poisoned")?.keys().map(ToString::to_string).collect();
    assert_eq!(keys, ["127.0.0.1".to_owned()]);
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";


const SLOW_BODY_REQUEST: &str =
    "POST /auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"user";


#[tokio::test]
async fn an_http2_preface_is_not_served() -> TestResult {
    let fx = fixture()?;
    let (handle, running) = start(&fx.config, fx.router.clone());
    let address = listening(&handle).await?;
    let mut prior = TcpStream::connect(address).await?;
    prior.write_all(HTTP2_PREFACE).await?;
    let mut first = [0; 1];
    let read = tokio::time::timeout(SETTLE_PAUSE, prior.read(&mut first)).await;
    assert!(read.map_or(true, |bytes| bytes.map_or(true, |count| count == 0 || first != [0])));
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_tls_client_offering_only_h2_fails_the_handshake() -> TestResult {
    let fx = fixture()?;
    let pki = pki()?;
    let config = ApiConfig {
        tls: Some(tls_files_in(fx.dir.path(), &pki)?),
        ..fx.config.clone()
    };
    let (handle, running) = start(&config, fx.router.clone());
    let address = listening(&handle).await?;
    let mut client = client_config(&pki, &TLS13)?;
    client.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));
    let outcome = connector
        .connect(ServerName::try_from(LOCALHOST_NAME)?, TcpStream::connect(address).await?)
        .await;
    assert!(outcome.is_err());
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_client_sending_its_body_slowly_gets_408() -> TestResult {
    let fx = fixture()?;
    let (handle, running) = start(&fx.config, fx.router.clone());
    let address = listening(&handle).await?;
    let mut slow = TcpStream::connect(address).await?;
    slow.write_all(SLOW_BODY_REQUEST.as_bytes()).await?;
    let reply = read_until_closed(&mut slow).await?;
    assert!(reply.starts_with("HTTP/1.1 408"));
    handle.shutdown();
    assert!(running.await?.is_ok());
    Ok(())
}

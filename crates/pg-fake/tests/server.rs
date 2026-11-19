use core_pg::connect::connect;
use core_pg::settings::parse_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{start, Fake, Mode, Reply, MAX_MESSAGES};
use pg_fake::types::Handler;
use rcgen::SanType;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_postgres::Client;
use tokio_rustls::TlsConnector;


const SSL_LENGTH: i32 = 8;


const SSL_CODE: i32 = 80_877_103;


const PROTOCOL: i32 = 196_608;


const CLEARTEXT_PASSWORD_BYTES: usize = 9;


const READY_BYTES: usize = 6;


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


const SEVEN: i32 = 7;


fn by_sql() -> Handler {
    Arc::new(|sql| {
        if sql.contains("HANG") {
            Reply::Hang
        } else if sql.contains("DROP") {
            Reply::Drop
        } else if sql.contains("ERR") {
            Reply::Error("42601")
        } else if sql.contains("INTS") {
            Reply::IntRows(vec![SEVEN])
        } else if sql.contains("TEXT") {
            Reply::Rows(vec![vec!["a".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


#[cfg(unix)]
fn write_secret(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}


async fn client_with(password: &str) -> Result<(Result<Client, core_pg::error::PgError>, Fake, TempDir), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Tls(pki.server), "p", by_sql()).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, password)?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let client = connect(&parse_settings(&text, "pg.yaml")?).await;
    Ok((client, fake, dir))
}


#[tokio::test]
async fn a_wrong_password_is_refused_and_reported() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with("wrong").await?;
    assert!(client.is_err());
    assert_eq!(fake.passwords.recv().await, Some(b"wrong".to_vec()));
    Ok(())
}


#[tokio::test]
async fn a_real_client_runs_simple_and_extended_statements() -> Result<(), Box<dyn Error>> {
    let (connection, mut fake, _dir) = client_with("p").await?;
    let client = connection?;
    assert_eq!(fake.passwords.recv().await, Some(b"p".to_vec()));
    client.simple_query("SELECT 1").await?;
    let texts = client.query("SELECT TEXT $1", &[&"v"]).await?;
    assert_eq!(texts.first().map(|row| row.get::<_, String>(0)), Some("a".to_owned()));
    let ints = client.query("SELECT INTS", &[]).await?;
    assert_eq!(ints.first().map(|row| row.get::<_, i32>(0)), Some(SEVEN));
    let failure = client.query("SELECT ERR", &[]).await.err().ok_or("accepted")?;
    assert_eq!(failure.code().map(|code| code.code().to_owned()), Some("42601".to_owned()));
    assert_eq!(fake.statements.recv().await, Some("SELECT 1".to_owned()));
    client.simple_query("TEXT").await?;
    assert!(client.simple_query("ERR").await.is_err());
    assert!(client.query("SELECT 1", &[]).await?.is_empty());
    assert!(client.simple_query("DROP").await.is_err());
    Ok(())
}


#[tokio::test]
async fn a_hung_statement_is_logged_and_never_answered() -> Result<(), Box<dyn Error>> {
    let (connection, mut fake, _dir) = client_with("p").await?;
    let client = Arc::new(connection?);
    let simple = Arc::clone(&client);
    let pending = tokio::spawn(async move { simple.simple_query("HANG").await.is_ok() });
    assert_eq!(fake.passwords.recv().await, Some(b"p".to_vec()));
    assert_eq!(fake.statements.recv().await, Some("HANG".to_owned()));
    pending.abort();
    Ok(())
}


#[tokio::test]
async fn a_hung_extended_statement_is_logged_and_never_answered() -> Result<(), Box<dyn Error>> {
    let (connection, mut fake, _dir) = client_with("p").await?;
    let client = Arc::new(connection?);
    let extended = Arc::clone(&client);
    let waiting = tokio::spawn(async move { extended.query("HANG $1", &[&"v"]).await.is_ok() });
    assert_eq!(fake.statements.recv().await, Some("HANG $1".to_owned()));
    waiting.abort();
    Ok(())
}


#[tokio::test]
async fn the_accept_loop_ends_after_its_cap() -> Result<(), Box<dyn Error>> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )?;
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let mut fake = start(Mode::Tls(pki.server), "p", by_sql()).await?;
    let address = SocketAddr::new(loopback(), fake.port);
    for _ in 0..MAX_MESSAGES {
        TcpStream::connect(address).await?;
    }
    assert!(fake.statements.recv().await.is_none());
    Ok(())
}


async fn raw_session(closing: &[u8]) -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let mut fake = start(Mode::Tls(pki.server), "p", by_sql()).await?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes())?)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut socket = TcpStream::connect(SocketAddr::new(loopback(), fake.port)).await?;
    socket.write_all(&[SSL_LENGTH.to_be_bytes(), SSL_CODE.to_be_bytes()].concat()).await?;
    let mut answer = [0u8; 1];
    socket.read_exact(&mut answer).await?;
    assert_eq!(&answer, b"S");
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::IpAddress(loopback().into()), socket)
        .await?;
    tls.write_all(&[SSL_LENGTH.to_be_bytes(), PROTOCOL.to_be_bytes()].concat()).await?;
    let mut request = [0u8; CLEARTEXT_PASSWORD_BYTES];
    tls.read_exact(&mut request).await?;
    tls.write_all(&pg_fake::fake::frame(b'p', b"p\0")?).await?;
    let mut accepted = [0u8; CLEARTEXT_PASSWORD_BYTES + READY_BYTES];
    tls.read_exact(&mut accepted).await?;
    assert_eq!(fake.passwords.recv().await, Some(b"p".to_vec()));
    tls.write_all(closing).await?;
    tls.shutdown().await?;
    let mut rest = Vec::new();
    assert!(matches!(tls.read_to_end(&mut rest).await, Ok(0) | Err(_)));
    Ok(())
}


#[tokio::test]
async fn a_clean_tls_close_after_unknown_messages_ends_the_session() -> Result<(), Box<dyn Error>> {
    let closing = [pg_fake::fake::frame(b'H', &[])?, pg_fake::fake::frame(b'D', b"P\0")?].concat();
    raw_session(&closing).await
}


#[tokio::test]
async fn a_terminate_over_tls_ends_the_session() -> Result<(), Box<dyn Error>> {
    raw_session(&pg_fake::fake::frame(b'X', &[])?).await
}

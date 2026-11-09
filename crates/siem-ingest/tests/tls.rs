use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use siem_ingest::clickhouse::{agent_for, clickhouse_sink, new_agent, read_ca, MAX_CA_BYTES};
use siem_ingest::error::InsertError;
use siem_ingest::model::Document;
use siem_ingest::settings::{open_settings, IngestSettings};
use siem_ingest::types::SinkFn;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


const EVENT: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event"}}"#;


const HOST: &str = "localhost";


const CHUNK: usize = 4096;


const ZERO: u8 = 0;


const MAX_READS: usize = 100;


const GARBAGE: &[u8] = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";


pub struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


pub struct Pki {
    pub certificate: String,
    pub key: String,
}


fn pki() -> Result<Pki, Box<dyn Error>> {
    let generated = generate_simple_self_signed(vec![HOST.to_owned()])?;
    Ok(Pki {
        certificate: generated.cert.pem(),
        key: generated.signing_key.serialize_pem(),
    })
}


pub struct Server {
    pub port: u16,
    pub handle: JoinHandle<io::Result<String>>,
}


fn serve_tls_once(pki: &Pki) -> Result<Server, Box<dyn Error>> {
    let certificates = CertificateDer::pem_slice_iter(pki.certificate.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(pki.key.as_bytes())?;
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        let (stream, _) = listener.accept()?;
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?, stream);
        let mut received = String::new();
        let mut chunk = [ZERO; CHUNK];
        let mut reads = 0;
        while !received.ends_with("}\n") && reads < MAX_READS {
            reads += 1;
            let count = tls.read(&mut chunk)?;
            received.push_str(&String::from_utf8_lossy(chunk.get(..count).unwrap_or_default()));
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        tls.flush().map(|()| received)
    });
    Ok(Server { port, handle })
}


fn settings_file(dir: &TempDir, port: u16, ca_file: &Path) -> Result<PathBuf, Box<dyn Error>> {
    fs::write(dir.path().join("password"), "s3cret\n")?;
    let path = dir.path().join("ingest.yaml");
    fs::write(
        &path,
        format!(
            "clickhouse_url: \"https://{HOST}:{port}\"\nclickhouse_password_file: \"{}\"\nclickhouse_ca_file: \"{}\"\ninsert_timeout_ms: 5000\n",
            dir.path().join("password").display(),
            ca_file.display()
        ),
    )?;
    Ok(path)
}


fn open_sink(path: PathBuf) -> Result<Box<SinkFn>, Box<dyn Error>> {
    let log = genesis_log(io::sink());
    let engine = open_settings(path, Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }))?;
    Ok(clickhouse_sink(Arc::new(engine)))
}


fn document() -> Document {
    Document {
        payload: EVENT.as_bytes().to_vec(),
        timestamp: OffsetDateTime::UNIX_EPOCH,
    }
}


fn failure(sink: &SinkFn) -> Result<String, Box<dyn Error>> {
    Ok(sink("tenant-a", &[document()]).err().ok_or("should fail")?.to_string())
}


#[test]
fn the_sink_trusts_the_configured_ca_over_https() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let pki = pki()?;
    fs::write(dir.path().join("ca.pem"), &pki.certificate)?;
    let server = serve_tls_once(&pki)?;
    let sink = open_sink(settings_file(&dir, server.port, &dir.path().join("ca.pem"))?)?;
    sink("tenant-a", &[document()]).map_err(|error| error.to_string())?;
    let request = server.handle.join().map_err(|_| "server thread panicked")??;
    assert!(request.contains(r#""tenant":"tenant-a""#), "{request}");
    assert!(request.contains("x-clickhouse-key: s3cret"));
    Ok(())
}


#[test]
fn a_server_signed_by_another_ca_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let stranger = pki()?;
    fs::write(dir.path().join("ca.pem"), &stranger.certificate)?;
    let server = serve_tls_once(&pki()?)?;
    let sink = open_sink(settings_file(&dir, server.port, &dir.path().join("ca.pem"))?)?;
    assert_eq!(failure(&sink)?, "ClickHouse insert failed: Unavailable");
    assert!(server.handle.join().map_err(|_| "server thread panicked")?.is_err());
    Ok(())
}


#[test]
fn a_bad_ca_file_fails_before_any_request() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let ca = dir.path().join("ca.pem");
    let sink = open_sink(settings_file(&dir, 1, &ca)?)?;
    assert_eq!(failure(&sink)?, "the ClickHouse CA file could not be read");
    fs::write(&ca, vec![b'A'; MAX_CA_BYTES as usize + 1])?;
    assert_eq!(failure(&sink)?, "the ClickHouse CA file exceeds the size cap");
    fs::write(&ca, "not a certificate")?;
    assert_eq!(failure(&sink)?, "the ClickHouse CA file holds no usable PEM certificate");
    fs::write(&ca, GARBAGE)?;
    let settings = IngestSettings {
        clickhouse_ca_file: Some(ca),
        ..IngestSettings::default()
    };
    assert!(matches!(agent_for(&settings), Err(InsertError::CaInvalid(_))));
    Ok(())
}


#[test]
fn the_ca_reader_is_bounded_and_reports_failures() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_ca(&b"pem"[..])?, b"pem");
    assert!(matches!(read_ca(Failing), Err(InsertError::CaFile(_))));
    assert!(matches!(read_ca(io::repeat(b'A')), Err(InsertError::CaTooLarge)));
    assert!(new_agent(None, true).is_ok());
    assert!(agent_for(&IngestSettings::default()).is_ok());
    Ok(())
}

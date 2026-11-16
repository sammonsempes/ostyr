use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::ring::default_provider;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::spawn;


const CHUNK: usize = 4096;


const MAX_READS: usize = 64;


const MAX_CONNECTIONS: usize = 256;


const HEADER_END: &[u8] = b"\r\n\r\n";


const AUTH_MARK: &str = "authorization: ";


pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub declared: usize,
    pub headers: Vec<(String, String)>,
    pub hold: bool,
}


pub struct Standin {
    pub port: u16,
    pub ca_pem: String,
    pub log: Arc<Mutex<Vec<String>>>,
}


pub fn reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        body: body.as_bytes().to_vec(),
        declared: body.len(),
        headers: Vec::new(),
        hold: false,
    }
}


pub fn with_header(mut answer: Reply, name: &str, value: &str) -> Reply {
    answer.headers.push((name.to_owned(), value.to_owned()));
    answer
}


fn record(log: &Mutex<Vec<String>>, entry: String) {
    if let Ok(mut guard) = log.lock() {
        guard.push(entry);
    }
}


fn has_end(received: &[u8]) -> bool {
    received.windows(HEADER_END.len()).any(|window| window == HEADER_END)
}


fn read_head(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [0u8; CHUNK];
    let mut reads = 0;
    while !has_end(&received) && reads < MAX_READS {
        reads += 1;
        let count = tls.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn serve(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    handler: &(dyn Fn(&str, &str) -> Reply + Send + Sync),
    log: &Mutex<Vec<String>>,
) -> io::Result<()> {
    let mut tls = StreamOwned::new(ServerConnection::new(config).map_err(io::Error::other)?, stream);
    let head = read_head(&mut tls)?;
    let mut words = head.split_whitespace();
    let method = words.next().unwrap_or("");
    let target = words.next().unwrap_or("");
    let authorisation = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with(AUTH_MARK))
        .and_then(|line| line.get(AUTH_MARK.len()..))
        .unwrap_or("none");
    record(log, format!("{method} {target} auth={authorisation}"));
    let answer = handler(method, target);
    let extra: String = answer.headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
    let status = answer.status;
    let declared = answer.declared;
    tls.write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: {declared}\r\n{extra}Connection: close\r\n\r\n").as_bytes())?;
    tls.write_all(&answer.body)?;
    tls.flush()?;
    if answer.hold {
        let mut chunk = [0u8; CHUNK];
        tls.read(&mut chunk).map(|_| ())
    } else {
        Ok(())
    }
}


pub fn start(handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static) -> Result<Standin, Box<dyn std::error::Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::new())?;
    params.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let certificate = params.self_signed(&key)?;
    serve_with(handler, certificate.pem(), certificate.pem(), key)
}


/// A stand-in whose CA-signed leaf carries only the given DNS names, so it never matches the host dialled.
pub fn start_with_names(
    handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static,
    names: Vec<String>,
) -> Result<Standin, Box<dyn std::error::Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let leaf_key = KeyPair::generate()?;
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf = CertificateParams::new(names)?.signed_by(&leaf_key, &issuer)?;
    let chain = format!("{}{}", leaf.pem(), ca.pem());
    serve_with(handler, ca.pem(), chain, leaf_key)
}


fn serve_with(
    handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static,
    ca_pem: String,
    chain_pem: String,
    key: KeyPair,
) -> Result<Standin, Box<dyn std::error::Error>> {
    let certificates = CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let private = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes())?;
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, private)?,
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let thread_log = Arc::clone(&log);
    spawn(move || {
        listener.incoming().take(MAX_CONNECTIONS).for_each(|incoming| {
            let outcome = incoming.and_then(|stream| serve(stream, Arc::clone(&config), &handler, &thread_log));
            if let Err(error) = outcome {
                record(&thread_log, format!("ERR {error}"));
            }
        });
    });
    Ok(Standin { port, ca_pem, log })
}


pub fn requests(standin: &Standin) -> Vec<String> {
    standin.log.lock().map_or_else(
        |_| Vec::new(),
        |guard| guard.iter().filter(|entry| !entry.starts_with("ERR")).cloned().collect(),
    )
}

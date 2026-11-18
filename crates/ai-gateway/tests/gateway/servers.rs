use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


pub const MAX_HEAD_LINES: usize = 64;


pub const PARTIAL_BODY: &[u8] = b"{\"cho";


pub const ANNOUNCED_BODY: usize = 100;


pub struct Served {
    pub port: u16,
    pub request: JoinHandle<io::Result<String>>,
}


pub struct Held {
    pub port: u16,
    pub release: Sender<()>,
    pub done: JoinHandle<io::Result<()>>,
}


pub struct TlsServed {
    pub served: Served,
    pub ca_pem: String,
}


/// The request line, the headers and the body (by `Content-Length`), as text.
pub fn read_request<Stream: Read + Write>(stream: &mut Stream) -> io::Result<String> {
    let mut reader = BufReader::new(stream);
    let head = reader
        .by_ref()
        .lines()
        .take(MAX_HEAD_LINES)
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect::<io::Result<Vec<String>>>()?;
    let length = head
        .iter()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|value| value.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(format!("{}\n\n{}", head.join("\n"), String::from_utf8_lossy(&body)))
}


pub fn http_reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}


pub fn plain_server(reply: Vec<u8>) -> Result<Served, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let request = spawn(move || {
        let (mut stream, _peer) = listener.accept()?;
        let text = read_request(&mut stream)?;
        stream.write_all(&reply)?;
        Ok(text)
    });
    Ok(Served { port, request })
}


/// Accepts one connection and holds it: `partial` is written first (headers of an answer that never finishes), then nothing until released.
pub fn held_server(partial: Vec<u8>) -> Result<Held, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let (release, wait) = channel::<()>();
    let done = spawn(move || {
        let (mut stream, _peer) = listener.accept()?;
        read_request(&mut stream)?;
        stream.write_all(&partial)?;
        stream.flush()?;
        wait.recv().map_err(io::Error::other)
    });
    Ok(Held { port, release, done })
}


pub fn closed_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}


/// A CA, and a leaf signed by it for `names`; the server answers one TLS connection.
pub fn tls_server(names: Vec<SanType>, reply: Vec<u8>) -> Result<TlsServed, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = names;
    let certificate = params.signed_by(&key, &Issuer::new(ca_params, ca_key))?;
    let private = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)?,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let request = spawn(move || {
        let (tcp, _peer) = listener.accept()?;
        let connection = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut stream = StreamOwned::new(connection, tcp);
        let text = read_request(&mut stream)?;
        stream.write_all(&reply)?;
        stream.flush()?;
        Ok(text)
    });
    Ok(TlsServed {
        served: Served { port, request },
        ca_pem: ca.pem(),
    })
}

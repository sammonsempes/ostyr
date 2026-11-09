use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


pub const SERVER_NAME: &str = "localhost";


pub struct TestPki {
    pub ca_pem: String,
    pub server_config: Arc<ServerConfig>,
}


pub fn test_pki() -> Result<TestPki, Box<dyn Error>> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)?;
    Ok(TestPki {
        ca_pem: cert.pem(),
        server_config: Arc::new(server_config),
    })
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub authorization: String,
    pub title: String,
    pub content_type: String,
    pub body: String,
}


pub struct Silent {
    pub port: u16,
    pub held: JoinHandle<io::Result<()>>,
}


pub struct Sink {
    pub port: u16,
    pub seen: JoinHandle<io::Result<Vec<Seen>>>,
}


pub fn serve_one<Stream: Read + Write>(stream: Stream, status: u16, location: &str) -> io::Result<Seen> {
    let mut reader = BufReader::new(stream);
    let headers = reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect::<io::Result<Vec<_>>>()?;
    let header = |name: &str| {
        headers
            .iter()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _value)| key.eq_ignore_ascii_case(name))
                    .map(|(_key, value)| value.trim().to_string())
            })
            .unwrap_or_default()
    };
    let length = header("content-length").parse::<usize>().map_err(io::Error::other)?;
    let mut body = vec![u8::MIN; length];
    reader.read_exact(&mut body)?;
    let response = format!("HTTP/1.1 {status} X\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    reader.get_mut().write_all(response.as_bytes())?;
    reader.get_mut().flush()?;
    Ok(Seen {
        authorization: header("authorization"),
        title: header("title"),
        content_type: header("content-type"),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}


/// One TLS connection per entry of `replies` (status, location header).
pub fn spawn_sink(config: Arc<ServerConfig>, replies: Vec<(u16, String)>) -> Result<Sink, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let seen = spawn(move || {
        replies
            .iter()
            .map(|(status, location)| {
                let (tcp, _peer) = listener.accept()?;
                let connection = ServerConnection::new(config.clone()).map_err(io::Error::other)?;
                serve_one(StreamOwned::new(connection, tcp), *status, location)
            })
            .collect()
    });
    Ok(Sink { port, seen })
}


/// Accepts one connection and holds it silent until `release` fires.
pub fn spawn_silent(release: Receiver<()>) -> Result<Silent, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        let (_tcp, _peer) = listener.accept()?;
        release.recv().map_err(io::Error::other)
    });
    Ok(Silent { port, held: handle })
}

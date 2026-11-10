use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
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


pub struct Seen {
    pub request_line: String,
    pub body: Vec<u8>,
}


pub struct Sink {
    pub port: u16,
    pub seen: JoinHandle<io::Result<Vec<Seen>>>,
}


pub fn serve_one<Stream: Read + Write>(stream: Stream, status: u16, reply: &[u8]) -> io::Result<Seen> {
    let mut reader = BufReader::new(stream);
    let headers = reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect::<io::Result<Vec<_>>>()?;
    let length = headers
        .iter()
        .find_map(|line| line.to_lowercase().strip_prefix("content-length:").map(|value| value.trim().to_owned()))
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(io::Error::other)?
        .unwrap_or(0);
    let mut body = vec![u8::MIN; length];
    reader.read_exact(&mut body)?;
    let head = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", reply.len());
    reader.get_mut().write_all(head.as_bytes())?;
    reader.get_mut().write_all(reply)?;
    reader.get_mut().flush()?;
    Ok(Seen {
        request_line: headers.first().cloned().ok_or_else(|| io::Error::other("no request line"))?,
        body,
    })
}


/// Serves one TLS request per entry of `replies`.
pub fn spawn_sink(tls: Arc<ServerConfig>, replies: Vec<(u16, Vec<u8>)>) -> Result<Sink, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let seen = spawn(move || {
        replies
            .iter()
            .map(|(status, reply)| {
                let (tcp, _peer) = listener.accept()?;
                serve_one(
                    StreamOwned::new(ServerConnection::new(tls.clone()).map_err(io::Error::other)?, tcp),
                    *status,
                    reply,
                )
            })
            .collect()
    });
    Ok(Sink { port, seen })
}

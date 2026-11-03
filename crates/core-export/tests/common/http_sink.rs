use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


/// Reads one request, answers with `status`, returns the `Authorization` header value (empty when absent) and the body.
pub fn serve_one<Stream: Read + Write>(stream: Stream, status: u16) -> io::Result<(String, String)> {
    let mut reader = BufReader::new(stream);
    let headers = reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect::<io::Result<Vec<_>>>()?;
    let header = |name: &str| {
        headers.iter().find_map(|line| {
            line.to_lowercase()
                .strip_prefix(&format!("{name}:"))
                .map(|value| value.trim().to_string())
        })
    };
    let length = header("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(io::Error::other)?
        .unwrap_or(0);
    let mut body = vec![u8::MIN; length];
    reader.read_exact(&mut body)?;
    let response = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    reader.get_mut().write_all(response.as_bytes())?;
    reader.get_mut().flush()?;
    Ok((
        header("authorization").unwrap_or(String::new()),
        String::from_utf8_lossy(&body).into_owned(),
    ))
}


pub struct HttpSink {
    pub port: u16,
    pub bodies: JoinHandle<io::Result<Vec<(String, String)>>>,
}


/// Serves one request per entry of `statuses`, over TLS when `tls` is given. Returns the port.
pub fn spawn_http_sink(tls: Option<Arc<ServerConfig>>, statuses: Vec<u16>) -> Result<HttpSink, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        statuses
            .iter()
            .map(|status| {
                let (tcp, _peer) = listener.accept()?;
                match &tls {
                    Some(config) => serve_one(
                        StreamOwned::new(ServerConnection::new(config.clone()).map_err(io::Error::other)?, tcp),
                        *status,
                    ),
                    None => serve_one(tcp, *status),
                }
            })
            .collect()
    });
    Ok(HttpSink { port, bodies: handle })
}

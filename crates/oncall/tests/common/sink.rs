use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub authorization: String,
    pub title: String,
    pub content_type: String,
    pub body: String,
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

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


/// Accepts one TLS connection and returns everything the client wrote until its close_notify. Returns the `localhost:port` address.
pub struct TlsSink {
    pub address: String,
    pub received: JoinHandle<std::io::Result<Vec<u8>>>,
}


pub fn spawn_tls_sink(config: Arc<ServerConfig>) -> Result<TlsSink, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = format!("localhost:{}", listener.local_addr()?.port());
    let handle = spawn(move || {
        let (tcp, _peer) = listener.accept()?;
        let connection = ServerConnection::new(config).map_err(std::io::Error::other)?;
        let mut stream = StreamOwned::new(connection, tcp);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).map(|_count| received)
    });
    Ok(TlsSink { address, received: handle })
}

use crate::tls_sink::TlsSink;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{sleep, spawn};
use std::time::Duration;


const SLOW_CHUNK: usize = 512;


const SLOW_MAX_READS: usize = 1_000_000;


const EMPTY_BYTE: u8 = 0;


const SLOW_PAUSE: Duration = Duration::from_millis(1);


/// Like `tls_sink::spawn_tls_sink` but reads small chunks with a pause, so the client finishes writing long before the server has read everything.
pub fn spawn_slow_tls_sink(config: Arc<ServerConfig>) -> Result<TlsSink, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = format!("localhost:{}", listener.local_addr()?.port());
    let handle = spawn(move || {
        let (tcp, _peer) = listener.accept()?;
        let connection = ServerConnection::new(config).map_err(std::io::Error::other)?;
        let mut stream = StreamOwned::new(connection, tcp);
        let mut received = Vec::new();
        let mut chunk = [EMPTY_BYTE; SLOW_CHUNK];
        let mut reads = 0;
        let mut count = stream.read(&mut chunk)?;
        while count > 0 && reads < SLOW_MAX_READS {
            reads += 1;
            received.extend(chunk.iter().take(count));
            sleep(SLOW_PAUSE);
            count = stream.read(&mut chunk)?;
        }
        stream.conn.send_close_notify();
        stream.flush()?;
        Ok(received)
    });
    Ok(TlsSink { address, received: handle })
}

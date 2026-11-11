use crate::stub::read_request;
use std::io::{self, Write};
use std::net::TcpListener;
use std::sync::mpsc::Receiver;
use std::thread::{spawn, JoinHandle};


const FILLER: u8 = b'7';


const MAX_CHUNKS: usize = 4096;


const BLOCK: usize = 65_536;


/// Accepts one connection, reads the request and holds it open until `release` fires.
pub fn stall(listener: TcpListener, release: Receiver<()>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        release.recv().map_err(io::Error::other)
    })
}


/// Sends the headers of a long reply and one row, then holds the connection until `release` fires.
pub fn half_reply(listener: TcpListener, release: Receiver<()>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n1\t1\n")?;
        release.recv().map_err(io::Error::other)
    })
}


/// Streams a body without end (`Connection: close`) until the client hangs up; returns the chunks written.
pub fn endless(listener: TcpListener) -> JoinHandle<io::Result<usize>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")?;
        let block = vec![FILLER; BLOCK];
        Ok((0..MAX_CHUNKS).take_while(|_| stream.write_all(&block).is_ok()).count())
    })
}

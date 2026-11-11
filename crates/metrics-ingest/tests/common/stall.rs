use crate::stub::read_request;
use std::io;
use std::net::TcpListener;
use std::sync::mpsc::Receiver;
use std::thread::{spawn, JoinHandle};


/// Accepts one connection, reads the request and holds it open until `release` fires.
pub fn stall(listener: TcpListener, release: Receiver<()>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        release.recv().map_err(io::Error::other)
    })
}

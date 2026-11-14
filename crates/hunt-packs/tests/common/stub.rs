use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


const ACCEPT_POLLS: usize = 5_000;


const POLL_STEP: Duration = Duration::from_millis(2);


pub fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        let text = String::from_utf8_lossy(&received).to_lowercase();
        expected = text.find(HEADER_END).map_or(usize::MAX, |end| {
            let length = text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            end + HEADER_END.len() + length
        });
        if count == 0 {
            expected = 0;
        }
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


pub fn accept_within(listener: &TcpListener, polls: usize) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let stream = (0..polls)
        .find_map(|_| match listener.accept() {
            Ok((stream, _)) => Some(Ok(stream)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep(POLL_STEP);
                None
            }
            Err(error) => Some(Err(error)),
        })
        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, "no client connected")))?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}


/// Answers one connection with a status, extra header lines and a body; returns the request it saw; fails if nobody connects.
pub fn reply(listener: TcpListener, status: &'static str, extra: &'static str, body: Vec<u8>) -> JoinHandle<io::Result<String>> {
    reply_within(listener, ACCEPT_POLLS, status, extra, body)
}


pub fn reply_within(listener: TcpListener, polls: usize, status: &'static str, extra: &'static str, body: Vec<u8>) -> JoinHandle<io::Result<String>> {
    spawn(move || {
        let mut stream = accept_within(&listener, polls)?;
        let seen = read_request(&mut stream)?;
        let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", body.len());
        stream.write_all(head.as_bytes())?;
        stream.write_all(&body)?;
        Ok(seen)
    })
}

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::thread::{spawn, JoinHandle};


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


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


/// Answers one connection per scripted status line, in order; every request is sent on the channel as it is read.
pub fn serve(listener: TcpListener, statuses: Vec<&'static str>) -> (JoinHandle<io::Result<()>>, Receiver<String>) {
    let (sender, requests) = channel();
    let handle = spawn(move || {
        statuses.into_iter().try_for_each(|status| {
            let (mut stream, _) = listener.accept()?;
            let request = read_request(&mut stream)?;
            sender.send(request).map_err(io::Error::other)?;
            let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(response.as_bytes())
        })
    });
    (handle, requests)
}

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


const MAX_POLLS: usize = 120_000;


const POLL_INTERVAL: Duration = Duration::from_millis(1);


const DEFAULT_STATUS: &str = "200 OK";


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
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


/// A scripted server: the thread serves until `stop` is set, then returns every request it saw.
pub struct Server {
    pub handle: JoinHandle<io::Result<Vec<String>>>,
    pub stop: Arc<AtomicBool>,
}


fn answer(stream: &mut TcpStream, status: &str) -> io::Result<String> {
    let request = read_request(stream)?;
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes())?;
    Ok(request)
}


fn poll_once(listener: &TcpListener, statuses: &[&'static str], seen: &mut Vec<String>) -> io::Result<()> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            stream.set_nonblocking(false)?;
            let status = statuses.get(seen.len()).copied().unwrap_or(DEFAULT_STATUS);
            seen.push(answer(&mut stream, status)?);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            sleep(POLL_INTERVAL);
            Ok(())
        }
        Err(error) => Err(error),
    }
}


/// Answers each connection with the next scripted status line (then `200 OK`) until stopped; it never waits for an expected request count.
pub fn serve(listener: TcpListener, statuses: Vec<&'static str>) -> Server {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = spawn(move || {
        listener.set_nonblocking(true)?;
        let mut seen = Vec::new();
        let mut polls = 0;
        while !flag.load(Ordering::SeqCst) && polls < MAX_POLLS {
            polls += 1;
            poll_once(&listener, &statuses, &mut seen)?;
        }
        Ok(seen)
    });
    Server { handle, stop }
}


/// Stops the server once the client is done and returns the requests it saw.
pub fn finish(server: Server) -> io::Result<Vec<String>> {
    server.stop.store(true, Ordering::SeqCst);
    server.handle.join().map_err(|_| io::Error::other("server thread panicked"))?
}


/// Accepts one connection, reads the request and holds it open until `release` fires.
pub fn stall(listener: TcpListener, release: Receiver<()>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        release.recv().map_err(io::Error::other)
    })
}

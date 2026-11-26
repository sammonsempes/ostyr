use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


const MAX_POLLS: usize = 6000;


const POLL: Duration = Duration::from_millis(5);


const READ_GUARD: Duration = Duration::from_secs(10);


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


/// The scripted stub: it stops when told to or after `MAX_POLLS` waits, so no test can hang on it.
pub struct Stub {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<io::Result<usize>>>,
}


impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                tracing::warn!("the clickhouse stub thread panicked");
            }
        }
    }
}


fn accept_one(listener: &TcpListener, stop: &AtomicBool) -> io::Result<Option<TcpStream>> {
    let found = (0..MAX_POLLS).find_map(|_poll| {
        if stop.load(Ordering::SeqCst) {
            Some(Ok(None))
        } else {
            match listener.accept() {
                Ok((stream, _)) => Some(Ok(Some(stream))),
                Err(failure) if failure.kind() == io::ErrorKind::WouldBlock => {
                    sleep(POLL);
                    None
                }
                Err(failure) => Some(Err(failure)),
            }
        }
    });
    found.unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, "the stub waited too long for a connection")))
}


fn answer_one(stream: &mut TcpStream, status: &str, sender: &Sender<String>) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READ_GUARD))?;
    stream.set_write_timeout(Some(READ_GUARD))?;
    let request = read_request(stream)?;
    sender.send(request).map_err(io::Error::other)?;
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes())
}


/// Answers one connection per scripted status line, in order; every request is sent on the channel as it is read.
pub fn serve(listener: TcpListener, statuses: Vec<&'static str>) -> io::Result<(Stub, Receiver<String>)> {
    listener.set_nonblocking(true)?;
    let (sender, requests) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&stop);
    let handle = spawn(move || {
        statuses.into_iter().try_fold(0, |served, status| {
            Ok(match accept_one(&listener, &seen)? {
                Some(mut stream) => {
                    answer_one(&mut stream, status, &sender)?;
                    served + 1
                }
                None => served,
            })
        })
    });
    Ok((Stub { stop, handle: Some(handle) }, requests))
}


/// Stops the stub, joins it and returns how many connections it answered; a stub that timed out or failed is an error.
pub fn finish(mut stub: Stub) -> Result<usize, Box<dyn std::error::Error>> {
    stub.stop.store(true, Ordering::SeqCst);
    let handle = stub.handle.take().ok_or("the stub was already finished")?;
    Ok(handle.join().map_err(|_panic| "the stub panicked")??)
}

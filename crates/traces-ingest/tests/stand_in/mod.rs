use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


const HEADER_END: &[u8] = b"\r\n\r\n";


const CHUNK: usize = 65_536;


const MAX_READS: usize = 10_000_000;


const MAX_CONNECTIONS: usize = 100_000;


const ZERO: u8 = 0;


pub struct Server {
    pub port: u16,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Served>,
}


pub struct Served {
    pub handled: usize,
    pub errors: Vec<String>,
}


fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .to_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length:").and_then(|value| value.trim().parse::<usize>().ok()))
        .unwrap_or(0)
}


pub fn drain<Source: Read>(stream: &mut Source) -> io::Result<usize> {
    let mut head = Vec::new();
    let mut chunk = vec![ZERO; CHUNK];
    let mut remaining: Option<usize> = None;
    let mut reads = 0;
    let mut total = 0;
    while remaining.is_none_or(|left| left > 0) && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        total += count;
        remaining = match remaining {
            None => {
                head.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
                head.windows(HEADER_END.len())
                    .position(|window| window == HEADER_END)
                    .map(|end| content_length(head.get(..end).unwrap_or(&[])).saturating_sub(head.len() - end - HEADER_END.len()))
            }
            Some(left) => Some(left.saturating_sub(count)),
        };
        remaining = if count == 0 { Some(0) } else { remaining };
    }
    Ok(total)
}


fn answer(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    drain(stream)?;
    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
}


fn start(listener: TcpListener, fail_at: Option<usize>, stop: Arc<AtomicBool>) -> JoinHandle<Served> {
    spawn(move || {
        let mut served = Served {
            handled: 0,
            errors: Vec::new(),
        };
        let mut woken = false;
        let mut accepted = 0;
        while !woken && accepted < MAX_CONNECTIONS {
            accepted += 1;
            match listener.accept() {
                Ok((mut stream, _)) => {
                    woken = stop.load(Ordering::SeqCst);
                    if !woken {
                        let status = if fail_at == Some(served.handled) {
                            "500 Internal Server Error"
                        } else {
                            "200 OK"
                        };
                        match answer(&mut stream, status) {
                            Ok(()) => served.handled += 1,
                            Err(error) => served.errors.push(format!("connection {accepted}: {error}")),
                        }
                    }
                }
                Err(error) => served.errors.push(format!("accept {accepted}: {error}")),
            }
        }
        served
    })
}


pub fn serve(fail_at: Option<usize>) -> io::Result<Server> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let handle = start(listener, fail_at, Arc::clone(&stop));
    Ok(Server { port, stop, handle })
}


pub fn finish(server: Server) -> Result<Served, Box<dyn std::error::Error>> {
    server.stop.store(true, Ordering::SeqCst);
    TcpStream::connect(("127.0.0.1", server.port))?;
    Ok(server.handle.join().map_err(|_| "stand-in thread panicked")?)
}

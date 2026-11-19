use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::Duration;


const MAX_POLLS: usize = 60_000;


const POLL_INTERVAL: Duration = Duration::from_millis(1);


const READ_LIMIT: Duration = Duration::from_secs(30);


/// Accepts one connection through a non-blocking listener polled at most `MAX_POLLS` times; the stream gets a read timeout.
pub fn accept_bounded(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let accepted = (0..MAX_POLLS).find_map(|_poll| match listener.accept() {
        Ok((stream, _)) => Some(Ok(stream)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            sleep(POLL_INTERVAL);
            None
        }
        Err(error) => Some(Err(error)),
    });
    let stream = accepted.unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, "no client connected")))?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READ_LIMIT))?;
    Ok(stream)
}

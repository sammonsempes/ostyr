use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


const ACCEPT_POLL: Duration = Duration::from_millis(50);


const MAX_ACCEPT_POLLS: usize = 400;


pub const CLEAN_NAMES: [&str; 19] = [
    "readonly",
    "max_result_rows",
    "timeout_overflow_mode",
    "timeout_overflow_mode_leaf",
    "read_overflow_mode",
    "read_overflow_mode_leaf",
    "group_by_overflow_mode",
    "result_overflow_mode",
    "sort_overflow_mode",
    "set_overflow_mode",
    "distinct_overflow_mode",
    "join_overflow_mode",
    "transfer_overflow_mode",
    "limit",
    "offset",
    "additional_result_filter",
    "filter",
    "additional_table_filters",
    "date_time_output_format",
];


/// The hang guard: a connection that never comes is a named error after a bounded number of polls, never a blocked thread.
pub fn accept_guarded(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let accepted = (0..MAX_ACCEPT_POLLS).find_map(|_| match listener.accept() {
        Ok((stream, _)) => Some(Ok(stream)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            sleep(ACCEPT_POLL);
            None
        }
        Err(error) => Some(Err(error)),
    });
    let stream = accepted.unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, "the client never connected")))?;
    stream.set_nonblocking(false)?;
    listener.set_nonblocking(false)?;
    Ok(stream)
}


/// Answers the settings check of a run with a profile that changed nothing outside the pins.
pub fn serve_check(listener: &TcpListener) -> io::Result<String> {
    let stream = accept_guarded(listener)?;
    serve(stream, "200 OK", "", format!("{}\n", CLEAN_NAMES.join("\n")).as_bytes())
}


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


/// Answers one connection with a status, extra header lines and a body; returns the request it saw; blocks until the client connects.
pub fn reply(listener: TcpListener, status: &'static str, extra: &'static str, body: Vec<u8>) -> JoinHandle<io::Result<String>> {
    spawn(move || {
        serve_check(&listener)?;
        let stream = accept_guarded(&listener)?;
        serve(stream, status, extra, &body)
    })
}


pub fn serve(mut stream: TcpStream, status: &str, extra: &str, body: &[u8]) -> io::Result<String> {
    let seen = read_request(&mut stream)?;
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", body.len());
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(seen)
}

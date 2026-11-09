use crate::error::TransportError;
use crate::limits::{MAX_CONNECT_ADDRESSES, MAX_IO_STEPS, MAX_REPLY_BYTES, MAX_REPLY_LINE_BYTES, READ_CHUNK_BYTES, WRITE_CHUNK_BYTES};
use crate::types::ClockFn;
use rustls::ClientConnection;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};


const DECIMAL_BASE: u16 = 10;


const CODE_DIGITS: usize = 3;


const TEXT_OFFSET: usize = CODE_DIGITS + 1;


/// One connection: the socket, the TLS state once upgraded, and the single deadline of the whole send read through the injected clock.
pub struct Link<'clock> {
    pub tcp: TcpStream,
    pub tls: Option<ClientConnection>,
    pub deadline: Instant,
    pub clock: ClockFn<'clock>,
}


/// A parsed reply: the code and the text of every line (the text is never put in an error).
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}


pub struct ReplyLine {
    pub code: u16,
    pub last: bool,
    pub text: String,
}


/// A timeout is the deadline; anything else keeps its cause.
pub fn io_error(error: Error) -> TransportError {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => TransportError::Deadline,
        _ => TransportError::Io(error),
    }
}


/// Time left before the deadline; none left is the `Deadline` error (a zero socket timeout would be an error of its own).
pub fn remaining(deadline: Instant, clock: ClockFn) -> Result<Duration, TransportError> {
    let left = deadline.saturating_duration_since(clock());
    if left.is_zero() {
        Err(TransportError::Deadline)
    } else {
        Ok(left)
    }
}


/// Called before every socket operation: the socket timeout becomes what is left of the total deadline.
pub fn arm(tcp: &TcpStream, deadline: Instant, clock: ClockFn) -> Result<(), TransportError> {
    let left = remaining(deadline, clock)?;
    tcp.set_read_timeout(Some(left))
        .and_then(|()| tcp.set_write_timeout(Some(left)))
        .map_err(io_error)
}


/// The first address that connects within the deadline; a failed one is logged and the next is tried.
pub fn connect_first(addresses: &[SocketAddr], deadline: Instant, clock: ClockFn) -> Result<TcpStream, TransportError> {
    let outcome = addresses
        .iter()
        .take(MAX_CONNECT_ADDRESSES)
        .try_fold(TransportError::NoAddress, |previous, address| {
            let reason = previous.to_string();
            tracing::debug!(reason, "relay address not usable, trying the next");
            match remaining(deadline, clock).and_then(|left| TcpStream::connect_timeout(address, left).map_err(io_error)) {
                Ok(tcp) => ControlFlow::Break(tcp),
                Err(error) => ControlFlow::Continue(error),
            }
        });
    match outcome {
        ControlFlow::Break(tcp) => Ok(tcp),
        ControlFlow::Continue(error) => Err(error),
    }
}


pub fn pump_write(conn: &mut ClientConnection, tcp: &mut TcpStream, deadline: Instant, clock: ClockFn) -> Result<(), TransportError> {
    arm(tcp, deadline, clock)?;
    conn.write_tls(tcp).map(|_written| ()).map_err(io_error)
}


/// One socket read into the TLS state; an end of stream here is a close without close_notify.
pub fn pump_read(conn: &mut ClientConnection, tcp: &mut TcpStream, deadline: Instant, clock: ClockFn) -> Result<(), TransportError> {
    arm(tcp, deadline, clock)?;
    if conn.read_tls(tcp).map_err(io_error)? == 0 {
        Err(TransportError::Closed)
    } else {
        conn.process_new_packets().map(|_state| ()).map_err(TransportError::Tls)
    }
}


pub fn handshake_step(conn: &mut ClientConnection, tcp: &mut TcpStream, deadline: Instant, clock: ClockFn) -> Option<Result<(), TransportError>> {
    if !conn.is_handshaking() && !conn.wants_write() {
        Some(Ok(()))
    } else if conn.wants_write() {
        pump_write(conn, tcp, deadline, clock).err().map(Err)
    } else {
        pump_read(conn, tcp, deadline, clock).err().map(Err)
    }
}


/// The TLS handshake driven one socket operation at a time, each under the total deadline; the client Finished is flushed before it returns.
pub fn handshake(conn: &mut ClientConnection, tcp: &mut TcpStream, deadline: Instant, clock: ClockFn) -> Result<(), TransportError> {
    (0..MAX_IO_STEPS)
        .find_map(|_| handshake_step(conn, tcp, deadline, clock))
        .unwrap_or(Err(TransportError::Closed))
}


pub fn flush_step(conn: &mut ClientConnection, tcp: &mut TcpStream, deadline: Instant, clock: ClockFn) -> Option<Result<(), TransportError>> {
    if conn.wants_write() {
        pump_write(conn, tcp, deadline, clock).err().map(Err)
    } else {
        Some(Ok(()))
    }
}


/// Plain: chunks, each under the deadline. TLS: the plaintext goes to the TLS buffer, then the records are flushed one socket write at a time.
pub fn send(link: &mut Link, bytes: &[u8]) -> Result<(), TransportError> {
    let Link { tcp, tls, deadline, clock } = link;
    match tls.as_mut() {
        None => bytes.chunks(WRITE_CHUNK_BYTES).try_for_each(|chunk| {
            arm(tcp, *deadline, *clock)?;
            tcp.write_all(chunk).map_err(io_error)
        }),
        Some(conn) => {
            conn.writer().write_all(bytes).map_err(io_error)?;
            (0..MAX_IO_STEPS)
                .find_map(|_| flush_step(conn, tcp, *deadline, *clock))
                .unwrap_or(Err(TransportError::Closed))
        }
    }
}


/// The TLS reader never touches the socket: its `WouldBlock` (mapped to `Deadline` by `io_error`) only means no plaintext is buffered yet.
pub fn tls_read_step(
    conn: &mut ClientConnection,
    tcp: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    clock: ClockFn,
) -> Option<Result<usize, TransportError>> {
    match conn.reader().read(buffer).map_err(io_error) {
        Err(TransportError::Deadline) => pump_read(conn, tcp, deadline, clock).err().map(Err),
        other => Some(other),
    }
}


/// One read of at most `buffer.len()` bytes under the deadline; zero is an end of stream.
pub fn read_some(link: &mut Link, buffer: &mut [u8]) -> Result<usize, TransportError> {
    let Link { tcp, tls, deadline, clock } = link;
    match tls.as_mut() {
        None => {
            arm(tcp, *deadline, *clock)?;
            tcp.read(buffer).map_err(io_error)
        }
        Some(conn) => (0..MAX_IO_STEPS)
            .find_map(|_| tls_read_step(conn, tcp, buffer, *deadline, *clock))
            .unwrap_or(Err(TransportError::Closed)),
    }
}


/// One reply line: three digits, then a space (last line) or a hyphen (more follow); a line over the bound is refused.
pub fn parse_line(segment: &[u8]) -> Result<ReplyLine, TransportError> {
    if segment.len() > MAX_REPLY_LINE_BYTES {
        Err(TransportError::ReplyTooLong)
    } else {
        let text = std::str::from_utf8(segment).map_err(|_error| TransportError::ReplyFormat)?;
        let body = text.trim_end_matches(['\r', '\n']);
        let digits = body.get(..CODE_DIGITS).ok_or(TransportError::ReplyFormat)?;
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            Err(TransportError::ReplyFormat)
        } else {
            let last = match body.as_bytes().get(CODE_DIGITS) {
                None | Some(b' ') => Ok(true),
                Some(b'-') => Ok(false),
                Some(_) => Err(TransportError::ReplyFormat),
            }?;
            let code = digits.bytes().fold(0, |value, digit| value * DECIMAL_BASE + u16::from(digit - b'0'));
            Ok(ReplyLine {
                code,
                last,
                text: body.get(TEXT_OFFSET..).unwrap_or_default().to_owned(),
            })
        }
    }
}


/// The reply when `buffer` holds a whole one and nothing after it (data after the last line is refused: it could be injected before TLS).
pub fn parse_reply(buffer: &[u8]) -> Result<Option<Reply>, TransportError> {
    let end = buffer.iter().rposition(|byte| *byte == b'\n').map_or(0, |position| position + 1);
    let (complete, tail) = buffer.split_at(end);
    if tail.len() > MAX_REPLY_LINE_BYTES {
        Err(TransportError::ReplyTooLong)
    } else {
        let lines = complete
            .split_inclusive(|byte| *byte == b'\n')
            .map(parse_line)
            .collect::<Result<Vec<_>, _>>()?;
        match (lines.iter().position(|line| line.last), lines.first()) {
            (Some(position), Some(first)) if position + 1 == lines.len() && tail.is_empty() && lines.iter().all(|line| line.code == first.code) => {
                Ok(Some(Reply {
                    code: first.code,
                    lines: lines.iter().map(|line| line.text.clone()).collect(),
                }))
            }
            (Some(_), _) => Err(TransportError::ReplyFormat),
            _ => Ok(None),
        }
    }
}


/// One iteration of `read_reply`: a read of at most what the reply bound still allows, then a parse; `None` asks for more bytes.
pub fn reply_step(
    read_some: &mut dyn FnMut(&mut [u8]) -> Result<usize, TransportError>,
    buffer: &mut Vec<u8>,
) -> Option<Result<Reply, TransportError>> {
    let mut chunk = vec![0; (MAX_REPLY_BYTES + 1 - buffer.len()).min(READ_CHUNK_BYTES)];
    match read_some(&mut chunk) {
        Err(error) => Some(Err(error)),
        Ok(0) => Some(Err(TransportError::Closed)),
        Ok(count) => {
            buffer.extend(chunk.iter().take(count));
            if buffer.len() > MAX_REPLY_BYTES {
                Some(Err(TransportError::ReplyTooLong))
            } else {
                parse_reply(buffer).transpose()
            }
        }
    }
}


/// Reads one reply, never more than `MAX_REPLY_BYTES + 1` bytes in total and no newline needed to stop; every read is one call of `read_some`.
pub fn read_reply(read_some: &mut dyn FnMut(&mut [u8]) -> Result<usize, TransportError>) -> Result<Reply, TransportError> {
    let mut buffer = Vec::new();
    (0..=MAX_REPLY_BYTES)
        .find_map(|_| reply_step(read_some, &mut buffer))
        .unwrap_or(Err(TransportError::ReplyTooLong))
}

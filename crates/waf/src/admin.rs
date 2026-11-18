use crate::cadir::open_ca_directory;
use crate::error::{DeliverError, WafError};
use crate::limits::{MIN_REMAINING_MILLISECONDS, STATUS_DIGITS_START, STATUS_PREFIX_BYTES, UNTRUSTED_ADMIN};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};


/// The judged parent directory of the admin socket, held open, and the socket's file name inside it.
#[derive(Debug)]
pub struct AdminDirectory {
    pub handle: OwnedFd,
    pub name: String,
}


/// Walks the socket's parent from `/` judging every handle (no symlink, no sticky or open ancestor) and keeps the final handle.
pub fn open_admin_directory(socket: &str) -> Result<AdminDirectory, DeliverError> {
    let path = Path::new(socket);
    let parent = path.parent().ok_or(DeliverError::AdminDir(WafError::BadCaDir(UNTRUSTED_ADMIN)))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(DeliverError::AdminDir(WafError::BadCaDir(UNTRUSTED_ADMIN)))?;
    let handle = open_ca_directory(parent).map_err(DeliverError::AdminDir)?;
    Ok(AdminDirectory {
        handle,
        name: name.to_owned(),
    })
}


/// A status line `HTTP/1.x NNN` read from the first bytes of the answer; nothing else of it is read.
pub fn parse_status(prefix: &[u8]) -> io::Result<u16> {
    let digits = prefix
        .get(STATUS_DIGITS_START..STATUS_PREFIX_BYTES)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| text.parse::<u16>().ok());
    prefix
        .starts_with(b"HTTP/1.")
        .then_some(digits)
        .flatten()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed status line"))
}


/// Reads exactly the status prefix, one byte at a time, each read under what is left of the deadline.
pub fn read_status_prefix(stream: &mut UnixStream, deadline: Duration) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    (0..STATUS_PREFIX_BYTES).try_fold(Vec::new(), |mut bytes, _| {
        let remaining = deadline
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(MIN_REMAINING_MILLISECONDS));
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [u8::MIN; 1];
        stream.read_exact(&mut byte)?;
        bytes.extend_from_slice(&byte);
        Ok(bytes)
    })
}


/// `GET /id/<id>` on the admin socket through the held directory (`/proc/self/fd`), a non-blocking connect; only the status code is read.
pub fn id_status(directory: &AdminDirectory, id: &str, deadline: Duration) -> io::Result<u16> {
    let path = format!("/proc/self/fd/{}/{}", directory.handle.as_raw_fd(), directory.name);
    let address = SocketAddrUnix::new(&path)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    connect(&socket, &address)?;
    let mut stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(deadline))?;
    stream.write_all(format!("GET /id/{id} HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n").as_bytes())?;
    parse_status(&read_status_prefix(&mut stream, deadline)?)
}

#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;
use waf::admin::{id_status, open_admin_directory, parse_status};
use waf::error::DeliverError;


const SHORT: Duration = Duration::from_millis(100);


const LONG: Duration = Duration::from_secs(30);


const STATUS_OK: u16 = 200;


const STATUS_MISSING: u16 = 404;


const INVALID_BYTE: u8 = u8::MAX;


const STATUS_BYTES: usize = 12;


const OPEN_DIRECTORY: u32 = 0o755;


fn listener_in(directory: &Path) -> Result<UnixListener, Box<dyn Error>> {
    let held = fs::File::open(directory)?;
    Ok(UnixListener::bind(format!("/proc/self/fd/{}/sock", held.as_raw_fd()))?)
}


fn directory() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    Ok(dir)
}


fn request_head(reader: &mut BufReader<UnixStream>) -> io::Result<Vec<String>> {
    reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect()
}


fn socket_text(dir: &Path) -> String {
    dir.join("sock").to_string_lossy().into_owned()
}


#[test]
fn the_status_line_is_parsed_from_the_first_twelve_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(parse_status(b"HTTP/1.1 200")?, STATUS_OK);
    assert_eq!(parse_status(b"HTTP/1.0 404")?, STATUS_MISSING);
    assert!(parse_status(b"HTTP/1.1 2x0").is_err());
    assert!(parse_status(b"garbage garb").is_err());
    assert!(parse_status(b"HTTP/1.1").is_err());
    assert!(parse_status(&[INVALID_BYTE; STATUS_BYTES]).is_err());
    Ok(())
}


#[test]
fn the_admin_directory_is_judged_and_held() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let held = open_admin_directory(&socket_text(dir.path()))?;
    assert_eq!(held.name, "sock");
    assert!(matches!(open_admin_directory("/"), Err(DeliverError::AdminDir(_))));
    assert!(matches!(open_admin_directory("/a/.."), Err(DeliverError::AdminDir(_))));
    assert!(matches!(open_admin_directory("/tmp/sock"), Err(DeliverError::AdminDir(_))));
    Ok(())
}


#[test]
fn a_status_is_read_through_the_held_directory() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let listener = listener_in(dir.path())?;
    let held = open_admin_directory(&socket_text(dir.path()))?;
    let server = std::thread::spawn(move || -> io::Result<String> {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream);
        let head = request_head(&mut reader)?;
        reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\n\r\n")?;
        Ok(format!("{}\r\n", head.first().map_or("", String::as_str)))
    });
    assert_eq!(id_status(&held, "ostyr-abc", LONG)?, STATUS_OK);
    assert_eq!(server.join().map_err(|_| "panicked")??, "GET /id/ostyr-abc HTTP/1.1\r\n");
    Ok(())
}


#[test]
fn a_silent_peer_ends_at_the_deadline_and_a_closing_peer_is_an_error() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let listener = listener_in(dir.path())?;
    let held = open_admin_directory(&socket_text(dir.path()))?;
    let silent = std::thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream);
        request_head(&mut reader)?;
        let mut rest = Vec::new();
        reader.read_until(0, &mut rest)?;
        Ok(())
    });
    let failure = id_status(&held, "ostyr-abc", SHORT).err().ok_or("answered")?;
    assert!(matches!(failure.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut));
    silent.join().map_err(|_| "panicked")??;
    Ok(())
}


#[test]
fn a_peer_that_closes_without_an_answer_and_a_missing_socket_are_errors() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let held = open_admin_directory(&socket_text(dir.path()))?;
    assert!(id_status(&held, "ostyr-abc", SHORT).is_err());
    let listener = listener_in(dir.path())?;
    let closer = std::thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        drop(stream);
        Ok(())
    });
    let failure = id_status(&held, "ostyr-abc", LONG).err().ok_or("answered")?;
    assert!(matches!(
        failure.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    ));
    closer.join().map_err(|_| "panicked")??;
    Ok(())
}

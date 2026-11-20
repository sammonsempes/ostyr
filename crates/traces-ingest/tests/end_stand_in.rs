mod common;
mod stand_in;


use common::types::TestResult;
use stand_in::{drain, finish, serve};
use std::io::{self, Read, Write};
use std::net::TcpStream;


struct Trickle {
    data: Vec<u8>,
    position: usize,
    sizes: Vec<usize>,
    call: usize,
}


impl Read for Trickle {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.sizes.get(self.call % self.sizes.len()).copied().unwrap_or(1);
        self.call += 1;
        let end = (self.position + size).min(self.data.len()).min(self.position + buffer.len());
        let part = self.data.get(self.position..end).unwrap_or(&[]);
        buffer.get_mut(..part.len()).unwrap_or(&mut []).copy_from_slice(part);
        self.position = end;
        Ok(part.len())
    }
}


const BODY_BYTES: usize = 300;


const CONNECTIONS: usize = 25;


const ODD_READ: usize = 7;


const ROUNDS: usize = 3;


fn request(header_name: &str) -> Vec<u8> {
    let mut bytes = format!("POST /?q=x HTTP/1.1\r\nhost: a\r\n{header_name}: {BODY_BYTES}\r\n\r\n").into_bytes();
    bytes.extend(std::iter::repeat_n(b'x', BODY_BYTES));
    bytes
}


fn read_sizes_total(bytes: &[u8]) -> io::Result<Vec<usize>> {
    (1..=bytes.len())
        .map(|first| {
            let mut stream = Trickle {
                data: bytes.to_vec(),
                position: 0,
                sizes: vec![first, 1, ODD_READ],
                call: 0,
            };
            drain(&mut stream)
        })
        .collect()
}


#[test]
fn the_stand_in_reads_the_whole_request_whatever_the_read_sizes() -> TestResult {
    let bytes = request("content-length");
    assert!(read_sizes_total(&bytes)?.iter().all(|total| *total == bytes.len()));
    Ok(())
}


#[test]
fn the_stand_in_reads_a_header_written_in_capitals_or_without_a_space() -> TestResult {
    let capitals = request("Content-Length");
    assert!(read_sizes_total(&capitals)?.iter().all(|total| *total == capitals.len()));
    let tight = String::from_utf8(request("content-length"))?
        .replace("content-length: ", "content-length:")
        .into_bytes();
    assert!(read_sizes_total(&tight)?.iter().all(|total| *total == tight.len()));
    Ok(())
}


#[test]
fn the_stand_in_accepts_every_connection_and_stops_cleanly_after_the_last() -> TestResult {
    let server = serve(None)?;
    let bytes = request("content-length");
    (0..CONNECTIONS).try_for_each(|_| -> TestResult {
        let mut stream = TcpStream::connect(("127.0.0.1", server.port))?;
        stream.write_all(&bytes)?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply)?;
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
        Ok(())
    })?;
    let served = finish(server)?;
    assert_eq!(served.handled, CONNECTIONS);
    assert!(served.errors.is_empty(), "{:?}", served.errors);
    Ok(())
}


#[test]
fn finishing_at_once_never_fails_the_wake_up_connection() -> TestResult {
    let served = finish(serve(None)?)?;
    assert_eq!(served.handled, 0);
    assert!(served.errors.is_empty());
    Ok(())
}


#[test]
fn a_planned_failure_answers_500_for_that_connection_only() -> TestResult {
    let server = serve(Some(1))?;
    let bytes = request("content-length");
    let statuses = (0..ROUNDS)
        .map(|_| -> io::Result<Vec<u8>> {
            let mut stream = TcpStream::connect(("127.0.0.1", server.port))?;
            stream.write_all(&bytes)?;
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply)?;
            Ok(reply)
        })
        .collect::<io::Result<Vec<Vec<u8>>>>()?;
    let served = finish(server)?;
    assert!(statuses.iter().map(|reply| reply.starts_with(b"HTTP/1.1 500")).eq([false, true, false]));
    assert_eq!(served.handled, ROUNDS);
    Ok(())
}

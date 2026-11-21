#[path = "common/accept.rs"]
mod accept;


use accept::accept_bounded;
use cloud_cost::fetch_error::{HttpClass, HttpFailure};
use cloud_cost::fetch_model::HttpRequest;
use cloud_cost::transport::{agent_for_request, ca_failure, classify, read_class, send};
use rcgen::generate_simple_self_signed;
use siem_ingest::clickhouse::MAX_CA_BYTES;
use std::error::Error;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::TcpSocket;


const HEAD_END: &[u8] = b"\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 64;


const BOUND: Duration = Duration::from_secs(30);


const CAP: u64 = 100;


const BODY_BYTES: usize = 64 * 1024;


const HUGE_LENGTH: u64 = 10_000_000_000;


const SHORT_TIMEOUT: Duration = Duration::from_millis(300);


const LONG_TIMEOUT: Duration = Duration::from_secs(30);


const PARTIAL_BYTES: usize = 10;


const DECLARED: usize = 1000;


const ENDLESS_CHUNKS: usize = 4000;


const STATUS_OK: u16 = 200;


const STATUS_REDIRECT: u16 = 302;


const STATUS_FORBIDDEN: u16 = 403;


const MARKER_BYTES: u64 = 6;


enum Script {
    Reply {
        status: &'static str,
        extra: &'static str,
        declared: u64,
        body: Vec<u8>,
    },
    Endless,
    Stall(Receiver<()>),
    Partial(Receiver<()>),
}


fn read_head(stream: &mut TcpStream) -> io::Result<()> {
    let mut seen = Vec::new();
    let mut chunk = [b' '; CHUNK];
    let mut reads = 0;
    while !seen.windows(HEAD_END.len()).any(|window| window == HEAD_END) && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        seen.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
    }
    Ok(())
}


fn write_reply(stream: &mut TcpStream, status: &str, extra: &str, declared: u64, body: &[u8]) -> io::Result<()> {
    stream.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {declared}\r\nConnection: close\r\n\r\n").as_bytes())?;
    stream.write_all(body)
}


fn run(mut stream: TcpStream, script: Script) -> io::Result<()> {
    read_head(&mut stream)?;
    match script {
        Script::Reply {
            status,
            extra,
            declared,
            body,
        } => write_reply(&mut stream, status, extra, declared, &body),
        Script::Endless => {
            write_reply(&mut stream, "200 OK", "", HUGE_LENGTH, &[])?;
            let block = vec![b'x'; CHUNK];
            (0..ENDLESS_CHUNKS)
                .try_for_each(|_chunk| stream.write_all(&block))
                .or_else(|error| match error.kind() {
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => Ok(()),
                    _ => Err(error),
                })
        }
        Script::Stall(release) => release.recv_timeout(BOUND).map_err(io::Error::other),
        Script::Partial(release) => {
            write_reply(&mut stream, "200 OK", "", DECLARED as u64, &[b'y'; PARTIAL_BYTES])?;
            release.recv_timeout(BOUND).map_err(io::Error::other)
        }
    }
}


struct Served {
    url: String,
    handle: JoinHandle<io::Result<()>>,
}


fn serve(script: Script) -> Result<Served, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://127.0.0.1:{}/bucket/", listener.local_addr()?.port());
    let handle = spawn(move || {
        let stream = accept_bounded(&listener)?;
        run(stream, script)
    });
    Ok(Served { url, handle })
}


fn request(url: &str, max_response: u64, timeout: Duration) -> HttpRequest {
    HttpRequest {
        url: url.to_owned(),
        max_response,
        ca_file: None,
        timeout,
    }
}


fn ok_script(body: Vec<u8>) -> Script {
    let declared = body.len() as u64;
    Script::Reply {
        status: "200 OK",
        extra: "",
        declared,
        body,
    }
}


#[test]
fn a_body_within_the_cap_is_returned() -> Result<(), Box<dyn Error>> {
    let Served { url, handle: server } = serve(ok_script(b"hello".to_vec()))?;
    let response = send(&request(&url, CAP, LONG_TIMEOUT))?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!((response.status, response.body), (STATUS_OK, b"hello".to_vec()));
    Ok(())
}


#[test]
fn a_huge_declared_length_stops_at_the_cap() -> Result<(), Box<dyn Error>> {
    let Served { url, handle: server } = serve(Script::Reply {
        status: "200 OK",
        extra: "",
        declared: HUGE_LENGTH,
        body: vec![b'z'; BODY_BYTES],
    })?;
    let response = send(&request(&url, CAP, LONG_TIMEOUT))?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(response.body.len() as u64, CAP);
    Ok(())
}


#[test]
fn an_endless_body_stops_at_the_cap() -> Result<(), Box<dyn Error>> {
    let Served { url, handle: server } = serve(Script::Endless)?;
    let response = send(&request(&url, CAP, LONG_TIMEOUT))?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(response.body.len() as u64, CAP);
    Ok(())
}


#[test]
fn a_redirect_is_returned_and_never_followed() -> Result<(), Box<dyn Error>> {
    let Served { url, handle: server } = serve(Script::Reply {
        status: "302 Found",
        extra: "Location: http://127.0.0.1:1/elsewhere\r\n",
        declared: 0,
        body: Vec::new(),
    })?;
    let response = send(&request(&url, CAP, LONG_TIMEOUT))?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(response.status, STATUS_REDIRECT);
    Ok(())
}


#[test]
fn an_error_status_is_returned_with_its_body() -> Result<(), Box<dyn Error>> {
    let Served { url, handle: server } = serve(Script::Reply {
        status: "403 Forbidden",
        extra: "",
        declared: MARKER_BYTES,
        body: b"marker".to_vec(),
    })?;
    let response = send(&request(&url, CAP, LONG_TIMEOUT))?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(response.status, STATUS_FORBIDDEN);
    Ok(())
}


#[test]
fn a_server_that_never_answers_hits_the_deadline() -> Result<(), Box<dyn Error>> {
    let (release, hold) = channel();
    let Served { url, handle: server } = serve(Script::Stall(hold))?;
    let outcome = send(&request(&url, CAP, SHORT_TIMEOUT));
    release.send(())?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(outcome, Err(HttpFailure(HttpClass::Timeout)));
    Ok(())
}


#[test]
fn a_body_that_stalls_is_cut_by_the_same_deadline() -> Result<(), Box<dyn Error>> {
    let (release, hold) = channel();
    let Served { url, handle: server } = serve(Script::Partial(hold))?;
    let outcome = send(&request(&url, DECLARED as u64, SHORT_TIMEOUT));
    release.send(())?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(outcome, Err(HttpFailure(HttpClass::Timeout)));
    Ok(())
}


#[test]
fn a_refused_connection_keeps_only_its_kind() -> Result<(), Box<dyn Error>> {
    let reserved = TcpSocket::new_v4()?;
    reserved.bind("127.0.0.1:0".parse()?)?;
    let url = format!("http://127.0.0.1:{}/", reserved.local_addr()?.port());
    let outcome = send(&request(&url, CAP, LONG_TIMEOUT));
    drop(reserved);
    assert_eq!(outcome, Err(HttpFailure(HttpClass::Io(ErrorKind::ConnectionRefused))));
    Ok(())
}


#[test]
fn another_failure_is_other() -> Result<(), Box<dyn Error>> {
    assert_eq!(send(&request("not a url", CAP, LONG_TIMEOUT)), Err(HttpFailure(HttpClass::Other)));
    assert_eq!(classify(ureq::Error::HostNotFound), HttpFailure(HttpClass::Other));
    assert_eq!(read_class(&io::Error::from(ErrorKind::TimedOut)), HttpFailure(HttpClass::Timeout));
    assert_eq!(
        read_class(&io::Error::from(ErrorKind::BrokenPipe)),
        HttpFailure(HttpClass::Io(ErrorKind::BrokenPipe))
    );
    let wrapped = io::Error::other(ureq::Error::Timeout(ureq::Timeout::Global));
    assert_eq!(read_class(&wrapped), HttpFailure(HttpClass::Timeout));
    let other_wrapped = io::Error::other(ureq::Error::HostNotFound);
    assert_eq!(read_class(&other_wrapped), HttpFailure(HttpClass::Io(ErrorKind::Other)));
    assert_eq!(ca_failure("anything"), HttpFailure(HttpClass::Ca));
    Ok(())
}


#[test]
fn a_plain_http_endpoint_off_loopback_is_refused_by_the_agent() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        send(&request("http://192.0.2.1/", CAP, SHORT_TIMEOUT)),
        Err(HttpFailure(HttpClass::Other))
    );
    Ok(())
}


#[test]
fn a_ca_file_is_read_for_the_request_and_refused_when_unusable() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let good = dir.path().join("ca.pem");
    fs::write(&good, generate_simple_self_signed(vec!["localhost".to_owned()])?.cert.pem())?;
    let Served { url, handle: server } = serve(ok_script(b"hello".to_vec()))?;
    let mut with_ca = request(&url, CAP, LONG_TIMEOUT);
    with_ca.ca_file = Some(good);
    assert_eq!(send(&with_ca)?.body, b"hello".to_vec());
    server.join().map_err(|_| "server thread panicked")??;
    let garbage = dir.path().join("garbage.pem");
    fs::write(&garbage, "not a certificate")?;
    let huge = dir.path().join("huge.pem");
    fs::write(&huge, vec![b'a'; usize::try_from(MAX_CA_BYTES)? + 1])?;
    [garbage, huge, dir.path().join("missing.pem")].into_iter().try_for_each(|path| {
        let mut bad = request("http://127.0.0.1:1/", CAP, LONG_TIMEOUT);
        bad.ca_file = Some(path);
        assert_eq!(agent_for_request(&bad).err(), Some(HttpFailure(HttpClass::Ca)));
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

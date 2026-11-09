use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::ReloadEngine;
use siem_ingest::clickhouse::clickhouse_sink;
use siem_ingest::model::Document;
use siem_ingest::settings::{open_settings, IngestSettings};
use siem_ingest::types::SinkFn;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


const EVENT: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event"},"tenant":"evil"}"#;


const HEADER_END: &str = "\r\n\r\n";


const ZERO: u8 = 0;


const CHUNK: usize = 1024;


const STALL_TIMEOUT_MS: u64 = 100;


const LONG_TIMEOUT_MS: u64 = 5000;


const MAX_READS: usize = 1000;


const TRACE_PASSWORD: &str = "TRACEPW-5b2e8d40";


const SECRET_ROW: &str = "password=hunter2";


pub struct Reply {
    pub status: &'static str,
    pub headers: &'static str,
    pub body: &'static str,
}


pub struct Rig {
    pub dir: TempDir,
    pub sink: Box<SinkFn>,
    pub port: u16,
    pub listener: Option<TcpListener>,
}


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or_default());
        let text = String::from_utf8_lossy(&received).into_owned();
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


fn serve(listener: TcpListener, reply: Reply) -> JoinHandle<io::Result<String>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_request(&mut stream)?;
        let response = format!(
            "HTTP/1.1 {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            reply.status,
            reply.headers,
            reply.body.len(),
            reply.body
        );
        stream.write_all(response.as_bytes())?;
        Ok(request)
    })
}


fn stall(listener: TcpListener, release: Receiver<()>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        read_request(&mut stream)?;
        release.recv().map_err(io::Error::other)
    })
}


fn rig(timeout_ms: u64, bind: bool) -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), "s3cret\n")?;
    let yaml = format!(
        "clickhouse_url: \"http://127.0.0.1:{port}\"\nclickhouse_password_file: \"{}\"\ninsert_timeout_ms: {timeout_ms}\n",
        dir.path().join("password").display()
    );
    fs::write(dir.path().join("ingest.yaml"), yaml)?;
    let log = genesis_log(io::sink());
    let engine: ReloadEngine<IngestSettings> = open_settings(
        dir.path().join("ingest.yaml"),
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
    )?;
    Ok(Rig {
        dir,
        sink: clickhouse_sink(Arc::new(engine)),
        port,
        listener: bind.then_some(listener),
    })
}


fn document(text: &str) -> Document {
    Document {
        payload: text.as_bytes().to_vec(),
        timestamp: OffsetDateTime::UNIX_EPOCH,
    }
}


fn joined(handle: JoinHandle<io::Result<String>>) -> Result<String, Box<dyn Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn failure_text(reply: Reply) -> Result<String, Box<dyn Error>> {
    let mut rig = rig(LONG_TIMEOUT_MS, true)?;
    let server = serve(rig.listener.take().ok_or("no listener")?, reply);
    let outcome = (rig.sink)("tenant-a", &[document(EVENT)]);
    joined(server)?;
    Ok(outcome.err().ok_or("the insert should have failed")?.to_string())
}


#[test]
fn insert_sends_the_rows_with_the_tenant_from_the_subject() -> Result<(), Box<dyn Error>> {
    let mut rig = rig(LONG_TIMEOUT_MS, true)?;
    let server = serve(
        rig.listener.take().ok_or("no listener")?,
        Reply {
            status: "200 OK",
            headers: "",
            body: "",
        },
    );
    (rig.sink)("tenant-a", &[document(EVENT)]).map_err(|error| error.to_string())?;
    let request = joined(server)?;
    assert!(request.starts_with("POST /?query=INSERT"), "{request}");
    assert!(request.contains("database=ostyr"));
    assert!(request.contains("x-clickhouse-user: ostyr_ingest"));
    assert!(request.contains("x-clickhouse-key: s3cret"));
    assert!(request.contains(r#""tenant":"tenant-a""#));
    assert!(!request.contains("evil"));
    assert!(request.contains(r#""event.kind":"event""#));
    assert!(rig.dir.path().exists());
    Ok(())
}


#[test]
fn server_errors_map_to_fixed_text_without_the_row() -> Result<(), Box<dyn Error>> {
    let parse = failure_text(Reply {
        status: "400 Bad Request",
        headers: "X-ClickHouse-Exception-Code: 27\r\n",
        body: SECRET_ROW,
    })?;
    assert_eq!(parse, "ClickHouse insert failed: ParseError");
    let denied = failure_text(Reply {
        status: "403 Forbidden",
        headers: "",
        body: SECRET_ROW,
    })?;
    assert_eq!(denied, "ClickHouse insert failed: Unauthorized");
    let down = failure_text(Reply {
        status: "503 Service Unavailable",
        headers: "",
        body: SECRET_ROW,
    })?;
    assert_eq!(down, "ClickHouse insert failed: Unavailable");
    let slow = failure_text(Reply {
        status: "504 Gateway Timeout",
        headers: "",
        body: SECRET_ROW,
    })?;
    assert_eq!(slow, "ClickHouse insert failed: Timeout");
    let missing = failure_text(Reply {
        status: "404 Not Found",
        headers: "",
        body: SECRET_ROW,
    })?;
    assert_eq!(missing, "ClickHouse insert failed: Rejected");
    assert!(!format!("{parse}{denied}{down}{slow}{missing}").contains("hunter2"));
    Ok(())
}


#[test]
fn a_redirect_is_rejected_and_never_followed() -> Result<(), Box<dyn Error>> {
    let mut rig = rig(LONG_TIMEOUT_MS, true)?;
    let target = TcpListener::bind("127.0.0.1:0")?;
    target.set_nonblocking(true)?;
    let location: &'static str = Box::leak(format!("Location: http://127.0.0.1:{}/\r\n", target.local_addr()?.port()).into_boxed_str());
    let server = serve(
        rig.listener.take().ok_or("no listener")?,
        Reply {
            status: "302 Found",
            headers: location,
            body: "",
        },
    );
    let outcome = (rig.sink)("tenant-a", &[document(EVENT)]);
    joined(server)?;
    assert_eq!(outcome.err().ok_or("should fail")?.to_string(), "ClickHouse insert failed: Rejected");
    assert_eq!(target.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    Ok(())
}


#[test]
fn a_closed_port_is_unavailable() -> Result<(), Box<dyn Error>> {
    let rig = rig(LONG_TIMEOUT_MS, false)?;
    let outcome = (rig.sink)("tenant-a", &[document(EVENT)]);
    assert_eq!(outcome.err().ok_or("should fail")?.to_string(), "ClickHouse insert failed: Unavailable");
    assert!(rig.port > 0);
    Ok(())
}


#[test]
fn a_stalled_insert_ends_at_the_request_deadline() -> Result<(), Box<dyn Error>> {
    let mut rig = rig(STALL_TIMEOUT_MS, true)?;
    let (release, held) = channel();
    let server = stall(rig.listener.take().ok_or("no listener")?, held);
    let outcome = (rig.sink)("tenant-a", &[document(EVENT)]);
    release.send(())?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(outcome.err().ok_or("should fail")?.to_string(), "ClickHouse insert failed: Timeout");
    Ok(())
}


#[test]
fn a_missing_password_file_fails_before_any_request() -> Result<(), Box<dyn Error>> {
    let rig = rig(STALL_TIMEOUT_MS, false)?;
    fs::remove_file(rig.dir.path().join("password"))?;
    let outcome = (rig.sink)("tenant-a", &[document(EVENT)]);
    assert_eq!(
        outcome.err().ok_or("should fail")?.to_string(),
        "the ClickHouse password file could not be read"
    );
    Ok(())
}


#[test]
fn an_unrenderable_document_is_a_parse_error() -> Result<(), Box<dyn Error>> {
    let rig = rig(STALL_TIMEOUT_MS, false)?;
    let outcome = (rig.sink)("tenant-a", &[document("{")]);
    assert_eq!(outcome.err().ok_or("should fail")?.to_string(), "ClickHouse insert failed: ParseError");
    Ok(())
}


#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn no_log_record_carries_the_server_body_or_the_row() -> Result<(), Box<dyn Error>> {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    failure_text(Reply {
        status: "400 Bad Request",
        headers: "X-ClickHouse-Exception-Code: 27\r\n",
        body: SECRET_ROW,
    })?;
    let rig = rig(STALL_TIMEOUT_MS, false)?;
    (rig.sink)("tenant-a", &[document("{")]).err().ok_or("should fail")?;
    let mut sent = self::rig(LONG_TIMEOUT_MS, true)?;
    fs::write(sent.dir.path().join("password"), TRACE_PASSWORD)?;
    let server = serve(
        sent.listener.take().ok_or("no listener")?,
        Reply {
            status: "200 OK",
            headers: "",
            body: "",
        },
    );
    (sent.sink)("tenant-a", &[document(EVENT)]).map_err(|error| error.to_string())?;
    assert!(joined(server)?.contains(TRACE_PASSWORD));
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("could not be rendered"), "{logged}");
    assert!(!logged.contains("hunter2"));
    assert!(!logged.contains("s3cret"));
    assert!(!logged.contains(TRACE_PASSWORD));
    Ok(())
}

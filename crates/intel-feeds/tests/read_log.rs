#[path = "common/types.rs"]
mod types;


use intel_feeds::config::ClickhouseConfig;
use intel_feeds::read::read_iocs;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const PASSWORD: &str = "READPW-77c1d9e2";


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const ZERO: u8 = 0;


const DICTIONARY_PORT: u16 = 9440;


const TIMEOUT_MS: u64 = 120_000;


const ROW: &str = r#"{"ioc_type":"domain","value":"secretvalue.example","feed":"f","feed_version":"v1","confidence":70,"tlp":"green","first_seen":"2026-11-03 00:00:00","last_seen":"2026-11-03 00:00:00","expires_at":"2026-12-03 00:00:00"}"#;


fn answer(listener: TcpListener, status: &'static str, body: &'static str) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        let (mut stream, _): (TcpStream, _) = listener.accept()?;
        let mut received = Vec::new();
        let mut chunk = [ZERO; CHUNK];
        let mut reads = 0;
        while !String::from_utf8_lossy(&received).contains(HEADER_END) && reads < CHUNK {
            reads += 1;
            let count = stream.read(&mut chunk)?;
            received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        }
        stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n{body}\n").as_bytes())
    })
}


#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);


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
fn a_trace_subscriber_never_sees_the_key_or_a_value() -> TestResult {
    tracing_log::LogTracer::init()?;
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    fs::write(dir.path().join("password"), PASSWORD)?;
    let config = ClickhouseConfig {
        url: format!("http://127.0.0.1:{}", listener.local_addr()?.port()),
        user: "ostyr".to_owned(),
        password_file: dir.path().join("password"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "iocs".to_owned(),
        dictionary: "ioc_trie".to_owned(),
        dictionary_user: "ostyr_dict".to_owned(),
        dictionary_port: DICTIONARY_PORT,
        timeout_ms: TIMEOUT_MS,
        tenant: "tenant-a".to_owned(),
    };
    let ok = answer(listener.try_clone()?, "200 OK", ROW);
    let mut out = Vec::new();
    read_iocs(&config, NOW, &mut out)?;
    ok.join().map_err(|_| "server thread panicked")??;
    let failing = answer(listener.try_clone()?, "500 Internal Server Error", "");
    assert!(read_iocs(&config, NOW, &mut out).is_err());
    failing.join().map_err(|_| "server thread panicked")??;
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("IOC read done"), "{logged}");
    assert!(logged.contains("IOC read failed"), "{logged}");
    assert!(logged.contains("ureq"), "{logged}");
    assert!(!logged.contains(PASSWORD));
    assert!(!logged.contains("secretvalue"));
    Ok(())
}

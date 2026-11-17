use detection::logging::service_subscriber;
use detection::run::run_service;
use detection::store::file_commit;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;


const MARKER: &str = "MARKERERR";


const ESCAPE: char = '\u{1b}';


const PROBE_BYTES: usize = 2_000_000;


const LOG_BYTES_BOUND: usize = 4096;


const SERVED_CONNECTIONS: usize = 1;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const RULE: &str = "title: Whoami
id: whoami
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
";


#[derive(Clone)]
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
fn a_hostile_nats_server_leaves_no_peer_text_in_the_service_log() -> Result<(), Box<dyn Error + Send + Sync>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    tracing::subscriber::set_global_default(service_subscriber(move || writer.clone(), Some("trace"))?)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let served = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&served);
    let line = format!("-ERR '{MARKER}{ESCAPE}[31m{}\r\n", "B".repeat(PROBE_BYTES)).into_bytes();
    let server = std::thread::spawn(move || -> io::Result<()> {
        (0..SERVED_CONNECTIONS).try_for_each(|_| {
            let (mut stream, _) = listener.accept()?;
            stream.write_all(&line)?;
            flag.store(true, Ordering::SeqCst);
            Ok(())
        })
    });
    let dir = tempdir()?;
    let base = dir.path().display();
    fs::write(dir.path().join("mapping.yaml"), MAPPING)?;
    fs::write(dir.path().join("rules.yaml"), RULE)?;
    let path = dir.path().join("detection.yaml");
    fs::write(
        &path,
        format!(
            "audit_file: {base}/audit.log\ncheckpoint_dir: {base}/checkpoints\nalerts_file: {base}/alerts.jsonl\nmapping_file: {base}/mapping.yaml\nrule_files:\n  - {base}/rules.yaml\ningest:\n  nats_url: \"nats://127.0.0.1:{port}\"\n  nats_fetch_deadline_ms: 200\n  nats_request_timeout_ms: 5000\n  max_batch_messages: 1\n  retry_attempts: 1\n  nats_consumer: detection\n"
        ),
    )?;
    let stop = Arc::clone(&served);
    run_service(&path, Box::new(move || stop.load(Ordering::SeqCst)), file_commit)?;
    server.join().map_err(|_| "server panicked")??;
    let logs = String::from_utf8(captured.lock().map_err(|poisoned| poisoned.to_string())?.clone())?;
    assert!(!logs.contains(MARKER) && !logs.contains(ESCAPE) && !logs.contains("u{1b}"), "{logs}");
    assert!(logs.len() < LOG_BYTES_BOUND, "{} log bytes", logs.len());
    Ok(())
}

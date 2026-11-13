use crate::common::types::TestResult;
use crate::memory_support::{high_water_kib, report, reset_high_water, NOW, TENANT};
use crate::worst_build::{build_request, Shape};
use std::fs::write;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::tempdir;
use traces_ingest::model::Limits;
use traces_ingest::run::run_insert;
use traces_ingest::sampling::Sampling;


const HEADER_END: &[u8] = b"\r\n\r\n";


const CHUNK: usize = 65_536;


const MAX_READS: usize = 10_000_000;


const MAX_CONNECTIONS: usize = 100_000;


const ZERO: u8 = 0;


const TIMEOUT_MS: u64 = 300_000;


const SERVICE_FILL: u8 = b'"';


const ATTRIBUTES: usize = 3;


const EVENTS: usize = 3;


const LINKS: usize = 3;


struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<io::Result<usize>>,
}


fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .to_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length: ").and_then(|value| value.trim().parse::<usize>().ok()))
        .unwrap_or(0)
}


fn drain(stream: &mut TcpStream) -> io::Result<()> {
    let mut head = Vec::new();
    let mut chunk = vec![ZERO; CHUNK];
    let mut remaining: Option<usize> = None;
    let mut reads = 0;
    while remaining.is_none_or(|left| left > 0) && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        remaining = match remaining {
            None => {
                head.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
                head.windows(HEADER_END.len())
                    .position(|window| window == HEADER_END)
                    .map(|end| content_length(head.get(..end).unwrap_or(&[])).saturating_sub(head.len() - end - HEADER_END.len()))
            }
            Some(left) => Some(left.saturating_sub(count)),
        };
        remaining = if count == 0 { Some(0) } else { remaining };
    }
    Ok(())
}


fn start(listener: TcpListener, fail_at: Option<usize>, stop: Arc<AtomicBool>) -> JoinHandle<io::Result<usize>> {
    spawn(move || {
        let mut handled = 0;
        while !stop.load(Ordering::SeqCst) && handled < MAX_CONNECTIONS {
            let (mut stream, _) = listener.accept()?;
            if !stop.load(Ordering::SeqCst) {
                drain(&mut stream)?;
                let status = if fail_at == Some(handled) {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
                handled += 1;
            }
        }
        Ok(handled)
    })
}


fn serve(fail_at: Option<usize>) -> io::Result<Server> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let handle = start(listener, fail_at, Arc::clone(&stop));
    Ok(Server { port, stop, handle })
}


fn finish(server: Server) -> Result<usize, Box<dyn std::error::Error>> {
    server.stop.store(true, Ordering::SeqCst);
    TcpStream::connect(("127.0.0.1", server.port))?;
    Ok(server.handle.join().map_err(|_| "stand-in thread panicked")??)
}


fn limits_section(limits: &Limits) -> String {
    format!(
        "limits:\n  max_request_bytes: {}\n  max_resource_spans: {}\n  max_spans: {}\n  max_total_attributes: {}\n  max_events_total: {}\n  \
max_links_total: {}\n  max_value_elements_total: {}\n  max_entity_refs_total: {}\n  max_entity_keys_total: {}\n  max_attributes_per_span: {}\n  \
max_events_per_span: {}\n  max_links_per_span: {}\n  max_name_bytes: {}\n  max_attribute_key_bytes: {}\n  max_attribute_value_bytes: {}\n  \
max_status_message_bytes: {}\n  max_future_skew_seconds: {}\n  max_batch_rows: {}\n  max_batch_bytes: {}\n  retention_seconds: {}\n",
        limits.max_request_bytes,
        limits.max_resource_spans,
        limits.max_spans,
        limits.max_total_attributes,
        limits.max_events_total,
        limits.max_links_total,
        limits.max_value_elements_total,
        limits.max_entity_refs_total,
        limits.max_entity_keys_total,
        limits.max_attributes_per_span,
        limits.max_events_per_span,
        limits.max_links_per_span,
        limits.max_name_bytes,
        limits.max_attribute_key_bytes,
        limits.max_attribute_value_bytes,
        limits.max_status_message_bytes,
        limits.max_future_skew_seconds,
        limits.max_batch_rows,
        limits.max_batch_bytes,
        limits.retention_seconds
    )
}


pub fn check_end_to_end(limits: &Limits, budget_kib: u64, fail_at: Option<usize>) -> TestResult {
    let dir = tempdir()?;
    let server = serve(fail_at)?;
    write(dir.path().join("password"), "pw\n")?;
    let settings = dir.path().join("settings.yaml");
    write(
        &settings,
        format!(
            "url: http://127.0.0.1:{}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\ntimeout_ms: {TIMEOUT_MS}\n{}",
            server.port,
            dir.path().join("password").display(),
            limits_section(limits)
        ),
    )?;
    let shape = Shape {
        attributes: ATTRIBUTES,
        events: EVENTS,
        links: LINKS,
        inner: 0,
        fill: SERVICE_FILL,
        timed: true,
    };
    let bytes = build_request(limits, shape);
    reset_high_water()?;
    let before = high_water_kib()?;
    let run = run_insert(&settings, &bytes, TENANT, &Sampling::default(), NOW, &|| Duration::ZERO)?;
    let growth = high_water_kib()?.saturating_sub(before);
    let handled = finish(server)?;
    report(&format!(
        "end to end: {} bytes, growth {growth} KiB, rows {}, planned {}, sent {}, failed {:?}, server handled {handled}",
        bytes.len(),
        run.rows,
        run.batches_planned,
        run.batches_sent,
        run.failed_batch
    ))?;
    assert!(run.refusal.is_none());
    assert!(run.refused.is_empty());
    assert!(run.batches_planned > 1);
    assert_eq!(run.failed_batch, fail_at);
    assert_eq!(handled, run.batches_sent + usize::from(fail_at.is_some()));
    assert!(growth < budget_kib, "{growth} KiB");
    Ok(())
}

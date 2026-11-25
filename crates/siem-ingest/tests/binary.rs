mod nats_stub;
#[path = "common/private.rs"]
mod private;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_audit::tenant::AUDIT_TENANT;
use core_config::reload::{reload, ReloadOutcome};
use nats_stub::{kill_connections, start_stub, wait_until, Queued, Stub};
use private::write_private;
use siem_ingest::error::ServeError;
use siem_ingest::model::{Ended, LoopReport};
use siem_ingest::serve::{exit_code, interrupt_flag, run, run_from, start, write_line, EXIT_CYCLE_CAP, EXIT_FAILURE};
use siem_ingest::settings::{load_settings, open_settings};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;
use tempfile::{tempdir, TempDir};


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-siem-ingest");


const EVENT: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event"}}"#;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const POLLS: usize = 3000;


const POLL_MS: u64 = 10;


const FETCH_MS: u64 = 200;


const REQUEST_MS: u64 = 20_000;


const PING_MS: u64 = 1000;


const PAIR: usize = 2;


const ZERO: u8 = 0;


const CAP: u64 = 2;


const RELOADED_AGE: u32 = 2;


const MAX_READS: usize = 1000;


pub struct Lab {
    pub dir: TempDir,
    pub stub: Stub,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub settings: PathBuf,
    pub audit: PathBuf,
}


fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        let text = String::from_utf8_lossy(&received).into_owned();
        expected = text.find(HEADER_END).map_or(usize::MAX, |end| {
            let length = text
                .lines()
                .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length: ").map(str::to_owned))
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


fn answer(mut stream: TcpStream, requests: &Arc<Mutex<Vec<String>>>) -> std::io::Result<()> {
    let request = read_request(&mut stream)?;
    requests.lock().map_err(|_| std::io::Error::other("poisoned"))?.push(request);
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}


fn fake_clickhouse(requests: &Arc<Mutex<Vec<String>>>) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let shared = Arc::clone(requests);
    spawn(move || {
        listener.incoming().for_each(|accepted| {
            let outcome = accepted.and_then(|stream| answer(stream, &shared));
            if let Err(error) = outcome {
                tracing::debug!(%error, "fake ClickHouse connection ended");
            }
        });
    });
    Ok(port)
}


fn queued(subject: &str) -> Queued {
    Queued {
        subject: subject.to_owned(),
        payload: EVENT.as_bytes().to_vec(),
        extra_headers: 0,
        repeated_values: 0,
        message_ids: Vec::new(),
    }
}


fn settings_text(nats_port: u16, clickhouse_port: u16, dir: &Path, age: u32, audit: Option<&Path>) -> String {
    let audit_line = audit.map_or_else(String::new, |path| format!("audit_file: \"{}\"\n", path.display()));
    format!(
        "nats_url: \"nats://127.0.0.1:{nats_port}\"\nnats_fetch_deadline_ms: {FETCH_MS}\nnats_request_timeout_ms: {REQUEST_MS}\n\
         nats_ping_interval_ms: {PING_MS}\nclickhouse_url: \"http://127.0.0.1:{clickhouse_port}\"\n\
         clickhouse_password_file: \"{}\"\nmax_batch_messages: 1\nmax_batch_age_seconds: {age}\n{audit_line}",
        dir.join("password").display()
    )
}


fn lab(events: &[&str]) -> Result<Lab, Box<dyn Error + Send + Sync>> {
    let requests: Arc<Mutex<Vec<String>>> = Arc::default();
    let clickhouse_port = fake_clickhouse(&requests)?;
    let subjects: Vec<String> = events.iter().map(|subject| (*subject).to_owned()).collect();
    let stub = start_stub(None, move |state| {
        subjects.iter().for_each(|subject| state.queue.push_back(queued(subject)));
    })?;
    let dir = tempdir()?;
    write_private(dir.path().join("password"), "s3cret\n")?;
    let audit = dir.path().join("audit.log");
    let settings = dir.path().join("ingest.yaml");
    fs::write(&settings, settings_text(stub.port, clickhouse_port, dir.path(), 1, Some(&audit)))?;
    Ok(Lab {
        dir,
        stub,
        requests,
        settings,
        audit,
    })
}


fn run_to_end(arguments: &[&Path], rust_log: Option<&str>) -> Result<Output, Box<dyn Error + Send + Sync>> {
    let mut command = Command::new(PROGRAM);
    command.args(arguments).stdin(Stdio::null());
    rust_log.iter().for_each(|directives| {
        command.env("RUST_LOG", directives);
    });
    Ok(command.output()?)
}


fn refused_with(output: &Output, marker: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let text = String::from_utf8(output.stderr.clone())?;
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains(marker), "{text}");
    assert!(output.stdout.is_empty());
    Ok(())
}


fn signal(child: &Child, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let status = Command::new("kill").arg(format!("-{name}")).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn eventually(check: impl Fn() -> bool) -> Result<(), Box<dyn Error + Send + Sync>> {
    if (0..POLLS).any(|_| {
        check() || {
            sleep(Duration::from_millis(POLL_MS));
            false
        }
    }) {
        Ok(())
    } else {
        Err("the condition was not reached".into())
    }
}


fn spawn_service(settings: &Path) -> Result<Child, Box<dyn Error + Send + Sync>> {
    Ok(Command::new(PROGRAM)
        .arg(settings)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> Result<(), Box<dyn Error + Send + Sync>> {
    refused_with(&run_to_end(&[], None)?, "usage: ostyr-siem-ingest <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")], None)?, "usage: ostyr-siem-ingest")
}


#[test]
fn an_unreadable_settings_file_is_a_named_error() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    refused_with(&run_to_end(&[&missing], None)?, "absent.yaml")
}


#[test]
fn an_invalid_settings_file_is_refused() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let file = dir.path().join("ingest.yaml");
    fs::write(&file, "max_batch_messages: 0\n")?;
    refused_with(&run_to_end(&[&file], None)?, "max_batch_messages")
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused_at_start() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let file = dir.path().join("ingest.yaml");
    fs::write(&file, "max_batch_messages: 1\n")?;
    refused_with(&run_to_end(&[&file], None)?, "audit_file")
}


#[test]
fn a_relative_audit_path_is_refused() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let file = dir.path().join("ingest.yaml");
    fs::write(&file, "audit_file: audit.log\n")?;
    refused_with(&run_to_end(&[&file], None)?, "absolute")
}


#[test]
fn an_unwritable_audit_file_stops_the_start() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let file = dir.path().join("ingest.yaml");
    let audit = dir.path().join("missing-directory").join("audit.log");
    fs::write(&file, format!("audit_file: \"{}\"\n", audit.display()))?;
    refused_with(&run_to_end(&[&file], None)?, "audit log")
}


#[test]
fn an_invalid_log_filter_stops_the_start() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[dir.path()], Some("debug=nonsense"))?, "log filter")
}


#[test]
fn the_service_stores_two_tenants_reloads_on_sighup_and_exits_zero_on_sigterm() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&["events.tenant-a", "events.tenant-b"])?;
    let mut child = spawn_service(&lab.settings)?;
    wait_until(&lab.stub, |state| state.acks.len() >= PAIR)?;
    let stored = lab.requests.lock().map_err(|_| "poisoned")?.join("\n");
    assert!(stored.contains(r#""tenant":"tenant-a""#), "{stored}");
    assert!(stored.contains(r#""tenant":"tenant-b""#), "{stored}");
    let staging = lab.dir.path().join("ingest.staging");
    let clickhouse_port: u16 = stored
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("host: 127.0.0.1:")
                .map(|port| port.trim().to_owned())
        })
        .ok_or("no host header")?
        .parse()?;
    fs::write(
        &staging,
        settings_text(lab.stub.port, clickhouse_port, lab.dir.path(), RELOADED_AGE, Some(&lab.audit)),
    )?;
    fs::rename(&staging, &lab.settings)?;
    signal(&child, "HUP")?;
    eventually(|| fs::read_to_string(&lab.audit).is_ok_and(|text| text.contains("max_batch_age_seconds")))?;
    let audit = fs::read_to_string(&lab.audit)?;
    assert!(audit.contains(&format!(r#""tenant":"{AUDIT_TENANT}""#)), "{audit}");
    signal(&child, "TERM")?;
    let mut out = String::new();
    child.stdout.take().ok_or("no stdout")?.read_to_string(&mut out)?;
    let mut errors = String::new();
    child.stderr.take().ok_or("no stderr")?.read_to_string(&mut errors)?;
    let exit = child.wait()?;
    assert_eq!(exit.code(), Some(0), "{errors}");
    assert!(out.contains("LoopReport"), "{out}");
    assert!(errors.contains("ostyr-siem-ingest serving"), "{errors}");
    assert!(errors.contains("ostyr-siem-ingest stopped"), "{errors}");
    Ok(())
}


#[test]
fn an_interrupt_stops_it_too() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&["events.tenant-a"])?;
    let mut child = spawn_service(&lab.settings)?;
    wait_until(&lab.stub, |state| !state.acks.is_empty())?;
    signal(&child, "INT")?;
    let exit = child.wait()?;
    assert_eq!(exit.code(), Some(0));
    Ok(())
}


fn arguments(lab: &Lab) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    Ok(vec![lab.settings.to_str().ok_or("settings path is not UTF-8")?.to_owned()])
}


#[test]
fn the_loop_returns_the_cycle_cap_outcome_when_the_cap_is_reached() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&["events.tenant-a"])?;
    let ended = run(&arguments(&lab)?, &|| false, CAP)?;
    assert!(matches!(ended, Ended::CycleCap(summary) if summary.cycles == CAP), "{ended:?}");
    assert_eq!(exit_code(&Ok(ended)), EXIT_CYCLE_CAP);
    assert_ne!(EXIT_CYCLE_CAP, 0);
    Ok(())
}


#[test]
fn a_stop_before_the_cap_is_a_clean_stop() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&[])?;
    let ended = run(&arguments(&lab)?, &|| true, CAP)?;
    assert_eq!(ended, Ended::Stopped(LoopReport::default()));
    assert_eq!(exit_code(&Ok(ended)), 0);
    Ok(())
}


#[test]
fn every_start_error_is_the_failure_exit_code() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_eq!(exit_code(&Err(ServeError::Usage)), EXIT_FAILURE);
    assert_eq!(EXIT_FAILURE, 1);
    Ok(())
}


#[test]
fn the_interrupt_flag_is_set_by_sigterm_and_sigint() -> Result<(), Box<dyn Error + Send + Sync>> {
    let flag = interrupt_flag()?;
    assert!(!flag.load(Ordering::SeqCst));
    signal_hook::low_level::raise(signal_hook::consts::SIGTERM)?;
    eventually(|| flag.load(Ordering::SeqCst))?;
    flag.store(false, Ordering::SeqCst);
    signal_hook::low_level::raise(signal_hook::consts::SIGINT)?;
    eventually(|| flag.load(Ordering::SeqCst))
}


#[test]
fn a_second_subscriber_is_refused_by_name() -> Result<(), Box<dyn Error + Send + Sync>> {
    let first = start(&[]);
    assert!(matches!(first, Err(ServeError::Usage)));
    let second = start(&[]);
    assert!(matches!(second, Err(ServeError::Subscriber(_))));
    Ok(())
}


#[test]
fn a_stop_with_the_bus_connections_dropped_is_still_a_clean_exit() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&["events.tenant-a"])?;
    let mut child = spawn_service(&lab.settings)?;
    wait_until(&lab.stub, |state| !state.acks.is_empty())?;
    kill_connections(&lab.stub);
    signal(&child, "TERM")?;
    assert_eq!(child.wait()?.code(), Some(0));
    Ok(())
}


#[test]
fn a_reload_that_changes_the_audit_file_is_refused_and_the_old_settings_stay() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&[])?;
    let log = genesis_log(std::io::sink());
    let engine = open_settings(
        lab.settings.clone(),
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
    )?;
    let text = fs::read_to_string(&lab.settings)?;
    fs::write(&lab.settings, text.replace("audit.log", "other.log"))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("audit_file")),
        "{outcome:?}"
    );
    assert_eq!(load_settings(&lab.settings)?.audit_file, Some(lab.dir.path().join("other.log")));
    assert_eq!(core_config::reload::current_config(&engine).audit_file, Some(lab.audit.clone()));
    Ok(())
}


pub struct Refusing;


impl Write for Refusing {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_failed_output_write_is_logged_and_a_good_one_is_written() -> Result<(), Box<dyn Error + Send + Sync>> {
    write_line(&mut Refusing, "lost");
    let mut kept = Vec::new();
    write_line(&mut kept, "kept");
    assert_eq!(kept, b"kept\n");
    Ok(())
}


#[test]
fn a_stop_that_arrives_as_the_cap_is_reached_is_a_clean_stop() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&[])?;
    let seen = std::sync::atomic::AtomicU64::new(0);
    let stop = move || seen.fetch_add(1, Ordering::SeqCst) > CAP;
    let ended = run(&arguments(&lab)?, &stop, CAP)?;
    assert!(matches!(ended, Ended::Stopped(summary) if summary.cycles == CAP), "{ended:?}");
    assert_eq!(exit_code(&Ok(ended)), 0);
    Ok(())
}


const LONG_CAP: u64 = 1_000_000;


const FIRST_AGE: u32 = 5;


fn run_in_thread(
    settings: PathBuf,
    first: siem_ingest::settings::IngestSettings,
) -> (Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<Result<Ended, ServeError>>) {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&flag);
    let handle = spawn(move || run_from(&settings, first, &move || seen.load(Ordering::SeqCst), LONG_CAP));
    (flag, handle)
}


#[test]
fn the_start_uses_the_settings_it_was_given_as_the_baseline_not_a_second_read() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&[])?;
    let mut first = load_settings(&lab.settings)?;
    first.max_batch_age_seconds = FIRST_AGE;
    let (flag, handle) = run_in_thread(lab.settings.clone(), first);
    wait_until(&lab.stub, |state| !state.connects.is_empty())?;
    let disk_text = fs::read_to_string(&lab.settings)?;
    let staging = lab.dir.path().join("ingest.staging");
    fs::write(&staging, disk_text.replace("max_batch_messages: 1\n", "max_batch_messages: 2\n"))?;
    fs::rename(&staging, &lab.settings)?;
    eventually(|| fs::read_to_string(&lab.audit).is_ok_and(|text| text.contains("max_batch_age_seconds")))?;
    flag.store(true, Ordering::SeqCst);
    handle.join().map_err(|_| "the service thread panicked")??;
    Ok(())
}


#[test]
fn the_audit_path_comes_from_the_given_settings_not_a_second_read() -> Result<(), Box<dyn Error + Send + Sync>> {
    let lab = lab(&[])?;
    let first = load_settings(&lab.settings)?;
    let other = lab.dir.path().join("other.log");
    let disk_text = fs::read_to_string(&lab.settings)?;
    let moved = disk_text.replace("audit.log", "other.log");
    fs::write(&lab.settings, &moved)?;
    let (flag, handle) = run_in_thread(lab.settings.clone(), first);
    wait_until(&lab.stub, |state| !state.connects.is_empty())?;
    fs::write(&lab.settings, moved.replace("max_batch_messages: 1\n", "max_batch_messages: 2\n"))?;
    eventually(|| fs::read_to_string(&lab.audit).is_ok_and(|text| text.contains("denied")))?;
    flag.store(true, Ordering::SeqCst);
    handle.join().map_err(|_| "the service thread panicked")??;
    assert!(!other.exists());
    Ok(())
}

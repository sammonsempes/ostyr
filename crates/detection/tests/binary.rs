#![cfg(unix)]
#[path = "binary_support/types.rs"]
mod binary_types;
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;


use binary_types::{TestError, TestResult};
use detection::serve::{directives_of, exit_of, exit_status, install_logging, service_with, warn_unreadable_directives, Exit, ServeError};
use detection::types::StopFlag;
use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued};
use serde_json::Value;
use std::env::VarError;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tempfile::tempdir;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-detect");


const USAGE: &str = "usage: ostyr-detect <detection.yaml>";


const RELOAD_MARKER: &str = "configuration reloaded";


const EXIT_CYCLE_CAP: u8 = 75;


const INVALID_SIGNAL: i32 = 100_000;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const RULES: &str = "title: Whoami
id: whoami
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
---
title: Whoami seen
id: whoami-seen
correlation:
  type: event_count
  rules:
    - whoami
  timespan: 5m
  condition:
    gte: 1
";


const EVENT: &str = r#"{"@timestamp":"2026-11-10T10:00:00Z","ecs":{"version":"8.11"},"event":{"id":"e1","kind":"event","category":["process"]},"process":{"executable":"/usr/bin/whoami"},"host":{"name":"h1"},"tenant":"evil"}"#;


pub struct Running {
    pub child: Child,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::debug!(%error, "the child had already ended");
        }
    }
}


fn settings_text(dir: &Path, port: u16, audit: &str) -> String {
    let base = dir.display();
    format!(
        "{audit}checkpoint_dir: {base}/checkpoints\nalerts_file: {base}/alerts.jsonl\nmapping_file: {base}/mapping.yaml\nrule_files:\n  - {base}/rules.yaml\ningest:\n  nats_url: \"nats://127.0.0.1:{port}\"\n  nats_fetch_deadline_ms: 100\n  nats_request_timeout_ms: 2000\n  max_batch_messages: 1\n  retry_attempts: 1\n  nats_consumer: detection\n"
    )
}


fn write_files(dir: &Path, port: u16, audit_line: bool) -> Result<PathBuf, TestError> {
    let audit = if audit_line {
        format!("audit_file: {}/audit.log\n", dir.display())
    } else {
        String::new()
    };
    fs::write(dir.join("mapping.yaml"), MAPPING)?;
    fs::write(dir.join("rules.yaml"), RULES)?;
    let path = dir.join("detection.yaml");
    fs::write(&path, settings_text(dir, port, &audit))?;
    Ok(path)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, TestError> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn spawn_child(settings: &Path) -> Result<(Running, BufReader<ChildStderr>), TestError> {
    let mut child = Command::new(PROGRAM)
        .arg(settings)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    Ok((Running { child }, reader))
}


fn wait_for_line(reader: &mut BufReader<ChildStderr>, marker: &str) -> Result<String, TestError> {
    reader
        .by_ref()
        .lines()
        .find_map(|line| match line {
            Ok(text) if text.contains(marker) => Some(Ok(text)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .ok_or_else(|| format!("the child ended before logging {marker}"))?
        .map_err(TestError::from)
}


fn signal(running: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn finish(mut running: Running, mut reader: BufReader<ChildStderr>) -> TestResult {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = running.child.wait()?;
    assert!(exit.success(), "{exit:?} {rest}");
    Ok(())
}


fn queued_event() -> Queued {
    Queued {
        subject: "events.a".to_owned(),
        payload: EVENT.as_bytes().to_vec(),
        extra_headers: 0,
        repeated_values: 0,
        message_ids: Vec::new(),
    }
}


fn json_lines(path: &Path) -> Result<Vec<Value>, TestError> {
    fs::read_to_string(path)?.lines().map(|line| Ok(serde_json::from_str(line)?)).collect()
}


fn field<'a>(record: &'a Value, name: &str) -> &'a str {
    record.get(name).and_then(Value::as_str).unwrap_or("")
}


#[test]
fn a_missing_or_surplus_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, USAGE)?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, USAGE)
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let invalid = dir.path().join("invalid.yaml");
    fs::write(&invalid, "audit_file: [\n")?;
    refused_with(&run_to_end(&[&invalid])?, "invalid.yaml")
}


#[test]
fn a_settings_file_without_an_audit_file_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let path = write_files(dir.path(), 1, false)?;
    refused_with(&run_to_end(&[&path])?, "audit_file")
}


#[test]
fn an_audit_file_that_cannot_be_opened_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let path = write_files(dir.path(), 1, true)?;
    fs::write(&path, fs::read_to_string(&path)?.replace("audit.log", "absent-directory/audit.log"))?;
    refused_with(&run_to_end(&[&path])?, "audit")
}


#[test]
fn an_invalid_log_directive_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = write_files(dir.path(), 1, true)?;
    let output = Command::new(PROGRAM)
        .arg(&path)
        .env("RUST_LOG", "target=notalevel")
        .stdin(Stdio::null())
        .output()?;
    refused_with(&output, "RUST_LOG")
}


#[test]
fn the_binary_stores_one_alert_under_the_subject_tenant_reloads_on_sighup_and_exits_zero_on_sigint() -> TestResult {
    let dir = tempdir()?;
    let stub = start_stub(None, |state| state.queue.push_back(queued_event()))?;
    let path = write_files(dir.path(), stub.port, true)?;
    let (running, mut reader) = spawn_child(&path)?;
    wait_until(&stub, |state| !state.acks.is_empty())?;
    let alerts = json_lines(&dir.path().join("alerts.jsonl"))?;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts.first().map(|alert| field(alert, "tenant")), Some("a"));
    let letters: Vec<(usize, usize, usize)> = lock(&stub.hub)
        .published
        .iter()
        .map(|letter| (letter.subject.len(), letter.headers.len(), letter.payload.len()))
        .collect();
    assert!(letters.is_empty(), "{letters:?}");
    fs::write(dir.path().join("rules.yaml"), RULES.replace("Whoami seen", "Whoami seen again"))?;
    signal(&running, "-HUP")?;
    wait_for_line(&mut reader, RELOAD_MARKER)?;
    signal(&running, "-INT")?;
    finish(running, reader)?;
    kill_connections(&stub);
    let audit = json_lines(&dir.path().join("audit.log"))?;
    let reloads: Vec<&Value> = audit.iter().filter(|record| field(record, "action") == "config.reload").collect();
    assert!(!reloads.is_empty(), "{audit:?}");
    assert!(audit.iter().all(|record| field(record, "tenant") == "all"), "{audit:?}");
    Ok(())
}


#[test]
fn sigterm_ends_the_loop_with_exit_zero() -> TestResult {
    let dir = tempdir()?;
    let stub = start_stub(None, |_| ())?;
    let path = write_files(dir.path(), stub.port, true)?;
    let (running, reader) = spawn_child(&path)?;
    wait_until(&stub, |state| !state.pulls.is_empty())?;
    signal(&running, "-TERM")?;
    finish(running, reader)?;
    kill_connections(&stub);
    assert!(lock(&stub.hub).acks.is_empty());
    Ok(())
}


#[test]
fn the_in_process_helpers_install_one_subscriber_then_name_every_refusal() -> TestResult {
    let refused = service_with(&[String::from("settings.yaml")], &[INVALID_SIGNAL]);
    assert!(matches!(refused, Err(ServeError::Signals(_))), "{refused:?}");
    let again = install_logging(None);
    assert!(matches!(again, Err(ServeError::Subscriber(_))), "{again:?}");
    let raised: StopFlag = Arc::new(AtomicBool::new(true));
    let idle: StopFlag = Arc::new(AtomicBool::new(false));
    assert_eq!(exit_of(&raised), Exit::Stopped);
    assert_eq!(exit_of(&idle), Exit::CycleCap);
    assert_eq!(exit_status(Exit::Stopped), 0);
    assert_eq!(exit_status(Exit::CycleCap), EXIT_CYCLE_CAP);
    let readable: Result<String, VarError> = Ok("warn".to_owned());
    let unreadable: Result<String, VarError> = Err(VarError::NotUnicode(OsString::from("x")));
    let absent: Result<String, VarError> = Err(VarError::NotPresent);
    assert_eq!(directives_of(&readable), Some("warn"));
    assert_eq!(directives_of(&unreadable), None);
    warn_unreadable_directives(&readable);
    warn_unreadable_directives(&unreadable);
    warn_unreadable_directives(&absent);
    Ok(())
}

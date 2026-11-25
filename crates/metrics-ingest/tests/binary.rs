#![cfg(unix)]
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;
mod serve_support;


use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued};
use serde_json::Value;
use serve_support::types::{TestError, TestResult};
use serve_support::{settings_text, write_settings, EVENT};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use tempfile::tempdir;


const TWO: usize = 2;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-metrics-ingest");


const CYCLE_MARKER: &str = "row_refused_timestamp_out_of_range=1";


const RELOAD_MARKER: &str = "configuration reloaded";


const USAGE: &str = "usage: ostyr-metrics-ingest <settings.yaml>";


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


fn queued(ids: &[&str]) -> Queued {
    Queued {
        subject: "events.a".to_owned(),
        payload: EVENT.as_bytes().to_vec(),
        extra_headers: 0,
        repeated_values: 0,
        message_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
    }
}


fn audit_records(audit_file: &Path) -> Result<Vec<Value>, TestError> {
    fs::read_to_string(audit_file)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}


fn field<'a>(record: &'a Value, name: &str) -> &'a str {
    record.get(name).and_then(Value::as_str).unwrap_or("")
}


#[test]
fn a_missing_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, USAGE)
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let invalid = write_settings(dir.path(), "audit_file: [\n")?;
    refused_with(&run_to_end(&[&invalid])?, "metrics.yaml")
}


#[test]
fn a_settings_file_without_an_audit_file_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let file = write_settings(dir.path(), "ingest:\n  nats_consumer: metrics-ingest\n")?;
    refused_with(&run_to_end(&[&file])?, "audit_file")
}


#[test]
fn an_audit_file_that_cannot_be_opened_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("absent-directory").join("audit.log");
    let file = write_settings(dir.path(), &settings_text(1, &audit, ""))?;
    refused_with(&run_to_end(&[&file])?, "cannot open the audit file")
}


#[test]
fn an_invalid_log_directive_is_refused() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let file = write_settings(dir.path(), &settings_text(1, &audit, ""))?;
    let output = Command::new(PROGRAM)
        .arg(&file)
        .env("RUST_LOG", "target=notalevel")
        .stdin(Stdio::null())
        .output()?;
    refused_with(&output, "RUST_LOG")
}


#[test]
fn the_binary_serves_a_round_reloads_on_sighup_and_on_a_file_change_and_exits_cleanly_on_sigint() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let stub = start_stub(None, |state| {
        state.queue.push_back(queued(&["a:agent1:1:0"]));
        state.queue.push_back(queued(&[]));
    })?;
    let real_directory = dir.path().join("real");
    let watched_directory = dir.path().join("watched");
    fs::create_dir(&real_directory)?;
    fs::create_dir(&watched_directory)?;
    let text = settings_text(stub.port, &audit, "");
    let real = write_settings(&real_directory, &text)?;
    let link = watched_directory.join("metrics.yaml");
    symlink(&real, &link)?;
    let (running, mut reader) = spawn_child(&link)?;
    wait_for_line(&mut reader, CYCLE_MARKER)?;
    wait_until(&stub, |state| state.acks.len() >= TWO && !state.published.is_empty())?;
    {
        let state = lock(&stub.hub);
        let letter = state.published.first().ok_or("no dead letter")?;
        assert_eq!(letter.subject, "dead.events.a");
        assert_eq!(letter.payload, EVENT.as_bytes());
        assert!(letter.headers.contains("identity_unusable"), "{}", letter.headers);
    }
    let edited = text.replace("max_batch_messages: 5", "max_batch_messages: 6");
    fs::write(&real, &edited)?;
    signal(&running, "-HUP")?;
    wait_for_line(&mut reader, RELOAD_MARKER)?;
    let replacement: PathBuf = watched_directory.join("replacement.yaml");
    fs::write(&replacement, edited.replace("max_batch_rows: 100", "max_batch_rows: 101"))?;
    fs::rename(&replacement, &link)?;
    wait_for_line(&mut reader, RELOAD_MARKER)?;
    signal(&running, "-INT")?;
    finish(running, reader)?;
    let records = audit_records(&audit)?;
    let reloads: Vec<&Value> = records.iter().filter(|record| field(record, "action") == "config.reload").collect();
    assert_eq!(reloads.len(), TWO, "{records:?}");
    let targets: Vec<&str> = reloads.iter().map(|record| field(record, "target")).collect();
    assert!(targets.first().is_some_and(|target| target.ends_with(" ingest")), "{targets:?}");
    assert!(targets.get(1).is_some_and(|target| target.ends_with(" limits")), "{targets:?}");
    assert!(reloads.iter().all(|record| field(record, "outcome") == "success"), "{records:?}");
    Ok(())
}


#[test]
fn sigterm_ends_the_loop_with_exit_zero() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let stub = start_stub(None, |_| ())?;
    let file = write_settings(dir.path(), &settings_text(stub.port, &audit, ""))?;
    let (running, reader) = spawn_child(&file)?;
    wait_until(&stub, |state| !state.pulls.is_empty())?;
    signal(&running, "-TERM")?;
    finish(running, reader)?;
    kill_connections(&stub);
    Ok(())
}

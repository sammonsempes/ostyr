#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use site::{write_site, Site, MANUAL_ACME};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-grc");


const LINE_GUARD: Duration = Duration::from_secs(120);


const EXIT_POLL: Duration = Duration::from_millis(50);


const EXIT_ATTEMPTS: u32 = 2_400;


struct Running {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::debug!(%error, "child already gone");
        }
        if let Err(error) = self.child.wait() {
            tracing::debug!(%error, "child not reaped");
        }
    }
}


fn start_child(settings_file: &Path) -> Result<Running, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    std::thread::spawn(move || forward(stderr, &sender));
    Ok(Running {
        child,
        lines,
        seen: Vec::new(),
    })
}


fn forward(stderr: std::process::ChildStderr, sender: &Sender<String>) -> Result<(), std::sync::mpsc::SendError<String>> {
    BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .try_for_each(|line| sender.send(line))
}


fn wait_for(running: &mut Running, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let found = std::iter::repeat_with(|| running.lines.recv_timeout(LINE_GUARD))
        .map(|received| received.inspect(|line| running.seen.push(line.clone())))
        .find(|received| received.as_ref().map_or(true, |line| line.contains(marker)));
    found
        .ok_or("no line")?
        .map_err(|error| format!("waiting for {marker:?}: {error}, stderr so far {:?}", running.seen).into())
}


fn signal(running: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn finish(running: &mut Running) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let exited = (0..EXIT_ATTEMPTS).find_map(|_attempt| match running.child.try_wait() {
        Ok(Some(status)) => Some(Ok(status)),
        Ok(None) => {
            std::thread::sleep(EXIT_POLL);
            None
        }
        Err(error) => Some(Err(error)),
    });
    Ok(exited.ok_or("the child never exited")??)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


struct Hold {
    arrived: Receiver<()>,
    release: Sender<()>,
}


fn accepting(store_rows: Vec<Vec<String>>, hold_on: Option<&'static str>) -> (Handler, Hold) {
    let (arrived_tx, arrived) = channel();
    let (release, release_rx) = channel();
    let waiting = Mutex::new(release_rx);
    let held = AtomicBool::new(false);
    let handler: Handler = Arc::new(move |sql: &str| {
        if hold_on.is_some_and(|marker| sql.contains(marker)) && !held.swap(true, Ordering::SeqCst) {
            if let Err(error) = arrived_tx.send(()) {
                tracing::debug!(%error, "nobody waits for the hold");
            }
            if let Err(error) = waiting.lock().unwrap_or_else(PoisonError::into_inner).recv() {
                tracing::debug!(%error, "the hold was never released");
            }
        }
        if sql.contains("grc_report_store") {
            Reply::Rows(store_rows.clone())
        } else if sql.contains("FROM grc_report") {
            Reply::Rows(Vec::new())
        } else {
            Reply::Done
        }
    });
    (handler, Hold { arrived, release })
}


async fn serving(handler: Handler, dir: &Path) -> Result<(Fake, Site), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let started = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let site = write_site(dir, started.port, &pki.ca_pem, "[builtin:nis2]")?;
    Ok((started, site))
}


fn stored_rows() -> Vec<Vec<String>> {
    vec![vec!["stored".to_owned(), "7".to_owned()]]
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-grc <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-grc")
}


#[test]
fn an_unreadable_invalid_or_audit_less_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "tenant: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "service.yaml")?;
    let site = write_site(dir.path(), 1, "", "[builtin:nis2]")?;
    let complete = fs::read_to_string(&site.settings_file)?;
    let without_audit: String = complete
        .lines()
        .filter(|line| !line.starts_with("audit_file"))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&settings_file, without_audit)?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")?;
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", "[builtin:nis2]")?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&site.settings_file]))?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    assert!(site.dir.join("audit.log").exists());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn two_rounds_a_live_manual_edit_refused_files_named_and_sigterm_exits_zero() -> TestResult {
    let dir = tempdir()?;
    let (handler, _hold) = accepting(stored_rows(), None);
    let (_fake, site) = serving(handler, dir.path()).await?;
    fs::write(site.indicators.join("bad.json"), "not json")?;
    let mut running = start_child(&site.settings_file)?;
    let first = tokio::task::block_in_place(|| wait_for(&mut running, "framework round done"))?;
    assert!(first.contains("outcome=\"stored\""), "{first}");
    tokio::task::block_in_place(|| wait_for(&mut running, "grc round done"))?;
    assert!(
        running
            .seen
            .iter()
            .any(|line| line.contains("indicator file refused") && line.contains("bad.json")),
        "{:?}",
        running.seen
    );
    fs::write(&site.manual_file, MANUAL_ACME.replace("ciso", "dpo"))?;
    tokio::task::block_in_place(|| wait_for(&mut running, "configuration reloaded"))?;
    tokio::task::block_in_place(|| wait_for(&mut running, "grc round done"))?;
    signal(&running, "-TERM")?;
    tokio::task::block_in_place(|| wait_for(&mut running, "stopped rounds="))?;
    assert!(tokio::task::block_in_place(|| finish(&mut running))?.success());
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"tenant\":\"all\"") && audit.contains("manual.art21-2-a"), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_and_a_hangup_queued_during_the_first_round_wait_for_it_then_exit_zero() -> TestResult {
    let dir = tempdir()?;
    let (handler, hold) = accepting(stored_rows(), Some("grc_report_store"));
    let (_fake, site) = serving(handler, dir.path()).await?;
    let mut running = start_child(&site.settings_file)?;
    tokio::task::block_in_place(|| hold.arrived.recv_timeout(LINE_GUARD))?;
    signal(&running, "-HUP")?;
    signal(&running, "-TERM")?;
    tokio::task::block_in_place(|| wait_for(&mut running, "reload requested"))?;
    tokio::task::block_in_place(|| wait_for(&mut running, "stop requested"))?;
    signal(&running, "-INT")?;
    tokio::task::block_in_place(|| wait_for(&mut running, "another stop signal ignored"))?;
    hold.release.send(())?;
    let done = tokio::task::block_in_place(|| wait_for(&mut running, "framework round done"))?;
    assert!(done.contains("outcome=\"stored\""), "{done}");
    tokio::task::block_in_place(|| wait_for(&mut running, "hangup received"))?;
    tokio::task::block_in_place(|| wait_for(&mut running, "stopped rounds=1"))?;
    assert!(tokio::task::block_in_place(|| finish(&mut running))?.success());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_during_start_queues_and_the_first_round_still_runs_before_exit() -> TestResult {
    let dir = tempdir()?;
    let (handler, hold) = accepting(stored_rows(), Some("schema_migrations"));
    let (_fake, site) = serving(handler, dir.path()).await?;
    let mut running = start_child(&site.settings_file)?;
    tokio::task::block_in_place(|| hold.arrived.recv_timeout(LINE_GUARD))?;
    signal(&running, "-TERM")?;
    tokio::task::block_in_place(|| wait_for(&mut running, "stop requested"))?;
    hold.release.send(())?;
    tokio::task::block_in_place(|| wait_for(&mut running, "framework round done"))?;
    tokio::task::block_in_place(|| wait_for(&mut running, "stopped rounds=1"))?;
    assert!(tokio::task::block_in_place(|| finish(&mut running))?.success());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_at_its_report_cap_gets_a_loud_named_error_and_nothing_else_changes() -> TestResult {
    let dir = tempdir()?;
    let (handler, _hold) = accepting(vec![vec!["refused".to_owned(), "0".to_owned()]], None);
    let (_fake, site) = serving(handler, dir.path()).await?;
    let mut running = start_child(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for(&mut running, "report cap reached"))?;
    assert!(line.contains("ERROR") && line.contains("framework=\"nis2\""), "{line}");
    let summary = tokio::task::block_in_place(|| wait_for(&mut running, "grc round done"))?;
    assert!(summary.contains("cap_reached=1") && summary.contains("stored=0"), "{summary}");
    signal(&running, "-INT")?;
    assert!(tokio::task::block_in_place(|| finish(&mut running))?.success());
    Ok(())
}

#![cfg(unix)]


#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::signal::{early_signals, reload_on_stream, stop_signals};
use rustix::process::{kill_process, Pid, Signal};
use signal_hook::consts::{SIGHUP, SIGTERM};
use signal_hook::low_level::raise;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;
use wait::wait_until;


#[test]
fn a_sighup_queued_before_the_engine_exists_is_handled_after_it() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let early = early_signals()?;
    raise(SIGHUP)?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    replace_file(&path, &module_text("120d"))?;
    let guard = reload_on_stream(early.reload, Arc::clone(&engine));
    assert!(wait_until(|| retention(&engine).as_deref() == Some("120d")));
    assert!(stop_signals(guard));
    assert_eq!(entries(&recorded)?.len(), 1);
    Ok(())
}


const CHILD_ENV: &str = "CORE_CONFIG_EARLY_CHILD";


const READY: &str = "early-signals-ready";


const BANNER_LINES: usize = 20;


pub struct ChildGuard(pub Child);


impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            tracing::debug!(%error, "child already gone");
        }
        if let Err(error) = self.0.wait() {
            tracing::debug!(%error, "child not reaped");
        }
    }
}


#[test]
fn sigterm_keeps_its_default_action_after_early_signals() -> TestResult {
    let mut guard = ChildGuard(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "child_waits_after_early_signals", "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = guard.0.stdout.take().ok_or_else(|| io::Error::other("no stdout"))?;
    assert!(BufReader::new(stdout)
        .lines()
        .take(BANNER_LINES)
        .any(|line| line.is_ok_and(|text| text == READY)));
    let pid = Pid::from_child(&guard.0);
    kill_process(pid, Signal::HUP)?;
    kill_process(pid, Signal::TERM)?;
    let status = guard.0.wait()?;
    assert_eq!(status.signal(), Some(SIGTERM));
    Ok(())
}


#[test]
fn child_waits_after_early_signals() -> TestResult {
    let active = std::env::var(CHILD_ENV).is_ok();
    let early = active.then(early_signals).transpose()?;
    active.then(|| writeln!(io::stdout(), "{READY}")).transpose()?;
    active.then(|| io::stdout().flush()).transpose()?;
    active.then(|| io::stdin().read_line(&mut String::new())).transpose()?;
    assert_eq!(early.is_some(), active);
    Ok(())
}

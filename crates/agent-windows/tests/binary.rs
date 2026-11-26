#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-agent-windows");


const OWNER_ONLY: u32 = 0o700;


const OPEN_TO_ALL: u32 = 0o777;


const ROUND_OVER: &str = "round failed";


const REFUSED: &str = "configuration reload refused";


const SETTINGS: &str = "audit_file: audit-log\npoll_interval_seconds: 1\n";


const HANG_GUARD: Duration = Duration::from_secs(120);


const LINES_AFTER_STOP: usize = 20;


const MAX_LINES: usize = 200;


struct Running {
    child: Child,
    lines: Receiver<String>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::warn!(%error, "cannot stop the test child");
        }
        if let Err(error) = self.child.wait() {
            tracing::warn!(%error, "cannot stop the test child");
        }
    }
}


struct Site {
    state: PathBuf,
    spool: PathBuf,
}


fn site(root: &Path, settings: &str) -> Result<Site, Box<dyn std::error::Error>> {
    let state = root.join("state");
    let spool_dir = root.join("spool");
    [&state, &spool_dir].iter().try_for_each(|directory| {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(OWNER_ONLY))
    })?;
    fs::write(state.join("settings.yaml"), settings)?;
    Ok(Site {
        state,
        spool: spool_dir.join("spool"),
    })
}


fn forward_lines(stderr: ChildStderr, sender: Sender<String>) {
    let sent = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .try_for_each(|line| sender.send(line));
    if let Err(error) = sent {
        tracing::warn!(%error, "the test reader lost its receiver");
    }
}


fn start_child(made: &Site) -> Result<Running, Box<dyn std::error::Error>> {
    start_child_with(&[&made.state, &made.spool])
}


fn start_child_with(arguments: &[&Path]) -> Result<Running, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    std::thread::spawn(move || forward_lines(stderr, sender));
    Ok(Running { child, lines })
}


fn read_until(running: &Running, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut seen = String::new();
    let found = (0..MAX_LINES).find_map(|_| match running.lines.recv_timeout(HANG_GUARD) {
        Ok(line) => {
            seen.push_str(&line);
            seen.push('\n');
            line.contains(marker).then_some(Ok(()))
        }
        Err(error) => Some(Err(error)),
    });
    match found {
        Some(Ok(())) => Ok(seen),
        Some(Err(error)) => Err(format!("hang guard: marker {marker:?} never logged ({error}): {seen}").into()),
        None => Err(format!("marker {marker:?} not among the first {MAX_LINES} lines: {seen}").into()),
    }
}


fn signal(running: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn finish(mut running: Running) -> Result<(std::process::ExitStatus, String), Box<dyn std::error::Error>> {
    let mut rest = String::new();
    let ended = (0..LINES_AFTER_STOP).find_map(|_| match running.lines.recv_timeout(HANG_GUARD) {
        Ok(line) => {
            rest.push_str(&line);
            rest.push('\n');
            None
        }
        Err(RecvTimeoutError::Disconnected) => Some(true),
        Err(RecvTimeoutError::Timeout) => Some(false),
    });
    match ended {
        Some(true) => Ok((running.child.wait()?, rest)),
        _ => Err(format!("hang guard: the child did not stop after the signal: {rest}").into()),
    }
}


fn run_to_end(arguments: &[&Path]) -> Result<(std::process::ExitStatus, String), Box<dyn std::error::Error>> {
    finish(start_child_with(arguments)?)
}


#[test]
fn a_missing_or_extra_argument_is_a_one_line_usage_error_and_exit_one() -> TestResult {
    let root = tempdir()?;
    [vec![], vec![root.path()], vec![root.path(), root.path(), root.path()]]
        .iter()
        .try_for_each(|arguments| -> TestResult {
            let (status, text) = run_to_end(arguments)?;
            assert_eq!(status.code(), Some(1), "{text}");
            assert_eq!(text.trim_end(), "usage: ostyr-agent-windows <state-dir> <spool>");
            Ok(())
        })
}


#[test]
fn a_bad_settings_file_is_a_one_line_error_and_exit_one() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), "batch: 7\n")?;
    let (status, text) = run_to_end(&[&made.state, &made.spool])?;
    assert_eq!(status.code(), Some(1), "{text}");
    assert_eq!(text.trim_end(), "cannot start: settings refused: setting `audit_file` is missing");
    Ok(())
}


#[test]
fn a_state_directory_writable_by_others_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    fs::set_permissions(&made.state, fs::Permissions::from_mode(OPEN_TO_ALL))?;
    let (status, text) = run_to_end(&[&made.state, &made.spool])?;
    assert_eq!(status.code(), Some(1), "{text}");
    assert!(text.starts_with("cannot start: state directory: "), "{text}");
    assert!(!made.spool.exists());
    Ok(())
}


#[test]
fn a_round_is_served_and_sigint_stops_it_cleanly() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let child = start_child(&made)?;
    read_until(&child, ROUND_OVER)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    assert!(rest.contains("stopped on request"), "{rest}");
    assert!(made.state.join("audit-log").is_file());
    Ok(())
}


#[test]
fn sigterm_stops_it_cleanly_too() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let child = start_child(&made)?;
    read_until(&child, ROUND_OVER)?;
    signal(&child, "-TERM")?;
    let (status, rest) = finish(child)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    Ok(())
}


#[test]
fn a_refused_reload_is_audited_in_the_real_file_for_the_tenant_all() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let child = start_child(&made)?;
    read_until(&child, ROUND_OVER)?;
    fs::write(made.state.join("settings.yaml"), "audit_file: audit-log\nbatch: 0\n")?;
    read_until(&child, REFUSED)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    let audit = fs::read_to_string(made.state.join("audit-log"))?;
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    assert!(audit.to_ascii_lowercase().contains("denied"), "{audit}");
    Ok(())
}


#[test]
fn a_reload_that_moves_the_audit_file_is_refused_in_the_running_service() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let child = start_child(&made)?;
    read_until(&child, ROUND_OVER)?;
    fs::write(made.state.join("settings.yaml"), "audit_file: elsewhere\npoll_interval_seconds: 1\n")?;
    read_until(&child, REFUSED)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    assert!(!made.state.join("elsewhere").exists());
    Ok(())
}

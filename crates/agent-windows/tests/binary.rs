#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use tempfile::tempdir;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-agent-windows");


const OWNER_ONLY: u32 = 0o700;


const OPEN_TO_ALL: u32 = 0o777;


const ROUND_OVER: &str = "round failed";


const REFUSED: &str = "configuration reload refused";


const SETTINGS: &str = "audit_file: audit-log\npoll_interval_seconds: 1\n";


struct Running(Child);


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            tracing::warn!(%error, "cannot stop the test child");
        }
        if let Err(error) = self.0.wait() {
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


fn spawn(made: &Site) -> Result<(Running, BufReader<ChildStderr>), Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(&made.state)
        .arg(&made.spool)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    Ok((Running(child), BufReader::new(stderr)))
}


fn read_until(reader: &mut BufReader<ChildStderr>, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut seen = String::new();
    let mut line = String::new();
    let found = (0..u32::MAX).find_map(|_| {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => Some(false),
            Ok(_) => {
                seen.push_str(&line);
                line.contains(marker).then_some(true)
            }
        }
    });
    if found == Some(true) {
        Ok(seen)
    } else {
        Err(format!("marker {marker:?} never logged: {seen}").into())
    }
}


fn signal(child: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(child.0.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn finish(mut child: Running, mut reader: BufReader<ChildStderr>) -> Result<(std::process::ExitStatus, String), Box<dyn std::error::Error>> {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    Ok((child.0.wait()?, rest))
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


#[test]
fn a_missing_or_extra_argument_is_a_one_line_usage_error_and_exit_one() -> TestResult {
    let root = tempdir()?;
    [vec![], vec![root.path()], vec![root.path(), root.path(), root.path()]]
        .iter()
        .try_for_each(|arguments| -> TestResult {
            let output = run_to_end(arguments)?;
            let text = String::from_utf8(output.stderr)?;
            assert_eq!(output.status.code(), Some(1), "{text}");
            assert_eq!(text.trim_end(), "usage: ostyr-agent-windows <state-dir> <spool>");
            Ok(())
        })
}


#[test]
fn a_bad_settings_file_is_a_one_line_error_and_exit_one() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), "batch: 7\n")?;
    let output = run_to_end(&[&made.state, &made.spool])?;
    let text = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert_eq!(text.trim_end(), "cannot start: settings refused: setting `audit_file` is missing");
    Ok(())
}


#[test]
fn a_state_directory_writable_by_others_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    fs::set_permissions(&made.state, fs::Permissions::from_mode(OPEN_TO_ALL))?;
    let output = run_to_end(&[&made.state, &made.spool])?;
    let text = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.starts_with("cannot start: state directory refused"), "{text}");
    assert!(!made.spool.exists());
    Ok(())
}


#[test]
fn a_round_is_served_and_sigint_stops_it_cleanly() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let (child, mut reader) = spawn(&made)?;
    read_until(&mut reader, ROUND_OVER)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child, reader)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    assert!(made.state.join("audit-log").is_file());
    Ok(())
}


#[test]
fn sigterm_stops_it_cleanly_too() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let (child, mut reader) = spawn(&made)?;
    read_until(&mut reader, ROUND_OVER)?;
    signal(&child, "-TERM")?;
    let (status, rest) = finish(child, reader)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    Ok(())
}


#[test]
fn a_refused_reload_is_audited_in_the_real_file_for_the_tenant_all() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), SETTINGS)?;
    let (child, mut reader) = spawn(&made)?;
    read_until(&mut reader, ROUND_OVER)?;
    fs::write(made.state.join("settings.yaml"), "audit_file: audit-log\nbatch: 0\n")?;
    read_until(&mut reader, REFUSED)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child, reader)?;
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
    let (child, mut reader) = spawn(&made)?;
    read_until(&mut reader, ROUND_OVER)?;
    fs::write(made.state.join("settings.yaml"), "audit_file: elsewhere\npoll_interval_seconds: 1\n")?;
    read_until(&mut reader, REFUSED)?;
    signal(&child, "-INT")?;
    let (status, rest) = finish(child, reader)?;
    assert_eq!(status.code(), Some(0), "{rest}");
    assert!(!made.state.join("elsewhere").exists());
    Ok(())
}

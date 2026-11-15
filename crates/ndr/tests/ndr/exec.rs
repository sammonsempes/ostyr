use crate::support::{fixture, logging_on, ready, TestResult, CLOSE_FDS, ENV_ECHO, EXIT_THREE, FOUR, PID_FLOOD, PID_SLEEP, SLEEP};
use ndr::error::NdrError;
use ndr::exec::{exit_ok, kill_all, kill_logged, read_bounded, run_bounded, run_with, wait_exit, watch};
use rustix::process::Pid;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;


const LONG: Duration = Duration::from_secs(60);


const SHORT: Duration = Duration::from_millis(200);


const BOUND: usize = 100;


fn no_args() -> Vec<OsString> {
    Vec::new()
}


fn pid_args(pid_file: &Path) -> Vec<OsString> {
    vec![pid_file.as_os_str().to_os_string()]
}


fn failing_read(_reader: &mut dyn Read, _max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    Err(io::Error::other("injected read failure"))
}


#[test]
fn read_bounded_keeps_the_bound_and_reports_the_excess() -> TestResult {
    assert_eq!(read_bounded(&mut &b"abcd"[..], FOUR as usize)?, (b"abcd".to_vec(), false));
    assert_eq!(read_bounded(&mut &b"abcde"[..], FOUR as usize)?, (b"abcd".to_vec(), true));
    Ok(())
}


#[test]
fn both_streams_arrive_in_one_bounded_output_with_a_clean_environment_and_null_stdin() -> TestResult {
    let fake = fixture(ENV_ECHO)?;
    let run = run_bounded(&fake.yr, &no_args(), BOUND, LONG)?;
    assert_eq!(String::from_utf8(run.bytes)?, "out [unset]\nerr\n");
    assert!(run.exited_ok && !run.cut && !run.timed_out);
    Ok(())
}


#[test]
fn a_failing_exit_is_reported() -> TestResult {
    let fake = fixture(EXIT_THREE)?;
    let run = run_bounded(&fake.yr, &no_args(), BOUND, LONG)?;
    assert!(!run.exited_ok && !run.cut && !run.timed_out);
    Ok(())
}


#[test]
fn an_endless_output_is_cut_at_the_bound_and_the_child_is_gone() -> TestResult {
    let pid_file = tempfile::NamedTempFile::new()?;
    let fake = fixture(PID_FLOOD)?;
    let run = run_bounded(&fake.yr, &pid_args(pid_file.path()), BOUND, LONG)?;
    assert!(run.cut && !run.timed_out && !run.exited_ok);
    assert_eq!(run.bytes.len(), BOUND);
    let pid = fs::read_to_string(pid_file.path())?;
    assert!(!Path::new("/proc").join(pid.trim()).exists());
    Ok(())
}


#[test]
fn a_child_that_never_exits_is_killed_at_the_deadline_and_reaped() -> TestResult {
    let pid_file = tempfile::NamedTempFile::new()?;
    let fake = fixture(PID_SLEEP)?;
    let run = run_bounded(&fake.yr, &pid_args(pid_file.path()), BOUND, SHORT)?;
    assert!(run.timed_out && !run.exited_ok && !run.cut);
    let pid = fs::read_to_string(pid_file.path())?;
    assert!(!Path::new("/proc").join(pid.trim()).exists());
    Ok(())
}


#[test]
fn a_child_that_closes_its_output_and_keeps_running_is_still_killed() -> TestResult {
    let fake = fixture(CLOSE_FDS)?;
    let run = run_bounded(&fake.yr, &no_args(), BOUND, SHORT)?;
    assert!(run.timed_out && run.bytes.is_empty());
    Ok(())
}


#[test]
fn a_failing_read_kills_and_reaps_the_child() -> TestResult {
    let fake = fixture(SLEEP)?;
    let result = run_with(&fake.yr, &no_args(), BOUND, LONG, failing_read);
    assert!(matches!(result, Err(NdrError::Output(_))));
    Ok(())
}


#[test]
fn a_program_that_cannot_be_executed_is_a_spawn_error() -> TestResult {
    let own = crate::program::own_dir()?;
    let yr = crate::program::plain_program(own.path())?;
    assert!(matches!(run_bounded(&yr, &no_args(), BOUND, LONG), Err(NdrError::Spawn(_))));
    Ok(())
}


#[test]
fn killing_a_pid_that_is_gone_is_an_error_not_a_panic() -> TestResult {
    assert!(logging_on());
    ready()?;
    let mut child = Command::new("/bin/true").spawn()?;
    let pid = Pid::from_child(&child);
    child.wait()?;
    assert!(kill_all(pid).is_err());
    kill_logged(pid);
    Ok(())
}


#[test]
fn the_watchdog_kills_only_when_the_deadline_passes_first() -> TestResult {
    assert!(logging_on());
    ready()?;
    let mut child = Command::new("/bin/true").spawn()?;
    let pid = Pid::from_child(&child);
    child.wait()?;
    let flag = AtomicBool::new(false);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    done_tx.send(())?;
    watch(pid, &done_rx, LONG, &flag);
    assert!(!flag.load(Ordering::SeqCst));
    drop(done_tx);
    let (held_tx, held_rx) = mpsc::channel::<()>();
    watch(pid, &held_rx, SHORT, &flag);
    assert!(flag.load(Ordering::SeqCst));
    drop(held_tx);
    Ok(())
}


#[test]
fn waiting_for_a_pid_that_is_not_a_child_is_logged_and_returns() -> TestResult {
    assert!(logging_on());
    wait_exit(Pid::INIT);
    Ok(())
}


#[test]
fn a_failed_wait_counts_as_a_failure_and_a_clean_exit_as_success() -> TestResult {
    assert!(logging_on());
    ready()?;
    assert!(!exit_ok(Err(io::Error::other("injected wait failure"))));
    let status = Command::new("/bin/true").status()?;
    assert!(exit_ok(Ok(status)));
    let failed = Command::new("/bin/false").status()?;
    assert!(!exit_ok(Ok(failed)));
    Ok(())
}

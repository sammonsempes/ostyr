use crate::types::TestResult;
use agent_channel::spool::{
    append_back, append_locked, is_lock_violation, lines_to_claim, lines_to_claim_with, lock_bounded, pause_between_lock_attempts, SPOOL_LOCK_BUSY,
    WINDOWS_LOCK_VIOLATION,
};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::Barrier;
use std::thread::scope;
use tempfile::tempdir;


const WRITERS: usize = 2;


const LINES_PER_WRITER: usize = 40;


const LINE_BYTES: usize = 3_000;


const CALL_LINES: usize = 3;


fn payload(writer: usize, index: usize) -> String {
    format!("{writer}-{index}-{}", "x".repeat(LINE_BYTES))
}


#[test]
fn concurrent_appends_to_one_spool_never_interleave() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let barrier = Barrier::new(WRITERS);
    let outcomes = scope(|workers| {
        (0..WRITERS)
            .map(|writer| {
                let (spool_ref, barrier_ref) = (&spool, &barrier);
                workers.spawn(move || {
                    barrier_ref.wait();
                    (0..LINES_PER_WRITER).try_for_each(|index| append_back(std::iter::once(Ok(payload(writer, index))), spool_ref).map(|_| ()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "a writer panicked"))
            .collect::<Vec<_>>()
    });
    outcomes
        .into_iter()
        .try_for_each(|outcome| outcome?.map_err(Box::<dyn std::error::Error>::from))?;
    let text = fs::read_to_string(&spool)?;
    let found: BTreeSet<&str> = text.lines().collect();
    let expected: Vec<String> = (0..WRITERS)
        .flat_map(|writer| (0..LINES_PER_WRITER).map(move |index| payload(writer, index)))
        .collect();
    assert_eq!(text.lines().count(), WRITERS * LINES_PER_WRITER);
    assert_eq!(found.len(), WRITERS * LINES_PER_WRITER);
    assert!(expected.iter().all(|line| found.contains(line.as_str())));
    Ok(())
}


#[test]
fn a_failing_line_appends_nothing_of_the_call() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let lines = vec![Ok("whole".to_owned()), Err(io::Error::other("injected"))];
    assert!(append_back(lines.into_iter(), &spool).is_err());
    assert!(!spool.exists());
    let batch = (0..CALL_LINES).map(|index| Ok(index.to_string()));
    assert!(append_back(batch, &spool)?);
    assert_eq!(fs::read_to_string(&spool)?, "0\n1\n2\n");
    Ok(())
}


const CHILD_PROCESSES: usize = 2;


const CHILD_LINES: usize = 200;


const CHILD_LINE_BYTES: usize = 4_000;


const CHILD_SPOOL_VARIABLE: &str = "OSTYR_SPOOL_CHILD_PATH";


const CHILD_WRITER_VARIABLE: &str = "OSTYR_SPOOL_CHILD_WRITER";


const CHILD_TEST: &str = "spool_append::spool_child_appends_when_asked";


const ATTEMPTS: u32 = 3;


const CLAIMED_LINES: u64 = 2;


fn child_payload(writer: &str, index: usize) -> String {
    format!("{writer}-{index}-{}", "y".repeat(CHILD_LINE_BYTES))
}


#[test]
fn spool_child_appends_when_asked() -> TestResult {
    if let (Some(spool), Ok(writer)) = (std::env::var_os(CHILD_SPOOL_VARIABLE), std::env::var(CHILD_WRITER_VARIABLE)) {
        (0..CHILD_LINES).try_for_each(|index| append_back(std::iter::once(Ok(child_payload(&writer, index))), Path::new(&spool)).map(|_| ()))?;
    }
    Ok(())
}


#[test]
fn two_processes_appending_to_one_spool_lose_no_line() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let me = std::env::current_exe()?;
    let children = (0..CHILD_PROCESSES)
        .map(|writer| {
            Command::new(&me)
                .args(["--exact", CHILD_TEST, "--test-threads=1"])
                .env(CHILD_SPOOL_VARIABLE, &spool)
                .env(CHILD_WRITER_VARIABLE, writer.to_string())
                .spawn()
        })
        .collect::<io::Result<Vec<_>>>()?;
    children.into_iter().try_for_each(|mut child| -> Result<(), Box<dyn std::error::Error>> {
        let status = child.wait()?;
        Ok(status.success().then_some(()).ok_or("a child appender failed")?)
    })?;
    let text = fs::read_to_string(&spool)?;
    let found: BTreeSet<&str> = text.lines().collect();
    let expected: Vec<String> = (0..CHILD_PROCESSES)
        .flat_map(|writer| (0..CHILD_LINES).map(move |index| child_payload(&writer.to_string(), index)))
        .collect();
    assert_eq!(text.lines().count(), CHILD_PROCESSES * CHILD_LINES);
    assert!(expected.iter().all(|line| found.contains(line.as_str())));
    Ok(())
}


fn holder(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).append(true).create(true).open(path)?;
    file.lock()?;
    Ok(file)
}


#[test]
fn a_held_spool_lock_fails_the_append_at_the_deadline_with_the_fixed_error() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let _held = holder(&spool)?;
    let mut pauses = 0;
    let error = append_locked(std::iter::once(Ok("a".to_owned())), &spool, ATTEMPTS, &mut || pauses += 1)
        .err()
        .ok_or("appended")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), SPOOL_LOCK_BUSY);
    assert_eq!(pauses, ATTEMPTS);
    assert_eq!(fs::read_to_string(&spool)?, "");
    Ok(())
}


#[test]
fn a_lock_released_during_the_wait_lets_the_append_through() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let mut held = Some(holder(&spool)?);
    assert!(append_locked(std::iter::once(Ok("late".to_owned())), &spool, ATTEMPTS, &mut || drop(
        held.take()
    ))?);
    assert_eq!(fs::read_to_string(&spool)?, "late\n");
    Ok(())
}


#[test]
fn a_lock_error_that_is_not_contention_is_returned_at_once() -> TestResult {
    let mut pauses = 0;
    let outcome = lock_bounded(ATTEMPTS, &mut || Err(TryLockError::Error(io::Error::other("injected"))), &mut || {
        pauses += 1
    });
    assert_eq!(outcome.err().map(|error| error.to_string()), Some("injected".to_owned()));
    assert_eq!(pauses, 0);
    Ok(())
}


#[test]
fn the_default_pause_returns() -> TestResult {
    pause_between_lock_attempts();
    Ok(())
}


#[test]
fn the_windows_lock_violation_code_is_recognised() -> TestResult {
    assert!(is_lock_violation(&io::Error::from_raw_os_error(WINDOWS_LOCK_VIOLATION)));
    assert!(!is_lock_violation(&io::Error::other("other")));
    Ok(())
}


fn violated(_path: &Path, _limit: usize) -> io::Result<u64> {
    Err(io::Error::from_raw_os_error(WINDOWS_LOCK_VIOLATION))
}


fn refused(_path: &Path, _limit: usize) -> io::Result<u64> {
    Err(io::Error::other("refused"))
}


fn counted(_path: &Path, _limit: usize) -> io::Result<u64> {
    Ok(CLAIMED_LINES)
}


#[test]
fn a_producer_holding_the_spool_defers_the_claim_and_other_errors_surface() -> TestResult {
    let path = Path::new("spool");
    assert_eq!(lines_to_claim_with(path, 1, violated)?, None);
    assert_eq!(lines_to_claim_with(path, 1, counted)?, Some(CLAIMED_LINES));
    assert!(lines_to_claim_with(path, 1, refused).is_err());
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    fs::write(&spool, "a\nb\n")?;
    assert_eq!(lines_to_claim(&spool, CHILD_LINE_BYTES)?, Some(CLAIMED_LINES));
    Ok(())
}


#[cfg(windows)]
#[test]
fn a_spool_locked_by_a_producer_never_fails_the_claim_on_windows() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    fs::write(&spool, "a\n")?;
    let _held = holder(&spool)?;
    let outcome = lines_to_claim(&spool, CHILD_LINE_BYTES)?;
    assert!(matches!(outcome, None | Some(1)));
    Ok(())
}

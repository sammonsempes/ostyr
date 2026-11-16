use crate::types::TestResult;
use agent_channel::agent_app::AgentFile;
use agent_channel::spool::{
    append_back, append_locked, append_locked_between, claim_spool, claim_spool_with, finish_spool, finish_spool_with, is_lock_violation,
    lines_to_claim, lines_to_claim_with, lock_bounded, pause_between_lock_attempts, write_locked_with, Spool, SPOOL_LOCK_BUSY,
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
                    (0..LINES_PER_WRITER).try_for_each(|index| {
                        append_locked(
                            std::iter::once(Ok(payload(writer, index))),
                            spool_ref,
                            CHILD_ATTEMPTS,
                            &mut pause_between_lock_attempts,
                        )
                        .map(|_| ())
                    })
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


const CHILD_ATTEMPTS: u32 = 1_000_000;


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
        (0..CHILD_LINES).try_for_each(|index| {
            append_locked(
                std::iter::once(Ok(child_payload(&writer, index))),
                Path::new(&spool),
                CHILD_ATTEMPTS,
                &mut pause_between_lock_attempts,
            )
            .map(|_| ())
        })?;
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


fn agent_file(dir: &Path) -> AgentFile {
    AgentFile {
        server: "127.0.0.1:1".to_owned(),
        server_name: "server".to_owned(),
        certificate: dir.join("cert"),
        key: dir.join("key"),
        platform_ca: dir.join("ca"),
        tenant: "acme".to_owned(),
        agent_id: "agent-1".to_owned(),
        keys_file: dir.join("keys"),
        state_file: dir.join("state"),
        audit_file: dir.join("audit"),
        spool_file: dir.join("spool"),
        sequence_file: dir.join("sequence"),
        executed_file: dir.join("executed"),
    }
}


fn locked_load(_sending: &Path, _spool: &Path, _count: u64, _limit: usize) -> io::Result<Vec<String>> {
    Err(io::Error::from_raw_os_error(WINDOWS_LOCK_VIOLATION))
}


fn refused_load(_sending: &Path, _spool: &Path, _count: u64, _limit: usize) -> io::Result<Vec<String>> {
    Err(io::Error::other("refused"))
}


#[test]
fn a_locked_claimed_file_is_kept_and_never_removed_by_finish() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "a\n")?;
    let spool = claim_spool_with(&file, locked_load)?;
    assert!(spool.batches.is_empty());
    finish_spool(&spool, &[])?;
    assert!(sending.exists());
    assert!(claim_spool_with(&file, refused_load).is_err());
    Ok(())
}


#[test]
fn a_spool_renamed_after_the_write_is_still_synced_on_the_written_handle() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let claimed = dir.path().join("spool.sending");
    let mut renamed = false;
    let appended = append_locked_between(std::iter::once(Ok("line".to_owned())), &spool, ATTEMPTS, &mut || (), &mut || {
        renamed = fs::rename(&spool, &claimed).is_ok();
    })?;
    assert!(appended && renamed);
    assert_eq!(fs::read_to_string(&claimed)?, "line\n");
    assert!(!spool.exists());
    Ok(())
}


#[test]
fn an_append_that_waited_while_the_agent_delivered_the_claim_never_loses_its_line() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let spool = dir.path().join("spool");
    let claimed = dir.path().join("spool.sending");
    fs::write(&spool, "first\n")?;
    let mut held = Some(holder(&spool)?);
    let mut finished = false;
    let appended = append_locked(std::iter::once(Ok("second".to_owned())), &spool, ATTEMPTS, &mut || {
        if let Ok(claim) = claim_spool(&file) {
            drop(held.take());
            finished = finish_spool(&claim, &[1]).is_ok();
        }
    })?;
    assert!(appended && finished);
    assert!(!claimed.exists());
    assert_eq!(fs::read_to_string(&spool)?, "second\n");
    Ok(())
}


#[test]
fn a_spool_replaced_by_another_producer_while_waiting_gets_the_line() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let aside = dir.path().join("aside");
    let mut held = Some(holder(&spool)?);
    let appended = append_locked(std::iter::once(Ok("waiter".to_owned())), &spool, ATTEMPTS, &mut || {
        logged(fs::rename(&spool, &aside));
        logged(fs::write(&spool, "other\n"));
        drop(held.take());
    })?;
    assert!(appended);
    assert_eq!(fs::read_to_string(&spool)?, "other\nwaiter\n");
    assert_eq!(fs::read_to_string(&aside)?, "");
    Ok(())
}


fn never_current(_out: &File, _spool: &Path) -> io::Result<bool> {
    Ok(false)
}


#[test]
fn an_append_that_never_finds_the_spool_current_fails_with_the_fixed_error_and_writes_nothing() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let error = write_locked_with("a\n", &spool, ATTEMPTS, &mut || (), &mut || (), never_current)
        .err()
        .ok_or("written")?;
    assert_eq!(error.to_string(), SPOOL_LOCK_BUSY);
    assert_eq!(fs::read_to_string(&spool)?, "");
    Ok(())
}


#[test]
fn a_claimed_file_locked_by_a_producer_is_kept_by_finish() -> TestResult {
    let dir = tempdir()?;
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "")?;
    let claimed = Spool {
        batches: Vec::new(),
        sending: sending.clone(),
        sending_bytes: 0,
    };
    let _held = holder(&sending)?;
    let mut pauses = 0;
    finish_spool_with(&claimed, &[], ATTEMPTS, &mut || pauses += 1)?;
    assert_eq!(pauses, ATTEMPTS);
    assert!(sending.exists());
    Ok(())
}


#[test]
fn an_empty_locked_claimed_file_is_never_removed_by_finish() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "")?;
    let claimed = claim_spool_with(&file, locked_load)?;
    assert_eq!(claimed.sending_bytes, u64::MAX);
    finish_spool(&claimed, &[])?;
    assert!(sending.exists());
    Ok(())
}


const WAIT_ATTEMPTS: u32 = 1_000_000;


const SIGNAL_DIRECTORY_VARIABLE: &str = "OSTYR_SPOOL_CHILD_SIGNALS";


const ROLE_VARIABLE: &str = "OSTYR_SPOOL_CHILD_ROLE";


const LOCK_CHILD_TEST: &str = "spool_append::spool_child_takes_a_role_when_asked";


const HOLD_ROLE: &str = "hold";


fn wait_until(ready: &dyn Fn() -> bool) -> Result<(), Box<dyn std::error::Error>> {
    let found = (0..WAIT_ATTEMPTS).find(|_| ready() || (pause_between_lock_attempts(), false).1);
    Ok(found.map(|_| ()).ok_or("a signal never came")?)
}


fn signal(path: &Path) -> io::Result<()> {
    fs::write(path, b"")
}


#[test]
fn spool_child_takes_a_role_when_asked() -> TestResult {
    if let (Some(spool_text), Some(signals_text), Ok(role)) = (
        std::env::var_os(CHILD_SPOOL_VARIABLE),
        std::env::var_os(SIGNAL_DIRECTORY_VARIABLE),
        std::env::var(ROLE_VARIABLE),
    ) {
        let (spool, signals) = (Path::new(&spool_text), Path::new(&signals_text));
        let mut failure: Option<Box<dyn std::error::Error>> = None;
        if role == HOLD_ROLE {
            append_locked_between(
                std::iter::once(Ok("held".to_owned())),
                spool,
                CHILD_ATTEMPTS,
                &mut pause_between_lock_attempts,
                &mut || {
                    failure = signal(&signals.join("held"))
                        .map_err(Into::into)
                        .and_then(|()| wait_until(&|| signals.join("release").exists()))
                        .err();
                },
            )?;
        } else {
            let mut pause_failure = None;
            append_locked(std::iter::once(Ok("waiter".to_owned())), spool, CHILD_ATTEMPTS, &mut || {
                pause_failure = signal(&signals.join("blocked")).err();
                pause_between_lock_attempts();
            })?;
            signal(&signals.join("done"))?;
            if let Some(error) = pause_failure {
                Err(error)?;
            }
        }
        if let Some(error) = failure {
            Err(error)?;
        }
    }
    Ok(())
}


fn child(spool: &Path, signals: &Path, role: &str) -> io::Result<std::process::Child> {
    Command::new(std::env::current_exe()?)
        .args(["--exact", LOCK_CHILD_TEST, "--test-threads=1"])
        .env(CHILD_SPOOL_VARIABLE, spool)
        .env(SIGNAL_DIRECTORY_VARIABLE, signals)
        .env(ROLE_VARIABLE, role)
        .spawn()
}


#[test]
fn a_process_waiting_for_the_spool_lock_cannot_finish_before_the_holder_releases_it() -> TestResult {
    let dir = tempdir()?;
    let signals = dir.path().join("signals");
    fs::create_dir(&signals)?;
    let spool = dir.path().join("spool");
    let mut holder_process = child(&spool, &signals, HOLD_ROLE)?;
    wait_until(&|| signals.join("held").exists())?;
    let mut waiter_process = child(&spool, &signals, "wait")?;
    wait_until(&|| signals.join("blocked").exists() || signals.join("done").exists())?;
    let finished_first = !signals.join("blocked").exists();
    signal(&signals.join("release"))?;
    assert!(holder_process.wait()?.success());
    assert!(waiter_process.wait()?.success());
    assert!(!finished_first);
    assert_eq!(fs::read_to_string(&spool)?, "held\nwaiter\n");
    Ok(())
}


#[test]
fn a_thread_waiting_for_the_spool_lock_cannot_finish_before_the_holder_releases_it() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let (held_sender, held_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel::<()>();
    let (event_sender, event_receiver) = std::sync::mpsc::channel();
    let first_event = scope(|workers| -> Result<&'static str, Box<dyn std::error::Error>> {
        let holder_spool = &spool;
        let holder_thread = workers.spawn(move || {
            append_locked_between(
                std::iter::once(Ok("held".to_owned())),
                holder_spool,
                CHILD_ATTEMPTS,
                &mut || (),
                &mut || {
                    logged(held_sender.send(()));
                    logged(release_receiver.recv());
                },
            )
        });
        held_receiver.recv()?;
        let blocked_sender = event_sender.clone();
        let waiter_spool = &spool;
        let waiter_thread = workers.spawn(move || {
            let appended = append_locked(std::iter::once(Ok("waiter".to_owned())), waiter_spool, CHILD_ATTEMPTS, &mut || {
                logged(blocked_sender.send("blocked"));
                pause_between_lock_attempts();
            });
            logged(event_sender.send("done"));
            appended
        });
        let first = event_receiver.recv()?;
        release_sender.send(())?;
        holder_thread.join().map_err(|_| "the holder panicked")??;
        waiter_thread.join().map_err(|_| "the waiter panicked")??;
        Ok(first)
    })?;
    assert_eq!(first_event, "blocked");
    assert_eq!(fs::read_to_string(&spool)?, "held\nwaiter\n");
    Ok(())
}


fn logged<Sent, Failure: std::fmt::Display>(outcome: Result<Sent, Failure>) {
    if let Err(error) = outcome {
        tracing::error!(%error, "test channel failed");
    }
}

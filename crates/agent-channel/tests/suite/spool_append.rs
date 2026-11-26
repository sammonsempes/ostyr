use crate::harness::long_tempdir;
use crate::types::TestResult;
use agent_channel::agent_app::AgentFile;
use agent_channel::spool::SequenceState;
use agent_channel::spool::{
    append_back, append_locked, append_locked_between, claim_fresh_with, claim_locked, claim_spool, claim_spool_in, claim_spool_with, count_lines,
    finish_spool, finish_spool_with, is_lock_violation, lines_to_claim, lines_to_claim_with, load_claimed, lock_bounded, pause_between_lock_attempts,
    write_locked_with, Spool, SPOOL_LOCK_BUSY, WINDOWS_LOCK_VIOLATION,
};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::sync::{mpsc, Barrier};
use std::thread::scope;


const WRITERS: usize = 2;


const LINES_PER_WRITER: usize = 40;


const LINE_BYTES: usize = 3_000;


const CALL_LINES: usize = 3;


fn payload(writer: usize, index: usize) -> String {
    format!("{writer}-{index}-{}", "x".repeat(LINE_BYTES))
}


#[test]
fn concurrent_appends_to_one_spool_never_interleave() -> TestResult {
    let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
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


const CHILD_LINES: usize = 100;


const CHILD_ATTEMPTS: u32 = u32::MAX;


const CHILD_HANG_GUARD_SECONDS: u64 = 600;


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


fn kill_process(pid: u32) -> io::Result<()> {
    let pid_text = pid.to_string();
    let status = if cfg!(windows) {
        Command::new("taskkill").args(["/F", "/PID", &pid_text]).status()?
    } else {
        Command::new("kill").args(["-9", &pid_text]).status()?
    };
    status.success().then_some(()).ok_or(io::Error::other("kill failed"))
}


fn wait_for_children(children: Vec<std::process::Child>) -> Result<(), Box<dyn std::error::Error>> {
    let pids: Vec<u32> = children.iter().map(std::process::Child::id).collect();
    let (sender, receiver) = mpsc::channel();
    let waiters: Vec<_> = children
        .into_iter()
        .map(|mut child| {
            let done_sender = sender.clone();
            std::thread::spawn(move || done_sender.send(child.wait().map(|status| status.success())))
        })
        .collect();
    drop(sender);
    let verdicts = (0..pids.len()).try_fold(Vec::new(), |mut done, _child| {
        receiver
            .recv_timeout(std::time::Duration::from_secs(CHILD_HANG_GUARD_SECONDS))
            .map(|verdict| {
                done.push(verdict);
                done
            })
    });
    match verdicts {
        Ok(done) => {
            waiters
                .into_iter()
                .try_for_each(|waiter| waiter.join().map(|_| ()).map_err(|_| "a waiter thread panicked"))?;
            done.into_iter()
                .collect::<io::Result<Vec<bool>>>()?
                .into_iter()
                .all(|success| success)
                .then_some(())
                .ok_or("a child appender failed".into())
        }
        Err(_) => {
            pids.iter().try_for_each(|pid| kill_process(*pid))?;
            Err("a child appender hung: the spool lock was never obtained before the child hang guard".into())
        }
    }
}


#[test]
fn two_processes_appending_to_one_spool_lose_no_line() -> TestResult {
    let dir = long_tempdir()?;
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
    wait_for_children(children)?;
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
    let dir = long_tempdir()?;
    let spool = dir.path().join("spool");
    let held = holder(&spool)?;
    let mut pauses = 0;
    let error = append_locked(std::iter::once(Ok("a".to_owned())), &spool, ATTEMPTS, &mut || pauses += 1)
        .err()
        .ok_or("appended")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), SPOOL_LOCK_BUSY);
    assert_eq!(pauses, ATTEMPTS);
    drop(held);
    assert_eq!(fs::read_to_string(&spool)?, "");
    Ok(())
}


#[test]
fn a_lock_released_during_the_wait_lets_the_append_through() -> TestResult {
    let dir = long_tempdir()?;
    let spool = dir.path().join("spool");
    let mut held = Some(holder(&spool)?);
    assert!(append_locked(std::iter::once(Ok("late".to_owned())), &spool, WAIT_ATTEMPTS, &mut || {
        drop(held.take());
        pause_between_lock_attempts();
    })?);
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
    let dir = long_tempdir()?;
    let spool = dir.path().join("spool");
    fs::write(&spool, "a\nb\n")?;
    assert_eq!(lines_to_claim(&spool, CHILD_LINE_BYTES)?, Some(CLAIMED_LINES));
    Ok(())
}


#[cfg(windows)]
#[test]
fn a_spool_locked_by_a_producer_never_fails_the_claim_on_windows() -> TestResult {
    let dir = long_tempdir()?;
    let spool = dir.path().join("spool");
    fs::write(&spool, "a\n")?;
    let _held = holder(&spool)?;
    let outcome = lines_to_claim(&spool, CHILD_LINE_BYTES)?;
    assert!(matches!(outcome, None | Some(1)));
    Ok(())
}


pub fn agent_file(dir: &Path) -> AgentFile {
    AgentFile {
        server: "127.0.0.1:1".to_owned(),
        server_name: "server".to_owned(),
        relays: Vec::new(),
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


fn locked_load(_claimed: &File, _spool: &Path, _count: u64, _limit: usize) -> io::Result<(Vec<String>, bool)> {
    Err(io::Error::from_raw_os_error(WINDOWS_LOCK_VIOLATION))
}


fn refused_load(_claimed: &File, _spool: &Path, _count: u64, _limit: usize) -> io::Result<(Vec<String>, bool)> {
    Err(io::Error::other("refused"))
}


#[test]
fn a_locked_claimed_file_is_kept_and_never_removed_by_finish() -> TestResult {
    let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let spool = dir.path().join("spool");
    let claimed = dir.path().join("spool.sending");
    fs::write(&spool, "first\n")?;
    let mut held = Some(holder(&spool)?);
    let mut finished = false;
    let appended = append_locked(std::iter::once(Ok("second".to_owned())), &spool, WAIT_ATTEMPTS, &mut || {
        held.take().into_iter().for_each(|lock| {
            drop(lock);
            if let Ok(claim) = claim_spool(&file) {
                finished = finish_spool(&claim, &[1]).is_ok();
            }
        });
        pause_between_lock_attempts();
    })?;
    assert!(appended && finished);
    assert!(!claimed.exists());
    assert_eq!(fs::read_to_string(&spool)?, "second\n");
    Ok(())
}


#[test]
fn a_spool_replaced_by_another_producer_while_waiting_gets_the_line() -> TestResult {
    let dir = long_tempdir()?;
    let spool = dir.path().join("spool");
    let aside = dir.path().join("aside");
    let mut held = Some(holder(&spool)?);
    let appended = append_locked(std::iter::once(Ok("waiter".to_owned())), &spool, WAIT_ATTEMPTS, &mut || {
        held.take().into_iter().for_each(|lock| {
            logged(fs::rename(&spool, &aside));
            logged(fs::write(&spool, "other\n"));
            drop(lock);
        });
        pause_between_lock_attempts();
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
    let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "")?;
    let claimed = Spool {
        batches: Vec::new(),
        sending: sending.clone(),
        sending_bytes: 0,
        sequence_file: dir.path().join("sequence"),
        state: SequenceState::default(),
    };
    let _held = holder(&sending)?;
    let mut pauses = 0;
    finish_spool_with(&claimed, &[], ATTEMPTS, &mut || pauses += 1)?;
    assert_eq!(pauses, ATTEMPTS);
    assert!(sending.exists());
    Ok(())
}


#[cfg(unix)]
#[test]
fn finish_that_waited_for_the_lock_never_removes_a_file_replaced_meanwhile() -> TestResult {
    let dir = long_tempdir()?;
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "one\n")?;
    let claimed = Spool {
        batches: Vec::new(),
        sending: sending.clone(),
        sending_bytes: ONE_LINE_BYTES,
        sequence_file: dir.path().join("sequence"),
        state: SequenceState::default(),
    };
    let mut held = Some(holder(&sending)?);
    finish_spool_with(&claimed, &[], WAIT_ATTEMPTS, &mut || {
        held.take().into_iter().for_each(|lock| {
            drop(lock);
            logged(fs::remove_file(&sending));
            logged(fs::write(&sending, "two\n"));
        });
        pause_between_lock_attempts();
    })?;
    assert_eq!(fs::read_to_string(&sending)?, "two\n");
    Ok(())
}


#[test]
fn an_empty_locked_claimed_file_is_never_removed_by_finish() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "")?;
    let claimed = claim_spool_with(&file, locked_load)?;
    assert_eq!(claimed.sending_bytes, u64::MAX);
    finish_spool(&claimed, &[])?;
    assert!(sending.exists());
    Ok(())
}


const WAIT_ATTEMPTS: u32 = 10_000;


#[cfg(unix)]
const ONE_LINE_BYTES: u64 = 4;


const SECOND_SEQUENCE: u64 = 2;


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
    let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
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


#[test]
fn a_claim_waits_for_an_appender_inside_its_locked_write_then_takes_its_line_whole() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let spool = dir.path().join("spool");
    let sending = dir.path().join("spool.sending");
    let (inside_sender, inside) = mpsc::channel();
    let (release_sender, release) = mpsc::channel();
    let (done_sender, done) = mpsc::channel();
    let mut pauses = 0;
    scope(|workers| -> TestResult {
        let spool_ref = &spool;
        let appender = workers.spawn(move || {
            let appended = append_locked_between(std::iter::once(Ok("whole".to_owned())), spool_ref, ATTEMPTS, &mut || (), &mut || {
                logged(inside_sender.send(()));
                logged(release.recv());
            });
            logged(done_sender.send(()));
            appended
        });
        inside.recv()?;
        claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut || {
            pauses += 1;
            logged(release_sender.send(()));
            if pauses == 1 {
                logged(done.recv());
            } else {
                pause_between_lock_attempts();
            }
        })?;
        logged(release_sender.send(()));
        assert!(appender.join().map_err(|_| "appender panicked")??);
        Ok(())
    })?;
    assert!(pauses >= 1);
    assert_eq!(fs::read_to_string(&sending)?, "whole\n");
    assert!(!spool.exists());
    Ok(())
}


#[test]
fn a_claim_that_never_gets_the_lock_defers_and_a_later_one_succeeds() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let spool = dir.path().join("spool");
    let sending = dir.path().join("spool.sending");
    fs::write(&spool, "a\n")?;
    let held = holder(&spool)?;
    let mut pauses = 0;
    claim_fresh_with(&file, &sending, ATTEMPTS, &mut || pauses += 1)?;
    assert_eq!(pauses, ATTEMPTS);
    assert!(spool.exists() && !sending.exists() && !file.sequence_file.exists());
    drop(held);
    claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut pause_between_lock_attempts)?;
    assert_eq!(fs::read_to_string(&sending)?, "a\n");
    Ok(())
}


const TERMINATED_LINE_LIMIT: usize = 100;


#[test]
fn an_unterminated_last_line_is_never_counted_or_loaded_and_a_claim_sets_it_aside() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let spool = dir.path().join("spool");
    let sending = dir.path().join("spool.sending");
    fs::write(&spool, "a\nb")?;
    assert_eq!(count_lines(&spool, TERMINATED_LINE_LIMIT)?, 1);
    assert_eq!(
        load_claimed(&File::open(&spool)?, &dir.path().join("back"), u64::MAX, TERMINATED_LINE_LIMIT)?,
        (vec!["a".to_owned()], false)
    );
    fs::write(&spool, "b")?;
    claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut pause_between_lock_attempts)?;
    assert!(spool.exists() && !sending.exists());
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "b\n");
    OpenOptions::new().append(true).open(&spool)?.write_all(b"c\n")?;
    let claimed = claim_spool(&file)?;
    assert_eq!(claimed.batches.len(), 1);
    assert_eq!(claimed.batches.first().map(|batch| batch.ecs_json.clone()), Some(b"c".to_vec()));
    Ok(())
}


fn sent_texts(spool: &Spool) -> Vec<String> {
    spool
        .batches
        .iter()
        .map(|batch| String::from_utf8_lossy(&batch.ecs_json).into_owned())
        .collect()
}


fn sequences(spool: &Spool) -> Vec<u64> {
    spool.batches.iter().map(|batch| batch.sequence).collect()
}


const WEDGE_ROUNDS: usize = 5;


#[test]
fn a_torn_tail_of_a_claimed_spool_is_set_aside_and_later_events_are_delivered() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, "a\nzzz")?;
    let mut rounds = Vec::new();
    (0..WEDGE_ROUNDS).try_for_each(|index| -> TestResult {
        let claimed = claim_spool(&file)?;
        rounds.push((sent_texts(&claimed), sequences(&claimed)));
        finish_spool(&claimed, &sequences(&claimed))?;
        assert!(!claimed.sending.exists());
        append_back(std::iter::once(Ok(format!("event-{index}"))), &file.spool_file)?;
        Ok(())
    })?;
    let expected: Vec<(Vec<String>, Vec<u64>)> = std::iter::once("a".to_owned())
        .chain((0..WEDGE_ROUNDS).map(|index| format!("event-{index}")))
        .zip(1..=WEDGE_ROUNDS as u64)
        .map(|(text, sequence)| (vec![text], vec![sequence]))
        .collect();
    assert_eq!(rounds, expected);
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "zzz\n");
    Ok(())
}


#[test]
fn an_invalid_utf8_tail_is_quarantined_lossily_and_cut_from_the_claim() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, b"a\nb\n\xff\xfe")?;
    let claimed = claim_spool(&file)?;
    assert_eq!(sent_texts(&claimed), vec!["a".to_owned(), "b".to_owned()]);
    assert_eq!(claimed.sending_bytes, "a\nb\n".len() as u64);
    assert_eq!(fs::read(&claimed.sending)?, b"a\nb\n");
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "\u{fffd}\u{fffd}\n");
    Ok(())
}


#[test]
fn a_claimed_file_that_ends_in_a_newline_or_is_empty_keeps_its_bytes() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::write(dir.path().join("spool.sending"), "a\nb\n")?;
    fs::write(&file.sequence_file, "2 2\n")?;
    let claimed = claim_spool(&file)?;
    assert_eq!(claimed.sending_bytes, "a\nb\n".len() as u64);
    assert!(!dir.path().join("spool.rejected").exists());
    Ok(())
}


#[test]
fn a_torn_tail_in_a_claimed_file_that_cannot_be_locked_is_left_whole_for_the_next_run() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "a\nzzz")?;
    fs::write(&file.sequence_file, "1 1\n")?;
    let mut pauses = 0;
    let deferred = claim_spool_in(&file, load_claimed, 0, &mut || pauses += 1)?;
    assert!(deferred.batches.is_empty());
    assert_eq!(deferred.sending_bytes, u64::MAX);
    assert_eq!(fs::read_to_string(&sending)?, "a\nzzz");
    assert!(!dir.path().join("spool.rejected").exists());
    Ok(())
}


fn stale_claim(delivered: bool) -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&file.spool_file, "1\n")?;
    let mut held = Some(holder(&file.spool_file)?);
    let mut pauses = 0;
    claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut || {
        pauses += 1;
        drop(held.take());
        pause_between_lock_attempts();
        if pauses == 1 {
            logged(claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut pause_between_lock_attempts));
            logged(fs::write(&file.spool_file, "7\n"));
            if delivered {
                logged(fs::remove_file(&sending));
            }
        }
    })?;
    assert_eq!(fs::read_to_string(&file.spool_file)?, "7\n");
    assert_eq!(fs::read_to_string(&file.sequence_file)?, "1 1\n");
    assert_eq!(sending.exists(), !delivered);
    Ok(())
}


#[test]
fn a_claim_that_waited_while_another_claimed_the_spool_defers_and_overwrites_nothing() -> TestResult {
    stale_claim(false)
}


#[test]
fn a_claim_that_waited_while_another_claimed_and_delivered_the_spool_defers_on_the_stale_handle() -> TestResult {
    stale_claim(true)
}


#[test]
fn a_locked_current_spool_is_never_renamed_over_an_existing_sending_file() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&file.spool_file, "7\n")?;
    fs::write(&sending, "1\n")?;
    let spool = holder(&file.spool_file)?;
    claim_locked(&file, &sending, &spool)?;
    drop(spool);
    assert_eq!(fs::read_to_string(&sending)?, "1\n");
    assert_eq!(fs::read_to_string(&file.spool_file)?, "7\n");
    assert!(!file.sequence_file.exists());
    Ok(())
}


#[test]
fn an_event_appended_after_a_dead_tail_is_never_glued_onto_it() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, "zzz")?;
    assert!(claim_spool(&file)?.batches.is_empty());
    append_back(std::iter::once(Ok("{\"event\":1}".to_owned())), &file.spool_file)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(sent_texts(&claimed), vec!["{\"event\":1}".to_owned()]);
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "zzz\n");
    Ok(())
}


#[test]
fn an_append_before_each_claim_never_glues_an_event_onto_a_dead_tail() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, "a\nzzz")?;
    let mut sent = Vec::new();
    (0..WEDGE_ROUNDS).try_for_each(|index| -> TestResult {
        append_back(std::iter::once(Ok(format!("event-{index}"))), &file.spool_file)?;
        let claimed = claim_spool(&file)?;
        sent.extend(sent_texts(&claimed).into_iter().zip(sequences(&claimed)));
        finish_spool(&claimed, &sequences(&claimed))?;
        assert!(!claimed.sending.exists());
        Ok(())
    })?;
    let expected: Vec<(String, u64)> = std::iter::once("a".to_owned())
        .chain((0..WEDGE_ROUNDS).map(|index| format!("event-{index}")))
        .zip(1..)
        .collect();
    assert_eq!(sent, expected);
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "zzz\n");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_second_claimer_that_waited_while_the_first_claimed_a_new_file_defers_and_loads_nothing() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "one\n")?;
    fs::write(&file.sequence_file, "1 1\n")?;
    let mut held = Some(holder(&sending)?);
    let mut pauses = 0;
    let deferred = claim_spool_in(&file, load_claimed, WAIT_ATTEMPTS, &mut || {
        pauses += 1;
        held.take().into_iter().for_each(|lock| {
            drop(lock);
            logged(fs::remove_file(&sending));
            logged(fs::write(&file.spool_file, "two\n"));
            logged(claim_fresh_with(&file, &sending, WAIT_ATTEMPTS, &mut pause_between_lock_attempts));
        });
        pause_between_lock_attempts();
    })?;
    assert!(pauses >= 1);
    assert!(deferred.batches.is_empty());
    assert_eq!(deferred.sending_bytes, u64::MAX);
    assert_eq!(fs::read_to_string(&sending)?, "two\n");
    assert_eq!(fs::read_to_string(&file.sequence_file)?, "2 1\n");
    finish_spool(&deferred, &[])?;
    assert_eq!(fs::read_to_string(&sending)?, "two\n");
    let next = claim_spool(&file)?;
    assert_eq!(sent_texts(&next), vec!["two".to_owned()]);
    assert_eq!(sequences(&next), vec![SECOND_SEQUENCE]);
    Ok(())
}


#[test]
fn finish_never_removes_a_claimed_file_that_a_later_claim_replaced() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let sending = dir.path().join("spool.sending");
    fs::write(&file.spool_file, "one\n")?;
    let loaded = claim_spool(&file)?;
    assert_eq!(sent_texts(&loaded), vec!["one".to_owned()]);
    finish_spool(&loaded.clone(), &[1])?;
    assert!(!sending.exists());
    append_back(std::iter::once(Ok("two".to_owned())), &file.spool_file)?;
    let rival = claim_spool(&file)?;
    assert_eq!(sent_texts(&rival), vec!["two".to_owned()]);
    assert_eq!(fs::metadata(&sending)?.len(), loaded.sending_bytes);
    finish_spool(&loaded, &[1])?;
    assert_eq!(fs::read_to_string(&sending)?, "two\n");
    finish_spool(&rival, &[SECOND_SEQUENCE])?;
    assert!(!sending.exists());
    Ok(())
}


#[test]
fn a_claimed_file_that_cannot_be_opened_fails_the_claim() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    fs::create_dir(dir.path().join("spool.sending"))?;
    assert!(claim_spool(&file).is_err());
    Ok(())
}

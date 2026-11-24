use crate::types::TestResult;
use core_audit::log::open_file_log;
use relay::app::{lock_audit, lock_error, open_runtime, open_runtime_with, same_inode};
use relay::audit::{append_entry, lifecycle_entry, START_ACTION};
use relay::error::RelayError;
use relay::model::Paths;
use rustix::io::Errno;
use std::io;
use std::path::Path;
use std::sync::Barrier;


const HUGE_SOFT: u64 = u64::MAX;


const EXPECTED_AUDIT_LINES: usize = 2;


const SETTINGS_TEXT: &str = "listen: 127.0.0.1:443\nupstream: 127.0.0.1:8443\n";


const RELAYS_STARTING_TOGETHER: usize = 2;


const START_ROUNDS: usize = 20;


fn paths_in(dir: &Path) -> Result<Paths, io::Error> {
    let settings = dir.join("relay.yaml");
    std::fs::write(&settings, SETTINGS_TEXT)?;
    Ok(Paths {
        settings,
        audit: dir.join("audit.log"),
    })
}


fn audit_lines(path: &Path) -> Result<usize, io::Error> {
    Ok(std::fs::read_to_string(path)?.lines().count())
}


#[test]
fn a_relay_whose_lock_is_delayed_until_the_other_stopped_continues_from_the_current_head() -> TestResult {
    let dir = tempfile::tempdir()?;
    let paths = paths_in(dir.path())?;
    let first = std::cell::RefCell::new(Some(open_runtime(&paths, HUGE_SOFT)?));
    let delayed_lock = |file: &std::fs::File| {
        if let Some(runtime) = first.borrow_mut().take() {
            let entry = lifecycle_entry(Path::new("relay.yaml"), "relay.stop", &[]);
            drop(append_entry(&runtime.log, entry));
        }
        lock_audit(file)
    };
    let second = open_runtime_with(&paths, HUGE_SOFT, &delayed_lock)?;
    append_entry(&second.log, lifecycle_entry(Path::new("relay.yaml"), START_ACTION, &[]))?;
    drop(second);
    assert!(first.borrow().is_none());
    assert_eq!(audit_lines(&paths.audit)?, EXPECTED_AUDIT_LINES);
    open_file_log(&paths.audit)?;
    Ok(())
}


#[test]
fn a_relay_started_while_the_other_still_runs_is_refused_locked() -> TestResult {
    let dir = tempfile::tempdir()?;
    let paths = paths_in(dir.path())?;
    let first = open_runtime(&paths, HUGE_SOFT)?;
    let refused = open_runtime_with(&paths, HUGE_SOFT, &lock_audit)
        .err()
        .ok_or("the second start was accepted")?;
    assert!(matches!(refused, RelayError::AuditLocked(_)));
    assert!(refused.to_string().contains("held by another relay"));
    drop(first);
    Ok(())
}


#[test]
fn only_would_block_is_another_relay_and_every_other_errno_is_named_apart() -> TestResult {
    let busy = lock_error(Errno::WOULDBLOCK);
    assert!(matches!(busy, RelayError::AuditLocked(_)));
    let no_locks = lock_error(Errno::NOLCK);
    assert!(matches!(no_locks, RelayError::AuditLockFailed(_)));
    assert!(no_locks.to_string().contains("could not be locked"));
    assert!(!no_locks.to_string().contains("held by another relay"));
    Ok(())
}


#[test]
fn a_log_replaced_between_the_open_and_the_lock_is_refused_by_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let paths = paths_in(dir.path())?;
    let audit = paths.audit.clone();
    let moved = dir.path().join("moved.log");
    let replaced = |file: &std::fs::File| {
        drop(std::fs::rename(&audit, &moved));
        drop(std::fs::write(&audit, b""));
        lock_audit(file)
    };
    let refused = open_runtime_with(&paths, HUGE_SOFT, &replaced)
        .err()
        .ok_or("the replaced log was accepted")?;
    assert!(matches!(refused, RelayError::AuditReplaced));
    assert!(refused.to_string().contains("replaced"));
    Ok(())
}


#[test]
fn a_log_whose_name_is_gone_after_the_lock_is_an_io_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = std::fs::File::create(dir.path().join("held.log"))?;
    let missing = same_inode(&file, &dir.path().join("absent.log"));
    assert!(matches!(missing, Err(RelayError::Io(_))));
    Ok(())
}


#[test]
fn two_relays_starting_together_on_a_missing_log_leave_one_winner_and_a_named_loser() -> TestResult {
    (0..START_ROUNDS).try_for_each(|_| {
        let dir = tempfile::tempdir()?;
        let paths = paths_in(dir.path())?;
        let barrier = Barrier::new(RELAYS_STARTING_TOGETHER);
        let results = std::thread::scope(|scope| {
            let starts: Vec<_> = (0..RELAYS_STARTING_TOGETHER)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        open_runtime(&paths, HUGE_SOFT)
                    })
                })
                .collect();
            starts.into_iter().map(|start| start.join()).collect::<Vec<_>>()
        });
        let started = results.iter().filter(|result| matches!(result, Ok(Ok(_)))).count();
        let named = results
            .iter()
            .filter(|result| matches!(result, Ok(Err(RelayError::AuditLocked(_) | RelayError::Audit(_)))))
            .count();
        assert_eq!(started, 1);
        assert_eq!(named, 1);
        Ok(())
    })
}

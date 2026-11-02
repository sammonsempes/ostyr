#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log, head, new_log, no_sync, open_file_log};
use core_audit::model::GENESIS_HASH;
use core_audit::verify::verify;
use failing_writer::FailingWriter;
use sample::entry;
use std::fs;
use std::io::{self, BufReader};
use std::sync::Arc;
use std::thread;
use types::TestResult;


const THREADS: usize = 8;


const APPENDS_PER_THREAD: usize = 25;


const FILE_RECORDS: usize = 3;


fn failing_sync(_writer: &mut Vec<u8>) -> io::Result<()> {
    Err(io::Error::other("injected sync failure"))
}


#[test]
fn write_failure_keeps_the_head() -> TestResult {
    let log = genesis_log(FailingWriter {
        fail_write: true,
        fail_flush: false,
    });
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert_eq!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn flush_failure_keeps_the_head() -> TestResult {
    let log = genesis_log(FailingWriter {
        fail_write: false,
        fail_flush: true,
    });
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert_eq!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn sync_failure_keeps_the_head() -> TestResult {
    let log = new_log(Vec::new(), GENESIS_HASH, failing_sync);
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert_eq!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn successful_sync_function_is_called() -> TestResult {
    let log = new_log(Vec::new(), GENESIS_HASH, no_sync);
    append(&log, entry(0)?)?;
    assert_ne!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn concurrent_appenders_produce_one_valid_chain() -> TestResult {
    let log = Arc::new(genesis_log(Vec::new()));
    thread::scope(|scope| {
        (0..THREADS).for_each(|worker| {
            let shared = Arc::clone(&log);
            scope.spawn(move || {
                (0..APPENDS_PER_THREAD).for_each(|index| {
                    if let Ok(new) = entry(worker * APPENDS_PER_THREAD + index) {
                        assert!(append(&shared, new).is_ok());
                    }
                });
            });
        });
    });
    let state = Arc::try_unwrap(log).map_err(|_| "log still shared")?.state.into_inner()?;
    let report = verify(state.writer.as_slice(), Some(&state.head))?;
    assert_eq!(report.records, THREADS * APPENDS_PER_THREAD);
    Ok(())
}


#[test]
fn file_log_persists_and_continues_the_chain() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    let first = open_file_log(&path)?;
    (0..FILE_RECORDS).try_for_each(|index| {
        entry(index)
            .map_err(|error| error.to_string())
            .and_then(|new| append(&first, new).map(|_| ()).map_err(|error| error.to_string()))
    })?;
    let first_head = head(&first);
    drop(first);
    let second = open_file_log(&path)?;
    assert_eq!(head(&second), first_head);
    append(&second, entry(FILE_RECORDS)?)?;
    let report = verify(BufReader::new(fs::File::open(&path)?), Some(&head(&second)))?;
    assert_eq!(report.records, FILE_RECORDS + 1);
    Ok(())
}


#[test]
fn file_log_refuses_a_tampered_file_and_a_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    fs::write(&path, "garbage\n")?;
    assert!(matches!(open_file_log(&path), Err(AuditError::Broken { line: 1, .. })));
    assert!(matches!(open_file_log(dir.path()), Err(AuditError::Io(_))));
    Ok(())
}

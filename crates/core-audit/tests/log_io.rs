#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/partial_writer.rs"]
mod partial_writer;
#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log, head, new_log, no_sync, open_file_log};
use core_audit::model::GENESIS_HASH;
use core_audit::verify::verify;
use failing_writer::FailingWriter;
use partial_writer::PartialWriter;
use sample::entry;
use std::fs;
use std::io::{self, BufReader};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;
use types::TestResult;


const THREADS: usize = 8;


const APPENDS_PER_THREAD: usize = 25;


const FILE_RECORDS: usize = 3;


#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;


#[cfg(unix)]
const MODE_MASK: u32 = 0o777;


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


#[cfg(unix)]
fn owner_only(path: &std::path::Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY_MODE))
}


#[cfg(not(unix))]
fn owner_only(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}


#[test]
fn file_log_refuses_a_tampered_file_and_a_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    fs::write(&path, "garbage\n")?;
    owner_only(&path)?;
    assert!(matches!(open_file_log(&path), Err(AuditError::Broken { line: 1, .. })));
    assert!(matches!(open_file_log(dir.path()), Err(AuditError::Io(_))));
    Ok(())
}


#[test]
fn failed_sync_poisons_the_handle() -> TestResult {
    let log = new_log(Vec::new(), GENESIS_HASH, failing_sync);
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert!(matches!(append(&log, entry(1)?), Err(AuditError::LogPoisoned)));
    assert_eq!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn partial_write_poisons_the_handle() -> TestResult {
    let log = genesis_log(PartialWriter::default());
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert!(matches!(append(&log, entry(1)?), Err(AuditError::LogPoisoned)));
    let state = log.state.into_inner()?;
    assert!(!state.writer.written.is_empty());
    Ok(())
}


#[test]
fn flush_failure_poisons_the_handle() -> TestResult {
    let log = genesis_log(FailingWriter {
        fail_write: false,
        fail_flush: true,
    });
    assert!(append(&log, entry(0)?).is_err());
    assert!(matches!(append(&log, entry(1)?), Err(AuditError::LogPoisoned)));
    Ok(())
}


#[test]
#[cfg(unix)]
fn file_log_is_created_owner_only() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & MODE_MASK, OWNER_ONLY_MODE);
    Ok(())
}


#[derive(Debug)]
pub struct PanickingWriter;


impl io::Write for PanickingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        std::panic::resume_unwind(Box::new("injected writer panic"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn panic_mid_write_poisons_the_mutex_and_refuses_appends() -> TestResult {
    let log = genesis_log(PanickingWriter);
    let first_entry = entry(0)?;
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| append(&log, first_entry)));
    assert!(first.is_err());
    assert!(matches!(append(&log, entry(1)?), Err(AuditError::LogPoisoned)));
    Ok(())
}


#[cfg(unix)]
const WIDE_MODE: u32 = 0o640;


#[test]
#[cfg(unix)]
fn file_log_refuses_group_or_other_access() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    fs::write(&path, "")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(WIDE_MODE))?;
    assert!(matches!(open_file_log(&path), Err(AuditError::InsecurePermissions { mode: WIDE_MODE })));
    fs::set_permissions(&path, fs::Permissions::from_mode(OWNER_ONLY_MODE))?;
    assert!(open_file_log(&path).is_ok());
    Ok(())
}

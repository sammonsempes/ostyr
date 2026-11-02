use crate::canonical::{render_line, seal};
use crate::error::AuditError;
use crate::model::{NewEntry, Record, GENESIS_HASH};
use crate::verify::verify;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::sync::{Mutex, PoisonError};


#[derive(Debug)]
pub struct LogState<Output> {
    pub writer: Output,
    pub head: String,
}


/// One handle per log, shared by reference or `Arc`; the mutex serialises appenders.
#[derive(Debug)]
pub struct AuditLog<Output> {
    pub state: Mutex<LogState<Output>>,
    pub sync: fn(&mut Output) -> io::Result<()>,
}


pub fn no_sync<Output>(_writer: &mut Output) -> io::Result<()> {
    Ok(())
}


pub fn sync_file(file: &mut File) -> io::Result<()> {
    file.sync_all()
}


/// A log that starts after `head` (`GENESIS_HASH` for a new log).
pub fn new_log<Output: Write>(writer: Output, head: &str, sync: fn(&mut Output) -> io::Result<()>) -> AuditLog<Output> {
    AuditLog {
        state: Mutex::new(LogState {
            writer,
            head: head.to_owned(),
        }),
        sync,
    }
}


pub fn genesis_log<Output: Write>(writer: Output) -> AuditLog<Output> {
    new_log(writer, GENESIS_HASH, no_sync)
}


/// Opens (creating if needed) an append-only file, verifies its existing chain and continues it.
pub fn open_file_log(path: &Path) -> Result<AuditLog<File>, AuditError> {
    let file = OpenOptions::new().read(true).append(true).create(true).open(path)?;
    let report = verify(BufReader::new(&file), None)?;
    Ok(new_log(file, &report.head, sync_file))
}


/// Chains, writes, flushes and syncs one record; the head only advances once the whole line is durable.
pub fn append<Output: Write>(log: &AuditLog<Output>, entry: NewEntry) -> Result<Record, AuditError> {
    let mut state = log.state.lock().unwrap_or_else(PoisonError::into_inner);
    let record = seal(entry, &state.head)?;
    state.writer.write_all(render_line(&record).as_bytes())?;
    state.writer.flush()?;
    (log.sync)(&mut state.writer)?;
    state.head.clone_from(&record.hash);
    Ok(record)
}


pub fn head<Output: Write>(log: &AuditLog<Output>) -> String {
    log.state.lock().unwrap_or_else(PoisonError::into_inner).head.clone()
}

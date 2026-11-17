use crate::follow::file_len;
use crate::types::SpoolLock;
use agent_channel::spool::append_back;
use std::io;
use std::path::Path;


/// `append_back` under the process-wide spool lock: one writer at a time, each call's lines written in one `write`.
pub fn append_locked(lock: &SpoolLock, lines: impl Iterator<Item = io::Result<String>>, spool: &Path) -> io::Result<bool> {
    let _writer = lock.lock();
    append_back(lines, spool)
}


/// Under the lock, appends the lines only when the spool and the sending file plus the lines stay within `max_bytes`; `false` writes nothing. No line is always fine.
pub fn append_within(lock: &SpoolLock, spool: &Path, sending: &Path, max_bytes: u64, lines: &[String]) -> io::Result<bool> {
    let _writer = lock.lock();
    let pending = file_len(spool)?.saturating_add(file_len(sending)?);
    let bytes: u64 = lines.iter().map(|line| line.len() as u64 + 1).sum();
    if bytes > 0 && pending.saturating_add(bytes) > max_bytes {
        Ok(false)
    } else {
        append_back(lines.iter().cloned().map(Ok), spool).map(|_| true)
    }
}

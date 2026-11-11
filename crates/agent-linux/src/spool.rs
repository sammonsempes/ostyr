use crate::types::SpoolLock;
use agent_channel::spool::append_back;
use std::io;
use std::path::Path;


/// `append_back` under the process-wide spool lock: one writer at a time, each call's lines written in one `write`.
pub fn append_locked(lock: &SpoolLock, lines: impl Iterator<Item = io::Result<String>>, spool: &Path) -> io::Result<bool> {
    let _writer = lock.lock();
    append_back(lines, spool)
}

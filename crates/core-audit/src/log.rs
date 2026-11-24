use crate::canonical::{render_line, restrict_parameters, seal};
use crate::error::AuditError;
use crate::model::{NewEntry, Record, GENESIS_HASH};
use crate::types::Slot;
#[cfg(unix)]
use crate::types::{FactsReader, Reopener};
use crate::verify::{verify, MAX_RECORD_BYTES};
#[cfg(unix)]
use rustix::fs::{fstat, openat, statat, unlinkat, AtFlags, Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError};


#[derive(Debug)]
pub struct LogState<Output> {
    pub writer: Output,
    pub head: String,
    pub poisoned: bool,
}


/// What a queued entry's caller waits for: its outcome, or the token that makes it the next leader.
#[derive(Debug, Default)]
pub struct SlotState {
    pub outcome: Option<Result<Record, AuditError>>,
    pub promoted: bool,
}


/// Where a queued entry's outcome is left, with a signal for the caller that waits for it.
#[derive(Debug, Default)]
pub struct SlotCell {
    pub state: Mutex<SlotState>,
    pub ready: Condvar,
}


/// An entry waiting for the next group commit, and the slot its caller reads the outcome from.
#[derive(Debug)]
pub struct Pending {
    pub entry: NewEntry,
    pub slot: Slot,
}


/// One handle per log, shared by reference or `Arc`; the mutex serialises writers and `pending` queues the entries of the next group commit.
#[derive(Debug)]
pub struct AuditLog<Output> {
    pub state: Mutex<LogState<Output>>,
    pub sync: fn(&mut Output) -> io::Result<()>,
    pub pending: Mutex<Vec<Pending>>,
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
            poisoned: false,
        }),
        sync,
        pending: Mutex::new(Vec::new()),
    }
}


pub fn genesis_log<Output: Write>(writer: Output) -> AuditLog<Output> {
    new_log(writer, GENESIS_HASH, no_sync)
}


pub const LOG_FILE_MODE: u32 = 0o600;


pub const GROUP_OTHER_MASK: u32 = 0o077;


#[cfg(unix)]
pub fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    options.mode(LOG_FILE_MODE)
}


#[cfg(not(unix))]
pub fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    options
}


#[cfg(unix)]
pub fn check_private(file: &File) -> Result<(), AuditError> {
    file.metadata()
        .map_err(AuditError::Io)
        .and_then(|metadata| private_mode(metadata.permissions().mode()))
}


#[cfg(unix)]
pub fn private_mode(mode: u32) -> Result<(), AuditError> {
    if mode & GROUP_OTHER_MASK == 0 {
        Ok(())
    } else {
        Err(AuditError::InsecurePermissions {
            mode: mode & !FILE_TYPE_MASK,
        })
    }
}


#[cfg(not(unix))]
pub fn check_private(_file: &File) -> Result<(), AuditError> {
    Ok(())
}


#[cfg(unix)]
pub const FILE_TYPE_MASK: u32 = 0o170000;


#[cfg(unix)]
#[derive(Debug)]
pub struct HandleFacts {
    pub regular: bool,
    pub owner: u32,
    pub links: u64,
    pub mode: u32,
}


#[cfg(unix)]
pub fn handle_facts(file: &File) -> io::Result<HandleFacts> {
    file.metadata().map(|metadata| HandleFacts {
        regular: metadata.file_type().is_file(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
    })
}


/// The two system calls of an anchored open, injected so tests can seek the reopened file, fail the reopen or hide /proc.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub struct Opener {
    pub facts: FactsReader,
    pub reopen: Reopener,
    pub proc_fd_dir: &'static str,
}


#[cfg(unix)]
pub const PROC_FD_DIR: &str = "/proc/self/fd";


#[cfg(unix)]
pub const SYSTEM_OPENER: Opener = Opener {
    facts: handle_facts,
    reopen: open_with,
    proc_fd_dir: PROC_FD_DIR,
};


#[cfg(unix)]
pub fn judge_opened(file: File, opener: &Opener) -> Result<File, AuditError> {
    judge_borrowed(&file, opener).map(|()| file)
}


/// Judges a handle the caller keeps, so a refusal can still clean up through it.
#[cfg(unix)]
pub fn judge_borrowed(file: &File, opener: &Opener) -> Result<(), AuditError> {
    (opener.facts)(file)
        .map_err(AuditError::Io)
        .and_then(|facts| judge_handle(&facts, rustix::process::geteuid().as_raw()))
}


#[cfg(unix)]
pub fn judge_handle(facts: &HandleFacts, effective_uid: u32) -> Result<(), AuditError> {
    if !facts.regular {
        Err(AuditError::NotRegularFile)
    } else if facts.owner != effective_uid {
        Err(AuditError::ForeignOwner {
            owner: facts.owner,
            expected: effective_uid,
        })
    } else if facts.links != 1 {
        Err(AuditError::LinkedFile { links: facts.links })
    } else if facts.mode & GROUP_OTHER_MASK != 0 {
        Err(AuditError::InsecurePermissions {
            mode: facts.mode & !FILE_TYPE_MASK,
        })
    } else {
        Ok(())
    }
}


#[cfg(unix)]
pub fn open_with(path: &Path, flags: OFlags) -> Result<File, AuditError> {
    Ok(rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR)
        .map(File::from)
        .map_err(io::Error::from)?)
}


/// Opens `O_PATH` (no driver `open` runs), judges the anchor by `fstat`, then reopens the regular file through `/proc/self/fd` and judges it again.
#[cfg(unix)]
pub fn open_anchored(path: &Path, flags: OFlags, opener: &Opener) -> Result<File, AuditError> {
    let anchor = open_with(path, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC)?;
    let symlink = anchor.metadata()?.file_type().is_symlink();
    if symlink {
        Err(AuditError::SymlinkRefused)
    } else {
        judge_opened(anchor, opener)
            .and_then(|judged| reopen_through_proc(&judged, flags, opener))
            .and_then(|reopened| judge_opened(reopened, opener))
    }
}


/// A missing `/proc` is a fixed error, never a `NotFound` that `open_checked` would take for a missing log.
#[cfg(unix)]
pub fn reopen_through_proc(anchor: &File, flags: OFlags, opener: &Opener) -> Result<File, AuditError> {
    (opener.reopen)(&Path::new(opener.proc_fd_dir).join(anchor.as_raw_fd().to_string()), flags).map_err(|error| match error {
        AuditError::Io(cause) if cause.kind() == io::ErrorKind::NotFound => AuditError::ProcUnavailable,
        other => other,
    })
}


/// Read-only open for verify and export: same anchor, no creation, same judgement of the handle.
#[cfg(unix)]
pub fn open_read_checked(path: &Path) -> Result<File, AuditError> {
    open_read_with(path, &SYSTEM_OPENER)
}


#[cfg(unix)]
pub fn open_read_with(path: &Path, opener: &Opener) -> Result<File, AuditError> {
    open_anchored(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC, opener)
}


#[cfg(not(unix))]
pub fn open_read_checked(path: &Path) -> Result<File, AuditError> {
    Ok(File::open(path)?)
}


/// Creates a new file exclusively below a held parent directory, then reopens and judges it like an existing log.
#[cfg(unix)]
pub fn create_new(path: &Path, opener: &Opener) -> Result<File, AuditError> {
    refuse_directory_form(path)?;
    let anchored = Path::new(".").join(path);
    let (directory, leaf) = anchored
        .parent()
        .zip(anchored.file_name())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    open_with(directory, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC)
        .map(OwnedFd::from)
        .and_then(|parent| create_below(&parent, leaf, opener))
}


/// A name ending in `/` or `/.` names a directory: refused before any I/O, so the first and the next start agree.
#[cfg(unix)]
pub fn refuse_directory_form(path: &Path) -> Result<(), AuditError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
        Err(AuditError::Io(io::Error::from(io::ErrorKind::InvalidInput)))
    } else {
        Ok(())
    }
}


/// Every failure after the exclusive create removes the new name (below the same held directory) and keeps the first error.
#[cfg(unix)]
pub fn create_below(parent: &OwnedFd, leaf: &OsStr, opener: &Opener) -> Result<File, AuditError> {
    let flags =
        OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let created = openat(parent, leaf, flags, Mode::RUSR | Mode::WUSR)
        .map(File::from)
        .map_err(io::Error::from)?;
    judge_borrowed(&created, opener)
        .and_then(|()| reopen_created(&created, opener))
        .or_else(|error| first_error(error, remove_if_same(parent, leaf, &created)))
}


/// Reopens the created file through `/proc` and judges the reopened handle.
#[cfg(unix)]
pub fn reopen_created(created: &File, opener: &Opener) -> Result<File, AuditError> {
    reopen_through_proc(
        created,
        OFlags::RDWR | OFlags::APPEND | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        opener,
    )
    .and_then(|reopened| judge_opened(reopened, opener))
}


/// The error that started the cleanup stays the error; a failed cleanup is only logged.
#[cfg(unix)]
pub fn first_error(error: AuditError, cleanup: Result<(), Errno>) -> Result<File, AuditError> {
    cleanup.err().iter().for_each(log_cleanup_failure);
    Err(error)
}


/// Logs that a new log name could not be removed.
#[cfg(unix)]
pub fn log_cleanup_failure(errno: &Errno) {
    let reason = errno.to_string();
    tracing::warn!(reason, "new audit log not removed");
}


/// Unlinks the name below the held parent only when it still is the inode of the handle.
#[cfg(unix)]
pub fn remove_if_same(parent: &OwnedFd, leaf: &OsStr, created: &File) -> Result<(), Errno> {
    fstat(created)
        .and_then(|held| statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map(|named| (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)))
        .and_then(|same| if same { unlinkat(parent, leaf, AtFlags::empty()) } else { Ok(()) })
}


/// A new log is created only where `/proc` is usable, so a host without it fails the same way on the first and the next start.
#[cfg(unix)]
pub fn create_after_proc_check(path: &Path, opener: &Opener) -> Result<File, AuditError> {
    if Path::new(opener.proc_fd_dir).is_dir() {
        create_new(path, opener)
    } else {
        Err(AuditError::ProcUnavailable)
    }
}


#[cfg(unix)]
pub fn open_checked(path: &Path, opener: &Opener) -> Result<File, AuditError> {
    match open_anchored(
        path,
        OFlags::RDWR | OFlags::APPEND | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        opener,
    ) {
        Err(AuditError::Io(error)) if error.kind() == io::ErrorKind::NotFound => create_after_proc_check(path, opener),
        other => other,
    }
}


#[cfg(not(unix))]
pub fn open_checked(path: &Path) -> Result<File, AuditError> {
    Ok(owner_only(OpenOptions::new().read(true).append(true).create(true)).open(path)?)
}


/// Opens (creating if needed) an append-only file without following a link or blocking, judges the handle, verifies its chain and continues it.
#[cfg(unix)]
pub fn open_file_log(path: &Path) -> Result<AuditLog<File>, AuditError> {
    open_file_log_with(path, &SYSTEM_OPENER)
}


#[cfg(unix)]
pub fn open_file_log_with(path: &Path, opener: &Opener) -> Result<AuditLog<File>, AuditError> {
    open_checked(path, opener).and_then(continue_log)
}


#[cfg(not(unix))]
pub fn open_file_log(path: &Path) -> Result<AuditLog<File>, AuditError> {
    open_checked(path).and_then(continue_log)
}


pub fn continue_log(file: File) -> Result<AuditLog<File>, AuditError> {
    let report = verify(BufReader::new(&file), None)?;
    Ok(new_log(file, &report.head, sync_file))
}


pub const MAX_GROUP_RECORDS: usize = 256;


pub const MAX_LEAD_ROUNDS: usize = 1_000_000;


/// Queues the entry; whoever holds the writer lock seals, writes and syncs a group of queued entries once. Returns only after the sync covering this record.
pub fn append<Output: Write>(log: &AuditLog<Output>, entry: NewEntry) -> Result<Record, AuditError> {
    let slot: Slot = Arc::new(SlotCell::default());
    log.pending.lock().map_err(|_| AuditError::LogPoisoned)?.push(Pending {
        entry,
        slot: Arc::clone(&slot),
    });
    match log.state.try_lock() {
        Ok(state) => lead(log, state, &slot),
        Err(TryLockError::Poisoned(_)) => poisoned_outcome(log, &slot),
        Err(TryLockError::WouldBlock) => follow(log, &slot),
    }
}


/// Waits with no timeout for the leader to fill the slot; a promoted follower takes the writer lock and leads the next groups.
pub fn follow<Output: Write>(log: &AuditLog<Output>, slot: &Slot) -> Result<Record, AuditError> {
    match await_slot(slot) {
        Some(outcome) => outcome,
        None => match log.state.lock() {
            Ok(state) => lead(log, state, slot),
            Err(_) => poisoned_outcome(log, slot),
        },
    }
}


/// Flushes groups until the leader's own entry is answered, then hands the lead to the oldest entry still queued.
pub fn lead<Output: Write>(log: &AuditLog<Output>, mut state: MutexGuard<'_, LogState<Output>>, slot: &Slot) -> Result<Record, AuditError> {
    (0..MAX_LEAD_ROUNDS).any(|_| {
        flush_group(log, &mut state);
        answered(slot)
    });
    drop(state);
    hand_off(log);
    wait_outcome(slot)
}


pub fn answered(slot: &Slot) -> bool {
    slot.state.lock().unwrap_or_else(PoisonError::into_inner).outcome.is_some()
}


/// Wakes the oldest queued entry's caller to lead: an entry queued after the last leader took its group is never left without one.
pub fn hand_off<Output>(log: &AuditLog<Output>) {
    let queue = log.pending.lock().unwrap_or_else(PoisonError::into_inner);
    queue.first().iter().for_each(|pending| promote(&pending.slot));
}


pub fn promote(slot: &Slot) {
    slot.state.lock().unwrap_or_else(PoisonError::into_inner).promoted = true;
    slot.ready.notify_all();
}


/// A panicked writer lock: every queued entry is refused, the entry in the dead leader's group was refused by its guard.
pub fn poisoned_outcome<Output>(log: &AuditLog<Output>, slot: &Slot) -> Result<Record, AuditError> {
    fail_pending(log);
    wait_outcome(slot)
}


pub fn fail_pending<Output>(log: &AuditLog<Output>) {
    let queue: Vec<Pending> = log.pending.lock().unwrap_or_else(PoisonError::into_inner).drain(..).collect();
    queue.iter().for_each(|pending| fill_slot(&pending.slot, Err(AuditError::LogPoisoned)));
}


/// Refuses the group's callers when the leader panics inside the writer, so no follower waits for an answer that cannot come.
pub struct InFlight<'log, Output> {
    pub log: &'log AuditLog<Output>,
    pub slots: Vec<Slot>,
}


impl<Output> Drop for InFlight<'_, Output> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.slots.iter().for_each(|slot| fill_slot(slot, Err(AuditError::LogPoisoned)));
            fail_pending(self.log);
        }
    }
}


/// `Some(outcome)` once the entry is answered, `None` when the caller is promoted to lead; no timeout, the leader notifies the slot.
pub fn await_slot(slot: &Slot) -> Option<Result<Record, AuditError>> {
    let guard = slot.state.lock().unwrap_or_else(PoisonError::into_inner);
    let mut waited = slot
        .ready
        .wait_while(guard, |state| state.outcome.is_none() && !state.promoted)
        .unwrap_or_else(PoisonError::into_inner);
    if waited.promoted {
        waited.promoted = false;
        None
    } else {
        Some(waited.outcome.take().unwrap_or(Err(AuditError::LogPoisoned)))
    }
}


/// The entry's outcome, once a leader or a poisoned-log refusal has left one.
pub fn wait_outcome(slot: &Slot) -> Result<Record, AuditError> {
    let guard = slot.state.lock().unwrap_or_else(PoisonError::into_inner);
    let mut waited = slot
        .ready
        .wait_while(guard, |state| state.outcome.is_none())
        .unwrap_or_else(PoisonError::into_inner);
    waited.outcome.take().unwrap_or(Err(AuditError::LogPoisoned))
}


pub fn take_outcome(slot: &Slot) -> Option<Result<Record, AuditError>> {
    slot.state.lock().unwrap_or_else(PoisonError::into_inner).outcome.take()
}


pub fn fill_slot(slot: &Slot, outcome: Result<Record, AuditError>) {
    slot.state.lock().unwrap_or_else(PoisonError::into_inner).outcome = Some(outcome);
    slot.ready.notify_all();
}


pub fn take_group<Output>(log: &AuditLog<Output>) -> Vec<Pending> {
    let mut queue = log.pending.lock().unwrap_or_else(PoisonError::into_inner);
    let count = queue.len().min(MAX_GROUP_RECORDS);
    queue.drain(..count).collect()
}


/// Seals each queued entry against the file it lands in, writes the lines, then syncs once for the whole group.
pub fn flush_group<Output: Write>(log: &AuditLog<Output>, state: &mut MutexGuard<'_, LogState<Output>>) {
    let group = take_group(log);
    let in_flight = InFlight {
        log,
        slots: group.iter().map(|pending| Arc::clone(&pending.slot)).collect(),
    };
    if state.poisoned {
        group.iter().for_each(|pending| fill_slot(&pending.slot, Err(AuditError::LogPoisoned)));
    } else {
        commit_group(log.sync, state, group);
    }
    drop(in_flight);
}


pub fn commit_group<Output: Write>(sync: fn(&mut Output) -> io::Result<()>, state: &mut LogState<Output>, group: Vec<Pending>) {
    let mut head = state.head.clone();
    let mut written: Vec<(Slot, Record)> = Vec::new();
    let mut failure: Option<io::Error> = None;
    group.into_iter().for_each(|pending| match &failure {
        Some(error) => fill_slot(&pending.slot, Err(group_failure(error))),
        None => match seal_checked(pending.entry, &head) {
            Err(error) => fill_slot(&pending.slot, Err(error)),
            Ok((record, line)) => match write_line(&mut state.writer, &line) {
                Ok(()) => {
                    head.clone_from(&record.hash);
                    written.push((pending.slot, record));
                }
                Err(error) => {
                    fill_slot(&pending.slot, Err(group_failure(&error)));
                    failure = Some(error);
                }
            },
        },
    });
    let synced = if failure.is_none() && !written.is_empty() {
        sync(&mut state.writer)
    } else {
        Ok(())
    };
    match failure.or(synced.err()) {
        None => {
            state.head = head;
            written.into_iter().for_each(|(slot, record)| fill_slot(&slot, Ok(record)));
        }
        Some(error) => {
            state.poisoned = true;
            written.iter().for_each(|(slot, _)| fill_slot(slot, Err(group_failure(&error))));
        }
    }
}


pub fn write_line<Output: Write>(writer: &mut Output, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.flush()
}


/// Every caller of a failed group gets its own error with the failure's kind and text.
pub fn group_failure(error: &io::Error) -> AuditError {
    AuditError::Io(io::Error::new(error.kind(), error.to_string()))
}


/// Seals the entry and refuses a stored line over `MAX_RECORD_BYTES`, which `verify` could not read back.
pub fn seal_checked(entry: NewEntry, head: &str) -> Result<(Record, String), AuditError> {
    let record = seal(entry, head)?;
    let line = render_line(&record);
    if line.len() > MAX_RECORD_BYTES {
        Err(AuditError::RecordTooLarge {
            size: line.len(),
            max: MAX_RECORD_BYTES,
        })
    } else {
        Ok((record, line))
    }
}


pub const MAX_PARAMETERS: usize = 64;


pub const MAX_KEY_BYTES: usize = 128;


/// Undeclared values become `[REDACTED]`; over `MAX_PARAMETERS` parameters or a key over `MAX_KEY_BYTES` is refused.
pub fn append_declared<Output: Write>(log: &AuditLog<Output>, entry: NewEntry, declared: &[&str]) -> Result<Record, AuditError> {
    if entry.parameters.len() > MAX_PARAMETERS {
        Err(AuditError::TooManyParameters {
            count: entry.parameters.len(),
            max: MAX_PARAMETERS,
        })
    } else if let Some(key) = entry.parameters.keys().find(|key| key.len() > MAX_KEY_BYTES) {
        Err(AuditError::KeyTooLong {
            length: key.len(),
            max: MAX_KEY_BYTES,
        })
    } else {
        append_restricted(log, entry, declared)
    }
}


fn append_restricted<Output: Write>(log: &AuditLog<Output>, entry: NewEntry, declared: &[&str]) -> Result<Record, AuditError> {
    let parameters = restrict_parameters(entry.parameters, declared);
    append(log, NewEntry { parameters, ..entry })
}


pub fn head<Output: Write>(log: &AuditLog<Output>) -> String {
    log.state.lock().unwrap_or_else(PoisonError::into_inner).head.clone()
}

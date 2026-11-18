use crate::canonical::{render_line, restrict_parameters, seal};
use crate::error::AuditError;
use crate::model::{NewEntry, Record, GENESIS_HASH};
#[cfg(unix)]
use crate::types::{FactsReader, Reopener};
use crate::verify::{verify, MAX_RECORD_BYTES};
#[cfg(unix)]
use rustix::fs::{fstat, statat, unlinkat, AtFlags, Mode, OFlags, CWD};
#[cfg(unix)]
use rustix::io::Errno;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, PoisonError};


#[derive(Debug)]
pub struct LogState<Output> {
    pub writer: Output,
    pub head: String,
    pub poisoned: bool,
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
            poisoned: false,
        }),
        sync,
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
    (opener.facts)(&file)
        .map_err(AuditError::Io)
        .and_then(|facts| judge_handle(&facts, rustix::process::geteuid().as_raw()))
        .map(|()| file)
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


/// Creates a new file exclusively (a name that does not exist yet cannot be a device or a link), then reopens and judges it like an existing log.
#[cfg(unix)]
pub fn create_new(path: &Path, opener: &Opener) -> Result<File, AuditError> {
    let flags =
        OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    open_with(path, flags)
        .and_then(|file| judge_opened(file, opener))
        .and_then(|created| reopen_created(path, created, opener))
}


/// A failed reopen of a new log removes the new name (only while it is still the created inode) and keeps the reopen error.
#[cfg(unix)]
pub fn reopen_created(path: &Path, created: File, opener: &Opener) -> Result<File, AuditError> {
    reopen_through_proc(
        &created,
        OFlags::RDWR | OFlags::APPEND | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        opener,
    )
    .and_then(|reopened| judge_opened(reopened, opener))
    .or_else(|error| first_error(error, remove_if_same(path, &created)))
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


/// Unlinks the name only when it still is the inode of the handle.
#[cfg(unix)]
pub fn remove_if_same(path: &Path, created: &File) -> Result<(), Errno> {
    fstat(created)
        .and_then(|held| statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map(|named| (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)))
        .and_then(|same| if same { unlinkat(CWD, path, AtFlags::empty()) } else { Ok(()) })
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


pub fn write_durably<Output: Write>(writer: &mut Output, sync: fn(&mut Output) -> io::Result<()>, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.flush()?;
    sync(writer)
}


/// Chains, writes, flushes and syncs one record; the head only advances once the whole line is durable.
pub fn append<Output: Write>(log: &AuditLog<Output>, entry: NewEntry) -> Result<Record, AuditError> {
    let mut state = log.state.lock().map_err(|_| AuditError::LogPoisoned)?;
    if state.poisoned {
        Err(AuditError::LogPoisoned)
    } else {
        let (record, line) = seal_checked(entry, &state.head)?;
        match write_durably(&mut state.writer, log.sync, &line) {
            Ok(()) => {
                state.head.clone_from(&record.hash);
                Ok(record)
            }
            Err(error) => {
                state.poisoned = true;
                Err(AuditError::Io(error))
            }
        }
    }
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

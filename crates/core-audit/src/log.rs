use crate::canonical::{render_line, restrict_parameters, seal};
use crate::error::AuditError;
use crate::model::{NewEntry, Record, GENESIS_HASH};
use crate::verify::verify;
#[cfg(unix)]
use rustix::fs::{Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
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
    let mode = file.metadata()?.permissions().mode();
    if mode & GROUP_OTHER_MASK == 0 {
        Ok(())
    } else {
        Err(AuditError::InsecurePermissions {
            mode: mode & !FILE_TYPE_MASK,
        })
    }
}


#[cfg(unix)]
pub const FILE_TYPE_MASK: u32 = 0o170000;


#[cfg(not(unix))]
pub fn check_private(_file: &File) -> Result<(), AuditError> {
    Ok(())
}


pub const MAX_LOG_BYTES: u64 = 1_073_741_824;


#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct HandleFacts {
    pub regular: bool,
    pub owner: u32,
    pub links: u64,
    pub mode: u32,
    pub size: u64,
}


#[cfg(unix)]
pub fn handle_facts(file: &File) -> Result<HandleFacts, AuditError> {
    let metadata = file.metadata()?;
    Ok(HandleFacts {
        regular: metadata.file_type().is_file(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        size: metadata.len(),
    })
}


#[cfg(unix)]
pub fn judge_handle(facts: &HandleFacts, effective_uid: u32, max_bytes: u64) -> Result<(), AuditError> {
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
    } else if facts.size > max_bytes {
        Err(AuditError::LogTooLarge {
            size: facts.size,
            max: max_bytes,
        })
    } else {
        Ok(())
    }
}


#[cfg(unix)]
pub fn open_nonblocking(path: &Path) -> Result<File, AuditError> {
    let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR).map(File::from).map_err(|errno| {
        if errno == Errno::LOOP {
            AuditError::SymlinkRefused
        } else {
            AuditError::Io(errno.into())
        }
    })
}


#[cfg(unix)]
pub fn open_checked(path: &Path, max_bytes: u64) -> Result<File, AuditError> {
    let file = open_nonblocking(path)?;
    judge_handle(&handle_facts(&file)?, rustix::process::geteuid().as_raw(), max_bytes)?;
    Ok(file)
}


#[cfg(not(unix))]
pub fn open_checked(path: &Path, _max_bytes: u64) -> Result<File, AuditError> {
    Ok(owner_only(OpenOptions::new().read(true).append(true).create(true)).open(path)?)
}


/// Opens (creating if needed) an append-only file, verifies its existing chain and continues it.
pub fn open_file_log(path: &Path) -> Result<AuditLog<File>, AuditError> {
    open_file_log_capped(path, MAX_LOG_BYTES)
}


/// The handle is opened without following a link or blocking, judged by `fstat`, and its chain read stops at `max_bytes`.
pub fn open_file_log_capped(path: &Path, max_bytes: u64) -> Result<AuditLog<File>, AuditError> {
    let file = open_checked(path, max_bytes)?;
    let report = verify(BufReader::new((&file).take(max_bytes)), None)?;
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
        let record = seal(entry, &state.head)?;
        match write_durably(&mut state.writer, log.sync, &render_line(&record)) {
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

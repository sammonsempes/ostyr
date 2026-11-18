use crate::canonical::{render_line, restrict_parameters, seal};
use crate::error::AuditError;
use crate::model::{NewEntry, Record, GENESIS_HASH};
use crate::verify::{verify, MAX_RECORD_BYTES};
#[cfg(unix)]
use rustix::fs::{Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufReader, Write};
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
pub fn handle_facts(metadata: &Metadata) -> HandleFacts {
    HandleFacts {
        regular: metadata.file_type().is_file(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
    }
}


#[cfg(unix)]
pub fn judge_opened(file: File) -> Result<File, AuditError> {
    file.metadata()
        .map_err(AuditError::Io)
        .and_then(|metadata| judge_handle(&handle_facts(&metadata), rustix::process::geteuid().as_raw()))
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
pub fn open_nonblocking(path: &Path) -> Result<File, AuditError> {
    let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    open_with(path, flags)
}


#[cfg(unix)]
pub fn open_with(path: &Path, flags: OFlags) -> Result<File, AuditError> {
    rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR).map(File::from).map_err(|errno| {
        if errno == Errno::LOOP {
            AuditError::SymlinkRefused
        } else {
            AuditError::Io(errno.into())
        }
    })
}


/// Read-only open for verify and export: same flags, no creation, same judgement of the handle.
#[cfg(unix)]
pub fn open_read_checked(path: &Path) -> Result<File, AuditError> {
    open_with(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
    )
    .and_then(judge_opened)
}


#[cfg(not(unix))]
pub fn open_read_checked(path: &Path) -> Result<File, AuditError> {
    Ok(File::open(path)?)
}


#[cfg(unix)]
pub fn open_checked(path: &Path) -> Result<File, AuditError> {
    open_nonblocking(path).and_then(judge_opened)
}


#[cfg(not(unix))]
pub fn open_checked(path: &Path) -> Result<File, AuditError> {
    Ok(owner_only(OpenOptions::new().read(true).append(true).create(true)).open(path)?)
}


/// Opens (creating if needed) an append-only file without following a link or blocking, judges the handle, verifies its chain and continues it.
pub fn open_file_log(path: &Path) -> Result<AuditLog<File>, AuditError> {
    let file = open_checked(path)?;
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

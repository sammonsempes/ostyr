//! Reads a FIM input (the role table, `planted.tsv`) only when root owns it and no one else can write it or swap anything above it.

use crate::types::{AfterOpenFn, JudgeFn};
use core_config::error::ConfigError;
use core_config::trusted_dir::{open_trusted_dir, TrustedDirError, GROUP_OTHER_WRITE};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const ROOT_UID: u32 = 0;


pub const NOT_REGULAR: &str = "not a regular file";


pub const NOT_OWNED: &str = "not owned by root or the agent user";


pub const WRITABLE: &str = "writable by group or others";


pub const SYMLINK: &str = "is a symlink";


pub const NO_PARENT: &str = "has no directory or no file name";


pub const DIRECTORY_WRITABLE: &str = "the directory holding this file, or one above it, is writable by group or others";


pub const DIRECTORY_ANCESTOR_NOT_OWNED: &str = "a directory above this file is not owned by root or the agent user";


pub const DIRECTORY_NOT_OWNED: &str = "the directory holding this file is not owned by the agent user";


pub const PATH_NOT_ABSOLUTE: &str = "the path of this file is not absolute";


pub const PATH_NOT_PLAIN: &str = "the path of this file is not a plain canonical path";


const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);


/// The judgement made on the opened handle: a regular file, owned by root or the agent user, not writable by group or others.
pub fn judge_trusted_file(is_file: bool, mode: u32, owner: u32, process_user: u32) -> Result<(), &'static str> {
    if !is_file {
        Err(NOT_REGULAR)
    } else if owner != process_user && owner != ROOT_UID {
        Err(NOT_OWNED)
    } else if mode & GROUP_OTHER_WRITE != 0 {
        Err(WRITABLE)
    } else {
        Ok(())
    }
}


pub fn no_hook(_path: &Path) {}


pub fn refused(file: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.to_owned(),
        reason: reason.to_owned(),
    }
}


pub fn io_error(file: &str, source: std::io::Error) -> ConfigError {
    ConfigError::Io {
        file: file.to_owned(),
        source,
    }
}


/// A directory refusal becomes a fixed wording about the directory of the file.
pub fn directory_reason(reason: &str) -> &'static str {
    if reason.contains("writable") {
        DIRECTORY_WRITABLE
    } else if reason.contains("ancestor is not owned") {
        DIRECTORY_ANCESTOR_NOT_OWNED
    } else if reason.contains("not owned") {
        DIRECTORY_NOT_OWNED
    } else if reason.contains("not absolute") {
        PATH_NOT_ABSOLUTE
    } else {
        PATH_NOT_PLAIN
    }
}


/// A directory refusal keeps a fixed reason; an I/O failure keeps its cause.
pub fn directory_error(file: &str, error: TrustedDirError) -> ConfigError {
    match error {
        TrustedDirError::Refused(reason) => refused(file, directory_reason(reason)),
        TrustedDirError::Io(source) => io_error(file, source),
    }
}


/// An open that failed on a symlink (`ELOOP` under `O_NOFOLLOW`) is a named refusal, anything else keeps its errno.
pub fn open_error(file: &str, errno: Errno) -> ConfigError {
    match errno {
        Errno::LOOP => refused(file, SYMLINK),
        other => io_error(file, other.into()),
    }
}


/// The parent is opened from `/` with every directory judged on its handle, the file opened from that handle, then judged and read on the one handle.
pub fn read_trusted_with(path: &Path, max: u64, judge: JudgeFn, after_open: AfterOpenFn) -> Result<Vec<u8>, ConfigError> {
    let file = path.display().to_string();
    let process_user = geteuid().as_raw();
    let (parent, name) = path.parent().zip(path.file_name()).ok_or_else(|| refused(&file, NO_PARENT))?;
    let directory = open_trusted_dir(parent, process_user).map_err(|error| directory_error(&file, error))?;
    let handle = File::from(openat(&directory, name, FILE_FLAGS, Mode::empty()).map_err(|errno| open_error(&file, errno))?);
    after_open(path);
    let io_failure = |source: std::io::Error| io_error(&file, source);
    let stat = fstat(&handle).map_err(std::io::Error::from).map_err(io_failure)?;
    let is_file = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile;
    judge(is_file, stat.st_mode, stat.st_uid, process_user).map_err(|reason| refused(&file, reason))?;
    let mut bytes = Vec::new();
    handle.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(io_failure)?;
    if bytes.len() as u64 > max {
        Err(ConfigError::TooLarge { file, max })
    } else {
        Ok(bytes)
    }
}


/// The production reader of the two FIM inputs, capped at `max` bytes.
pub fn read_trusted_capped(path: &Path, max: u64) -> Result<Vec<u8>, ConfigError> {
    read_trusted_with(path, max, judge_trusted_file, no_hook)
}

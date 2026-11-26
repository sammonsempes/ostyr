//! The CA file read through a judged parent directory and a judged file handle: owner root or the service user, no group or other write.

use core_config::error::ConfigError;
use core_config::parse::read_text_capped;
use core_config::trusted_dir::open_trusted_dir;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags, RawMode, CWD};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;


pub const GROUP_OTHER_WRITE: RawMode = 0o022;


pub const PROC_FD_DIRECTORY: &str = "/proc/self/fd/";


pub const ROOT_USER: u32 = 0;


pub const DIRECTORY_REFUSED: &str = "the directory is not trusted";


pub const NOT_REGULAR: &str = "the file is not a regular file";


pub const FOREIGN_OWNER: &str = "the file is owned by neither root nor the service user";


pub const OPEN_TO_WRITES: &str = "the file can be written by its group or by others";


pub const FILE_REFUSED: &str = "the file is not trusted";


pub fn refuse(file: &str, reason: String) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.to_owned(),
        reason,
    }
}


/// A regular file, owned by root or the process user, that group and others cannot write; the refusal names the check that failed.
pub fn file_refusal(mode: RawMode, owner: u32, process_user: u32) -> Result<(), &'static str> {
    if FileType::from_raw_mode(mode) != FileType::RegularFile {
        Err(NOT_REGULAR)
    } else if owner != process_user && owner != ROOT_USER {
        Err(FOREIGN_OWNER)
    } else if mode & GROUP_OTHER_WRITE != 0 {
        Err(OPEN_TO_WRITES)
    } else {
        Ok(())
    }
}


pub fn errno_refusal(file: &str) -> impl Fn(Errno) -> ConfigError + '_ {
    move |errno| refuse(file, format!("{FILE_REFUSED}: {}", std::io::Error::from(errno)))
}


/// The anchor is opened without following a symlink and without running a driver, then judged by `fstat`.
pub fn judge_file(directory: &OwnedFd, name: &str, file: &str) -> Result<OwnedFd, ConfigError> {
    let anchor = openat(directory, name, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno_refusal(file))?;
    let stat = fstat(&anchor).map_err(errno_refusal(file))?;
    file_refusal(stat.st_mode, stat.st_uid, geteuid().as_raw())
        .map(|()| anchor)
        .map_err(|check| refuse(file, check.to_owned()))
}


/// The text of the inode that was judged, read through `/proc/self/fd` and capped at `max_bytes`.
pub fn read_trusted_text(path: &Path, max_bytes: u64) -> Result<String, ConfigError> {
    let label = path.display().to_string();
    let (parent, name) = path
        .parent()
        .zip(path.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| refuse(&label, DIRECTORY_REFUSED.to_owned()))?;
    let directory = open_trusted_dir(parent, geteuid().as_raw()).map_err(|failure| refuse(&label, format!("{DIRECTORY_REFUSED}: {failure}")))?;
    let anchor = judge_file(&directory, name, &label)?;
    let proc_path = format!("{PROC_FD_DIRECTORY}{}", anchor.as_raw_fd());
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let mut handle = openat(CWD, proc_path.as_str(), flags, Mode::empty())
        .map(File::from)
        .map_err(errno_refusal(&label))?;
    read_text_capped(&mut handle, &label, max_bytes)
}

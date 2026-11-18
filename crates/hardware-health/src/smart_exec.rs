//! Judges the smartctl program before it runs as root: every ancestor and the file are closed to anyone but root and the caller (Unix only).

use crate::model::FailureClass;
use core_config::trusted_dir::open_trusted_dir;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use rustix::process::geteuid;
use std::ffi::OsStr;
use std::path::Path;
use tracing::debug;


const ROOT_UID: u32 = 0;


const GROUP_OTHER_WRITE: u32 = 0o022;


const FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::NONBLOCK).union(OFlags::CLOEXEC);


/// The directory and the name of an absolute path made only of plain names: no `.`, `..`, empty part or relative form.
pub fn split_program(path: &Path) -> Option<(&Path, &OsStr)> {
    let text = path.to_str()?;
    let plain = text
        .strip_prefix('/')?
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..");
    plain.then_some(())?;
    path.parent().zip(path.file_name())
}


/// Why a program file is not trusted: not a regular file, an owner other than root or `trusted_uid`, or write access for group or others.
pub fn distrust(is_regular: bool, owner: u32, mode: u32, trusted_uid: u32) -> Option<&'static str> {
    [
        (!is_regular, "it is not a regular file"),
        (owner != ROOT_UID && owner != trusted_uid, "it is owned by another user"),
        (mode & GROUP_OTHER_WRITE != 0, "it is writable by group or others"),
    ]
    .into_iter()
    .find_map(|(bad, reason)| bad.then_some(reason))
}


fn refuse(reason: &'static str) -> FailureClass {
    debug!(reason, "the smartctl program is refused");
    FailureClass::ProgramRefused
}


/// Opens the parent with `open_trusted_dir`, then the file on that handle without following a link, and judges the same handle.
pub fn check_program_as(program: &Path, trusted_uid: u32) -> Result<(), FailureClass> {
    let (parent, name) = split_program(program).ok_or_else(|| refuse("the path is not absolute or holds a . or .. component"))?;
    let directory = open_trusted_dir(parent, trusted_uid).map_err(|_| refuse("its directory or an ancestor is not trusted"))?;
    let stat = openat(&directory, name, FILE_FLAGS, Mode::empty())
        .and_then(|file| fstat(&file))
        .map_err(|_| refuse("it cannot be opened without following a link"))?;
    let regular = FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile;
    distrust(regular, stat.st_uid, stat.st_mode, trusted_uid).map_or(Ok(()), |reason| Err(refuse(reason)))
}


/// `check_program_as` for the effective user of this process.
pub fn check_program(program: &Path) -> Result<(), FailureClass> {
    check_program_as(program, geteuid().as_raw())
}

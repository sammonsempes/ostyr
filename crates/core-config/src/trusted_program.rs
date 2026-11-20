//! Opens an external program only when no one but root and the trusted uid can swap it or anything above it (Unix only).

use crate::trusted_dir::{check_canonical_form, check_trusted_path, GROUP_OTHER_WRITE, NOT_CANONICAL};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};
use thiserror::Error;


const OWNER_EXECUTE: u32 = 0o100;


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const PROGRAM_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


/// A refusal names the check, never a path; `Io` keeps the errno.
#[derive(Debug, Error)]
pub enum TrustedProgramError {
    #[error("program is refused: {0}")]
    Refused(&'static str),
    #[error("program cannot be opened: {0}")]
    Io(#[from] io::Error),
}


impl From<Errno> for TrustedProgramError {
    fn from(errno: Errno) -> Self {
        Self::Io(io::Error::from(errno))
    }
}


fn ensure(ok: bool, reason: &'static str) -> Result<(), TrustedProgramError> {
    ok.then_some(()).ok_or(TrustedProgramError::Refused(reason))
}


fn open_component(parent: &OwnedFd, name: &OsStr, flags: OFlags) -> Result<OwnedFd, TrustedProgramError> {
    openat(parent, name, flags, Mode::empty()).map_err(|errno| match errno {
        Errno::NOTDIR => TrustedProgramError::Refused("program path has a symlink or a non-directory component"),
        other => TrustedProgramError::from(other),
    })
}


fn check_directory(handle: &OwnedFd, trusted_uid: u32) -> Result<(), TrustedProgramError> {
    let stat = fstat(handle)?;
    ensure(
        [0, trusted_uid].contains(&stat.st_uid),
        "program ancestor is not owned by root or the trusted user",
    )?;
    ensure(stat.st_mode & GROUP_OTHER_WRITE == 0, "program ancestor is writable by group or others")
}


fn check_file(handle: &OwnedFd, trusted_uid: u32) -> Result<(), TrustedProgramError> {
    let stat = fstat(handle)?;
    ensure(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        "program is not a regular file",
    )?;
    ensure(
        [0, trusted_uid].contains(&stat.st_uid),
        "program is not owned by root or the trusted user",
    )?;
    ensure(stat.st_mode & GROUP_OTHER_WRITE == 0, "program is writable by group or others")?;
    ensure(stat.st_mode & OWNER_EXECUTE != 0, "program has no owner execute bit")
}


/// Opens the program from `/` one component at a time without following a link, every directory judged on its handle, no sticky exception.
pub fn open_trusted_program(path: &Path, trusted_uid: u32) -> Result<OwnedFd, TrustedProgramError> {
    ensure(path.is_absolute(), "program path is not absolute")?;
    check_canonical_form(path).map_err(|_| TrustedProgramError::Refused(NOT_CANONICAL))?;
    check_trusted_path(path).map_err(|_| TrustedProgramError::Refused("program path has a component other than a name"))?;
    let names: Vec<&OsStr> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    let (file_name, directories) = names.split_last().ok_or(TrustedProgramError::Refused("program path has no file name"))?;
    let start = openat(rustix::fs::CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    let parent = directories.iter().try_fold(start, |parent, name| {
        check_directory(&parent, trusted_uid)?;
        open_component(&parent, name, DIRECTORY_FLAGS)
    })?;
    check_directory(&parent, trusted_uid)?;
    let program = open_component(&parent, file_name, PROGRAM_FLAGS)?;
    check_file(&program, trusted_uid)?;
    Ok(program)
}


/// True when the path still names the program the handle holds, judged again from `/` (`st_dev`, `st_ino`).
pub fn same_program(handle: &OwnedFd, path: &Path, trusted_uid: u32) -> Result<bool, TrustedProgramError> {
    let current = open_trusted_program(path, trusted_uid)?;
    let held = fstat(handle)?;
    let now = fstat(&current)?;
    Ok((held.st_dev, held.st_ino) == (now.st_dev, now.st_ino))
}

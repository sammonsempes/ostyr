//! Opens a work directory only when no one but root and the caller can swap it or anything above it (Unix only).

use rustix::fs::{fstat, openat, Mode, OFlags};
use rustix::io::Errno;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};
use thiserror::Error;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const STICKY_BIT: u32 = 0o1000;


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


/// A refusal names the check, never a path; `Io` keeps the errno.
#[derive(Debug, Error)]
pub enum TrustedDirError {
    #[error("work directory is refused: {0}")]
    Refused(&'static str),
    #[error("work directory cannot be opened: {0}")]
    Io(#[from] io::Error),
}


impl From<Errno> for TrustedDirError {
    fn from(errno: Errno) -> Self {
        Self::Io(io::Error::from(errno))
    }
}


fn ensure(ok: bool, reason: &'static str) -> Result<(), TrustedDirError> {
    ok.then_some(()).ok_or(TrustedDirError::Refused(reason))
}


fn check_ancestor(handle: &OwnedFd, expected_uid: u32) -> Result<(), TrustedDirError> {
    let stat = fstat(handle)?;
    ensure(
        stat.st_uid == 0 || stat.st_uid == expected_uid,
        "work directory ancestor is not owned by root or the caller",
    )?;
    ensure(
        stat.st_mode & GROUP_OTHER_WRITE == 0 || stat.st_mode & STICKY_BIT != 0,
        "work directory ancestor is writable by group or others",
    )
}


/// The path is absolute and holds only names (no `..`, no `.`), checked before anything is opened.
pub fn check_trusted_path(path: &Path) -> Result<(), TrustedDirError> {
    ensure(path.is_absolute(), "work directory is not absolute")?;
    ensure(
        path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "work directory has a component other than a name",
    )
}


/// Opens the directory from `/` one component at a time without following a link, with every ancestor judged on its handle.
pub fn open_trusted_dir(path: &Path, expected_uid: u32) -> Result<OwnedFd, TrustedDirError> {
    check_trusted_path(path)?;
    let start = openat(rustix::fs::CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    let dir = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .try_fold(start, |parent, name| {
            check_ancestor(&parent, expected_uid)?;
            openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(TrustedDirError::from)
        })?;
    let stat = fstat(&dir)?;
    ensure(stat.st_uid == expected_uid, "work directory is not owned by the caller")?;
    ensure(stat.st_mode & GROUP_OTHER_WRITE == 0, "work directory is writable by group or others")?;
    Ok(dir)
}

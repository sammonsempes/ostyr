#![cfg(target_os = "linux")]
//! Reads the exec probe object once, through one checked handle, from a path only root can change.

use crate::types::{OpenFn, Opened, StatFn};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat, CWD};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};


pub const EXEC_OBJECT_PATH: &str = "/usr/lib/ostyr/ebpf/exec.o";


pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


pub const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Meta {
    pub mode: u32,
    pub uid: u32,
    pub size: u64,
    pub dev: u64,
    pub ino: u64,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectError {
    PathNotAbsolute,
    PathNotPlain,
    Symlink { depth: usize },
    NotDirectory { depth: usize },
    AncestorOwner { depth: usize },
    AncestorWritable { depth: usize },
    Open { depth: usize, errno: i32 },
    NotRegular,
    Owner,
    Writable,
    TooLarge,
    Swapped,
    ReadTooLarge,
    Read { kind: ErrorKind },
}


impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::PathNotAbsolute => write!(formatter, "object path is not absolute"),
            ObjectError::PathNotPlain => write!(formatter, "object path is not a plain canonical path"),
            ObjectError::Symlink { depth } => write!(formatter, "object path component {depth} is a symlink"),
            ObjectError::NotDirectory { depth } => write!(formatter, "object path component {depth} is not a directory"),
            ObjectError::AncestorOwner { depth } => write!(formatter, "object ancestor {depth} is not owned by root"),
            ObjectError::AncestorWritable { depth } => write!(formatter, "object ancestor {depth} is writable by group or others"),
            ObjectError::Open { depth, errno } => write!(formatter, "object path component {depth} cannot be opened (errno {errno})"),
            ObjectError::NotRegular => write!(formatter, "object is not a regular file"),
            ObjectError::Owner => write!(formatter, "object is not owned by root"),
            ObjectError::Writable => write!(formatter, "object is writable by group or others"),
            ObjectError::TooLarge => write!(formatter, "object is larger than {MAX_OBJECT_BYTES} bytes"),
            ObjectError::Swapped => write!(formatter, "object changed between the path check and the open"),
            ObjectError::ReadTooLarge => write!(formatter, "object read exceeds {MAX_OBJECT_BYTES} bytes"),
            ObjectError::Read { kind } => write!(formatter, "object cannot be read ({kind:?})"),
        }
    }
}


impl std::error::Error for ObjectError {}


/// Keeps only the fields the checks read.
pub fn meta_of(stat: &Stat) -> Meta {
    Meta {
        mode: stat.st_mode,
        uid: stat.st_uid,
        size: u64::try_from(stat.st_size).unwrap_or(u64::MAX),
        dev: stat.st_dev,
        ino: stat.st_ino,
    }
}


/// An ancestor must be a directory of root that group and others cannot write (the POSIX ACL mask sits in the group bits).
pub fn check_directory(meta: &Meta, depth: usize) -> Result<(), ObjectError> {
    let is_directory = FileType::from_raw_mode(meta.mode) == FileType::Directory;
    let owned_by_root = meta.uid == 0;
    let closed = meta.mode & GROUP_OTHER_WRITE == 0;
    is_directory.then_some(()).ok_or(ObjectError::NotDirectory { depth })?;
    owned_by_root.then_some(()).ok_or(ObjectError::AncestorOwner { depth })?;
    closed.then_some(()).ok_or(ObjectError::AncestorWritable { depth })
}


/// The object must be a small regular file of root that group and others cannot write.
pub fn check_file(meta: &Meta) -> Result<(), ObjectError> {
    let is_regular = FileType::from_raw_mode(meta.mode) == FileType::RegularFile;
    let owned_by_root = meta.uid == 0;
    let closed = meta.mode & GROUP_OTHER_WRITE == 0;
    let small = meta.size <= MAX_OBJECT_BYTES;
    is_regular.then_some(()).ok_or(ObjectError::NotRegular)?;
    owned_by_root.then_some(()).ok_or(ObjectError::Owner)?;
    closed.then_some(()).ok_or(ObjectError::Writable)?;
    small.then_some(()).ok_or(ObjectError::TooLarge)
}


/// True when both stats name one file.
pub fn same_file(left: &Meta, right: &Meta) -> bool {
    (left.dev, left.ino) == (right.dev, right.ino)
}


fn open_error(depth: usize, errno: Errno) -> ObjectError {
    match errno {
        Errno::LOOP => ObjectError::Symlink { depth },
        Errno::NOTDIR => ObjectError::NotDirectory { depth },
        other => ObjectError::Open {
            depth,
            errno: other.raw_os_error(),
        },
    }
}


/// The real `openat`, returning the handle with its own `fstat`.
pub fn real_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    openat(parent, name, flags, Mode::empty()).and_then(|handle| fstat(&handle).map(|stat| (handle, meta_of(&stat))))
}


/// The real `fstatat` without following a symlink.
pub fn real_stat(parent: BorrowedFd<'_>, name: &OsStr) -> Result<Meta, Errno> {
    statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map(|stat| meta_of(&stat))
}


/// Opens the last name from its parent: judged by `fstatat` first, opened once without blocking, judged again on the handle, same file.
pub fn open_last(parent: BorrowedFd<'_>, name: &OsStr, depth: usize, open: OpenFn, stat_entry: StatFn) -> Result<OwnedFd, ObjectError> {
    let entry = stat_entry(parent, name).map_err(|errno| open_error(depth, errno))?;
    check_file(&entry)?;
    let (handle, meta) = open(parent, name, FILE_FLAGS).map_err(|errno| open_error(depth, errno))?;
    check_file(&meta)?;
    same_file(&entry, &meta).then_some(handle).ok_or(ObjectError::Swapped)
}


/// Splits a canonical absolute path into names; `//`, `.`, `..`, a trailing `/` and `/` alone are refused.
pub fn plain_names(path: &Path) -> Result<(OsString, Vec<OsString>), ObjectError> {
    path.is_absolute().then_some(()).ok_or(ObjectError::PathNotAbsolute)?;
    let names: Vec<OsString> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    let rebuilt: PathBuf = std::iter::once(OsString::from("/")).chain(names.iter().cloned()).collect();
    let plain = rebuilt.as_os_str() == path.as_os_str();
    plain.then_some(()).ok_or(ObjectError::PathNotPlain)?;
    let (last, directories) = names.split_last().ok_or(ObjectError::PathNotPlain)?;
    Ok((last.clone(), directories.to_vec()))
}


/// Walks from `/` one component at a time without following a link, every ancestor judged on its handle before anything inside it is opened.
pub fn walk_object(path: &Path, open: OpenFn, stat_entry: StatFn) -> Result<OwnedFd, ObjectError> {
    let (file_name, directories) = plain_names(path)?;
    let root = open(CWD, OsStr::new("/"), DIRECTORY_FLAGS).map_err(|errno| open_error(0, errno))?;
    check_directory(&root.1, 0)?;
    let (parent, _) = directories.iter().enumerate().try_fold(root, |held, (index, name)| {
        let depth = index + 1;
        let next = open(held.0.as_fd(), name, DIRECTORY_FLAGS).map_err(|errno| open_error(depth, errno))?;
        check_directory(&next.1, depth)?;
        Ok::<Opened, ObjectError>(next)
    })?;
    open_last(parent.as_fd(), &file_name, directories.len() + 1, open, stat_entry)
}


/// Reads at most `max` bytes and refuses one more.
pub fn read_bounded(source: &mut dyn Read, max: u64) -> Result<Vec<u8>, ObjectError> {
    let mut bytes = Vec::new();
    Read::take(source, max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ObjectError::Read { kind: error.kind() })?;
    let fits = u64::try_from(bytes.len()).is_ok_and(|length| length <= max);
    fits.then_some(bytes).ok_or(ObjectError::ReadTooLarge)
}


/// Reads the object through the given open functions; the bytes come from the one handle the checks judged.
pub fn read_object_with(path: &Path, open: OpenFn, stat_entry: StatFn) -> Result<Vec<u8>, ObjectError> {
    let handle = walk_object(path, open, stat_entry)?;
    read_bounded(&mut File::from(handle), MAX_OBJECT_BYTES)
}


/// Reads the object at `path` (production passes `EXEC_OBJECT_PATH`).
pub fn read_object(path: &Path) -> Result<Vec<u8>, ObjectError> {
    read_object_with(path, real_open, real_stat)
}

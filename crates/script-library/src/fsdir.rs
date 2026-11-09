use crate::check::ensure;
use crate::error::ScriptError;
use crate::types::{NameFn, StatFn};
use rustix::fs::{fstat, mkdirat, openat, Mode, OFlags, RawMode, CWD};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use tracing::warn;


pub const WRITABLE_BY_OTHERS: RawMode = 0o022;


pub const STICKY_BIT: RawMode = 0o1000;


pub const PRIVATE_FILE_MODE: RawMode = 0o600;


pub const PRIVATE_DIRECTORY_MODE: RawMode = 0o700;


pub const PRIVATE_DIRECTORY_PREFIX: &str = "script-";


pub const NAME_ATTEMPTS: u32 = 16;


pub const NAME_RANDOM_BYTES: usize = 8;


pub const ZERO_BYTE: u8 = 0;


/// The checked work root: the handle is what every later operation goes through, the path is only for the interpreter's argument.
#[derive(Debug)]
pub struct WorkRoot {
    pub path: PathBuf,
    pub handle: OwnedFd,
}


/// A fresh `0700` directory below the work root, removed with its content when dropped.
#[derive(Debug)]
pub struct PrivateDirectory {
    pub path: PathBuf,
    pub handle: OwnedFd,
}


/// `O_DIRECTORY | O_NOFOLLOW`: a symlink or a non-directory at the last component is refused.
pub fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    Ok(openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}


pub fn open_child_directory(parent: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    Ok(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}


/// An ancestor must be owned by the agent user or root, and closed to group and others unless sticky.
pub fn check_ancestor(directory: BorrowedFd<'_>, owner: u32, inspect: StatFn) -> Result<(), ScriptError> {
    let stat = inspect(directory).map_err(|errno| ScriptError::Io {
        context: "cannot inspect a parent of the work root",
        source: errno.into(),
    })?;
    ensure(
        (stat.st_uid == owner || stat.st_uid == 0) && (stat.st_mode & WRITABLE_BY_OTHERS == 0 || stat.st_mode & STICKY_BIT != 0),
        ScriptError::UnsafeWorkRoot,
    )
}


/// The root itself must be owned by the agent user and closed to group and others, sticky or not.
pub fn check_root_handle(directory: BorrowedFd<'_>, owner: u32, inspect: StatFn) -> Result<(), ScriptError> {
    let stat = inspect(directory).map_err(|errno| ScriptError::Io {
        context: "cannot inspect the work root",
        source: errno.into(),
    })?;
    ensure(
        stat.st_uid == owner && stat.st_mode & WRITABLE_BY_OTHERS == 0,
        ScriptError::UnsafeWorkRoot,
    )
}


fn open_error(source: io::Error) -> ScriptError {
    ScriptError::Io {
        context: "cannot open the work root",
        source,
    }
}


/// Opens the root component by component without following a symlink, checking every directory through its own handle (no path is checked then reused).
pub fn open_work_root(root: &Path, owner: u32) -> Result<WorkRoot, ScriptError> {
    open_work_root_with(root, owner, stat_directory)
}


pub fn stat_directory(directory: BorrowedFd<'_>) -> Result<rustix::fs::Stat, Errno> {
    fstat(directory)
}


/// `open_work_root` with an injected `fstat`.
pub fn open_work_root_with(root: &Path, owner: u32, stat: StatFn) -> Result<WorkRoot, ScriptError> {
    let canonical = fs::canonicalize(root).map_err(|source| ScriptError::Io {
        context: "cannot resolve the work root",
        source,
    })?;
    let start = open_directory(Path::new("/")).map_err(open_error)?;
    let handle = canonical
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .try_fold(start, |parent, name| {
            check_ancestor(parent.as_fd(), owner, stat)?;
            open_child_directory(parent.as_fd(), name).map_err(open_error)
        })?;
    check_root_handle(handle.as_fd(), owner, stat)?;
    Ok(WorkRoot { path: canonical, handle })
}


/// Production names: the prefix and 16 hex digits from the kernel's random source.
pub fn random_name() -> io::Result<String> {
    let mut bytes = [ZERO_BYTE; NAME_RANDOM_BYTES];
    rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty())?;
    Ok(format!("{PRIVATE_DIRECTORY_PREFIX}{}", data_encoding::HEXLOWER.encode(&bytes)))
}


fn make_directory(root: BorrowedFd<'_>, name: &str) -> io::Result<Option<()>> {
    match mkdirat(root, name, Mode::from_bits_truncate(PRIVATE_DIRECTORY_MODE)) {
        Ok(()) => Ok(Some(())),
        Err(Errno::EXIST) => Ok(None),
        Err(errno) => Err(errno.into()),
    }
}


/// `mkdirat` relative to the checked root handle; a name that already exists is retried, up to `NAME_ATTEMPTS` times.
pub fn create_private_directory(root: &WorkRoot, namer: NameFn<'_>) -> Result<PrivateDirectory, ScriptError> {
    let context = "cannot create the private script directory";
    let (created, handle) = (0..NAME_ATTEMPTS)
        .find_map(|_attempt| {
            namer()
                .and_then(|name| make_directory(root.handle.as_fd(), &name).map(|made| made.map(|()| name)))
                .transpose()
        })
        .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::AlreadyExists)))
        .and_then(|name| open_child_directory(root.handle.as_fd(), OsStr::new(&name)).map(|handle| (name, handle)))
        .map_err(|source| ScriptError::Io { context, source })?;
    Ok(PrivateDirectory {
        path: root.path.join(created),
        handle,
    })
}


pub fn write_all_into<Sink: Write>(mut sink: Sink, bytes: &[u8]) -> Result<(), ScriptError> {
    sink.write_all(bytes).map_err(|source| ScriptError::Io {
        context: "cannot write the private script file",
        source,
    })
}


/// One `O_EXCL | O_NOFOLLOW` file of mode 0600, created relative to the private directory's handle.
pub fn write_private_file(directory: &PrivateDirectory, file_name: &str, bytes: &[u8]) -> Result<PathBuf, ScriptError> {
    let descriptor = openat(
        directory.handle.as_fd(),
        file_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(PRIVATE_FILE_MODE),
    )
    .map_err(|errno| ScriptError::Io {
        context: "cannot create the private script file",
        source: errno.into(),
    })?;
    write_all_into(File::from(descriptor), bytes).map(|()| directory.path.join(file_name))
}


impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            warn!(%error, "cannot remove the private script directory");
        }
    }
}

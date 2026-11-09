use crate::error::SpoolError;
use crate::spool_model::DirectoryFacts;
use crate::types::DirHandle;
use std::fs::File;
use std::io;
use std::path::Path;


#[cfg(unix)]
const SEGMENT_FILE_MODE: u32 = 0o600;


#[cfg(unix)]
pub fn open_directory(path: &Path) -> Result<DirHandle, SpoolError> {
    use rustix::fs::{open, Mode, OFlags};
    use rustix::io::Errno;
    let opened = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );
    opened.map_err(|errno| match errno {
        Errno::NOTDIR | Errno::LOOP => SpoolError::NotDirectory,
        other => SpoolError::Io(other.into()),
    })
}


#[cfg(unix)]
pub fn directory_facts(dir: &DirHandle) -> io::Result<DirectoryFacts> {
    use rustix::fs::{fstat, FileType};
    let status = fstat(dir)?;
    Ok(DirectoryFacts {
        is_directory: FileType::from_raw_mode(status.st_mode) == FileType::Directory,
        owner: status.st_uid,
        mode: status.st_mode,
        expected_owner: rustix::process::geteuid().as_raw(),
    })
}


#[cfg(unix)]
fn open_named(dir: &DirHandle, name: &str, flags: rustix::fs::OFlags) -> io::Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let mode = Mode::from_raw_mode(SEGMENT_FILE_MODE);
    Ok(File::from(openat(dir, name, flags | OFlags::NOFOLLOW | OFlags::CLOEXEC, mode)?))
}


#[cfg(unix)]
pub fn open_read(dir: &DirHandle, name: &str) -> io::Result<File> {
    open_named(dir, name, rustix::fs::OFlags::RDONLY)
}


#[cfg(unix)]
pub fn open_write(dir: &DirHandle, name: &str) -> io::Result<File> {
    open_named(dir, name, rustix::fs::OFlags::WRONLY)
}


#[cfg(unix)]
pub fn open_append(dir: &DirHandle, name: &str) -> io::Result<File> {
    open_named(dir, name, rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::APPEND)
}


#[cfg(unix)]
pub fn create_append(dir: &DirHandle, name: &str) -> io::Result<File> {
    use rustix::fs::OFlags;
    open_named(dir, name, OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::EXCL)
}


#[cfg(unix)]
pub fn remove_named(dir: &DirHandle, name: &str) -> io::Result<()> {
    Ok(rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty())?)
}


#[cfg(unix)]
pub fn regular_file_names(dir: &DirHandle, max_entries: usize) -> io::Result<Vec<String>> {
    use rustix::fs::{Dir, FileType};
    let mut names = Vec::new();
    for entry in Dir::read_from(dir)?.take(max_entries) {
        let found = entry?;
        let is_file = found.file_type() == FileType::RegularFile;
        names.extend(found.file_name().to_str().ok().map(str::to_owned).filter(|_| is_file));
    }
    Ok(names)
}


#[cfg(not(unix))]
pub fn open_directory(_path: &Path) -> Result<DirHandle, SpoolError> {
    Err(SpoolError::Unsupported)
}


#[cfg(not(unix))]
fn unsupported<Output>() -> io::Result<Output> {
    Err(io::ErrorKind::Unsupported.into())
}


#[cfg(not(unix))]
pub fn directory_facts(_dir: &DirHandle) -> io::Result<DirectoryFacts> {
    unsupported()
}


#[cfg(not(unix))]
pub fn open_read(_dir: &DirHandle, _name: &str) -> io::Result<File> {
    unsupported()
}


#[cfg(not(unix))]
pub fn open_write(_dir: &DirHandle, _name: &str) -> io::Result<File> {
    unsupported()
}


#[cfg(not(unix))]
pub fn open_append(_dir: &DirHandle, _name: &str) -> io::Result<File> {
    unsupported()
}


#[cfg(not(unix))]
pub fn create_append(_dir: &DirHandle, _name: &str) -> io::Result<File> {
    unsupported()
}


#[cfg(not(unix))]
pub fn remove_named(_dir: &DirHandle, _name: &str) -> io::Result<()> {
    unsupported()
}


#[cfg(not(unix))]
pub fn regular_file_names(_dir: &DirHandle, _max_entries: usize) -> io::Result<Vec<String>> {
    unsupported()
}

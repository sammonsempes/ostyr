use crate::error::SpoolError;
use crate::spool_model::DirectoryFacts;
use crate::types::DirHandle;
use std::fs::File;
use std::io::{self, Write};
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
    let file = open_named(dir, name, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK)?;
    file.metadata()?
        .is_file()
        .then_some(file)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"))
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
pub fn rename_named(dir: &DirHandle, from: &str, to: &str) -> io::Result<()> {
    Ok(rustix::fs::renameat(dir, from, dir, to)?)
}


#[cfg(unix)]
pub fn sync_directory(dir: &DirHandle) -> io::Result<()> {
    File::from(dir.try_clone()?).sync_all()
}


#[cfg(unix)]
pub fn random_bytes<const LENGTH: usize>() -> io::Result<[u8; LENGTH]> {
    let mut bytes = [0u8; LENGTH];
    let filled = rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty())?;
    (filled == LENGTH).then_some(bytes).ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
}


#[cfg(unix)]
pub fn regular_file_names(dir: &DirHandle, max_entries: usize) -> Result<Vec<String>, SpoolError> {
    use rustix::fs::{Dir, FileType};
    let entries = Dir::read_from(dir)
        .map_err(io::Error::from)?
        .take(max_entries.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::from)?;
    (entries.len() <= max_entries).then_some(()).ok_or(SpoolError::TooManyEntries)?;
    Ok(entries
        .iter()
        .filter(|entry| entry.file_type() == FileType::RegularFile)
        .filter_map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
        .collect())
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
pub fn regular_file_names(_dir: &DirHandle, _max_entries: usize) -> Result<Vec<String>, SpoolError> {
    Err(SpoolError::Unsupported)
}


#[cfg(not(unix))]
pub fn random_bytes<const LENGTH: usize>() -> io::Result<[u8; LENGTH]> {
    unsupported()
}


#[cfg(not(unix))]
pub fn rename_named(_dir: &DirHandle, _from: &str, _to: &str) -> io::Result<()> {
    unsupported()
}


#[cfg(not(unix))]
pub fn sync_directory(_dir: &DirHandle) -> io::Result<()> {
    unsupported()
}


/// Written to a temporary file in the directory, synced, renamed over `name`, directory synced: every step relative to the opened directory.
pub fn write_text_atomic(dir: &DirHandle, temporary: &str, name: &str, text: &str) -> io::Result<()> {
    match remove_named(dir, temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        Ok(()) | Err(_) => Ok(()),
    }?;
    let mut file = create_append(dir, temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    rename_named(dir, temporary, name)?;
    sync_directory(dir)
}

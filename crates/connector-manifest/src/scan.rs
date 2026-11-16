use crate::error::ConnectorError;
use crate::manifest::valid_file_name;
use crate::model::{Limits, Package, MANIFEST_NAME, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, SIGNATURE_NAME};
use crate::package::{digest_bytes, hash_capped, io_at, io_error, read_capped};
use crate::types::{InspectFn, ListerFn, OpenFn};
use rustix::fs::{openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;


pub const MAX_SHOWN_NAME_CHARS: usize = 64;


pub const EXTRA_ENTRIES: usize = 4;


/// A name that cannot be shown as is: lossy, escaped and cut.
pub fn shown_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_SHOWN_NAME_CHARS)
        .flat_map(char::escape_default)
        .collect()
}


/// A package file name is an ASCII allowlist, so no two names can be one canonical entry (no `..`, no normalisation variants).
pub fn file_name_text(bytes: &[u8]) -> Result<String, ConnectorError> {
    match String::from_utf8(bytes.to_vec()) {
        Ok(name) if valid_file_name(&name) => Ok(name),
        _ => Err(ConnectorError::BadFileName { name: shown_name(bytes) }),
    }
}


pub fn errno_error(label: &str) -> impl Fn(Errno) -> ConnectorError + '_ {
    move |errno| io_error(label, io::Error::from(errno))
}


/// The raw names of at most `limit` entries, the dot entries included.
pub fn raw_entries(directory: &OwnedFd, limit: usize) -> Result<Vec<Vec<u8>>, Errno> {
    Dir::read_from(directory).and_then(|entries| {
        entries
            .take(limit)
            .map(|entry| entry.map(|found| found.file_name().to_bytes().to_vec()))
            .collect()
    })
}


/// The entry names of the opened directory: at most `max_files` files plus the signature are read before the count is refused.
pub fn list_names_with(lister: ListerFn, directory: &OwnedFd, label: &str, max_files: usize) -> Result<Vec<String>, ConnectorError> {
    let entries = lister(directory, max_files.saturating_add(EXTRA_ENTRIES)).map_err(errno_error(label))?;
    let names: Vec<&Vec<u8>> = entries
        .iter()
        .filter(|name| name.as_slice() != b"." && name.as_slice() != b"..")
        .collect();
    (names.iter().filter(|name| name.as_slice() != SIGNATURE_NAME.as_bytes()).count() <= max_files)
        .then_some(())
        .ok_or(ConnectorError::TooManyFiles { max: max_files })?;
    names.iter().map(|name| file_name_text(name)).collect()
}


pub fn list_names(directory: &OwnedFd, label: &str, max_files: usize) -> Result<Vec<String>, ConnectorError> {
    list_names_with(raw_entries, directory, label, max_files)
}


/// The verdict on one entry: a symlink, anything that is not a regular file, a file with several links.
pub fn judge_entry(kind: FileType, single_link: bool, name: &str) -> Result<(), ConnectorError> {
    (kind != FileType::Symlink)
        .then_some(())
        .ok_or_else(|| ConnectorError::Symlink { path: name.to_owned() })?;
    (kind == FileType::RegularFile)
        .then_some(())
        .ok_or_else(|| ConnectorError::NotRegular { path: name.to_owned() })?;
    single_link
        .then_some(())
        .ok_or_else(|| ConnectorError::HardLinked { path: name.to_owned() })
}


/// `fstatat` without following links, before any open: a device, FIFO or socket in the package is refused without its driver being opened.
pub fn precheck_entry(directory: &OwnedFd, name: &str) -> Result<(), ConnectorError> {
    let stat = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(errno_error(name))?;
    judge_entry(FileType::from_raw_mode(stat.st_mode), stat.st_nlink <= 1, name)
}


/// The real `openat`, injected into `open_entry_with` so a test can see which flags reach which path.
pub fn open_at(directory: BorrowedFd<'_>, path: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    openat(directory, path, flags, Mode::empty())
}


/// A handle's verdict through the injected `fstat`; returns the identity (device, inode) of the inode it judged.
pub fn judged_identity(inspect: InspectFn, handle: &File, name: &str) -> Result<(u64, u64), ConnectorError> {
    let metadata = inspect(handle).map_err(io_at(name))?;
    judge_entry(FileType::from_raw_mode(metadata.mode()), metadata.nlink() <= 1, name)?;
    Ok((metadata.dev(), metadata.ino()))
}


/// `O_PATH` opens no driver for any file type; the judged inode is then reopened through `/proc/self/fd` and must be the same one.
pub fn open_entry_with(opener: OpenFn, inspect: InspectFn, directory: &OwnedFd, name: &str) -> Result<File, ConnectorError> {
    let anchor = opener(directory.as_fd(), name, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC)
        .map(File::from)
        .map_err(errno_error(name))?;
    let judged = judged_identity(inspect, &anchor, name)?;
    let proc_path = format!("/proc/self/fd/{}", anchor.as_raw_fd());
    let handle = opener(CWD, &proc_path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC)
        .map(File::from)
        .map_err(errno_error(name))?;
    (judged_identity(inspect, &handle, name)? == judged)
        .then_some(handle)
        .ok_or_else(|| ConnectorError::Swapped { path: name.to_owned() })
}


pub fn open_entry(directory: &OwnedFd, name: &str) -> Result<File, ConnectorError> {
    open_entry_with(open_at, File::metadata, directory, name)
}


/// The handle that is read is judged again on its own metadata; `inspect` is injected so a failing `fstat` can be tested.
pub fn check_regular_with(inspect: InspectFn, handle: &File, name: &str) -> Result<(), ConnectorError> {
    judged_identity(inspect, handle, name).map(|_| ())
}


/// The manifest and the signature are read into memory (bounded); the manifest bytes are hashed from the buffer that is kept for parsing.
pub fn read_entry(directory: &OwnedFd, limits: &Limits, mut package: Package, name: &str) -> Result<Package, ConnectorError> {
    precheck_entry(directory, name)?;
    let mut handle = open_entry(directory, name)?;
    match name {
        SIGNATURE_NAME => package.signature = Some(read_capped(&mut handle, MAX_SIGNATURE_BYTES, name)?),
        MANIFEST_NAME => {
            package.manifest = read_capped(&mut handle, MAX_MANIFEST_BYTES as u64, name)?;
            let digest = digest_bytes(&package.manifest);
            package.total_bytes = package.total_bytes.saturating_add(digest.size);
            package.files.insert(name.to_owned(), digest);
        }
        _ => {
            let digest = hash_capped(&mut handle, limits.max_file_bytes, name)?;
            package.total_bytes = package.total_bytes.saturating_add(digest.size);
            package.files.insert(name.to_owned(), digest);
        }
    }
    (package.total_bytes <= limits.max_package_bytes)
        .then_some(package)
        .ok_or(ConnectorError::PackageTooLarge {
            max: limits.max_package_bytes,
        })
}


/// The directory is opened once with `O_DIRECTORY | O_NOFOLLOW`; every name is then opened relative to that handle.
pub fn scan_directory(directory: &Path, limits: &Limits) -> Result<Package, ConnectorError> {
    let label = directory.display().to_string();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let handle = openat(CWD, directory, flags, Mode::empty()).map_err(errno_error(&label))?;
    list_names(&handle, &label, limits.max_files)?
        .iter()
        .try_fold(Package::default(), |package, name| read_entry(&handle, limits, package, name))
}

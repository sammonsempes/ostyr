//! Bounded, handle-based read of a file in Suricata's filestore: `<root>/<first two hex>/<sha256>`, no symlink followed at any component.


use crate::model::Loaded;
#[cfg(unix)]
use rustix::fs::{openat, Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
use std::fs::{File, Metadata};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;


const SHA256_CHARS: usize = 64;


const PREFIX_CHARS: usize = 2;


#[cfg(unix)]
pub const DIR_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


#[cfg(unix)]
pub const FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::NONBLOCK).union(OFlags::CLOEXEC);


/// The result of opening one component without following a symlink.
#[derive(Debug)]
pub enum Stored {
    Found(File),
    Refused,
    Missing,
}


/// Reads at most `max_bytes`; `None` when the source holds more, so a file is never silently truncated.
pub fn read_capped(source: impl Read, max_bytes: u64) -> io::Result<Option<Vec<u8>>> {
    let mut content = Vec::new();
    source.take(max_bytes.saturating_add(1)).read_to_end(&mut content)?;
    let within = u64::try_from(content.len()).is_ok_and(|length| length <= max_bytes);
    Ok(within.then_some(content))
}


/// Names the filestore sub-directory (the first two characters) and the file (the whole hash) of a lowercase hex SHA-256; anything else is `None`.
pub fn split_name(sha256: &str) -> Option<(&str, &str)> {
    let valid = sha256.len() == SHA256_CHARS && sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    sha256.get(..PREFIX_CHARS).filter(|_| valid).map(|prefix| (prefix, sha256))
}


/// Opens one component below `parent`; a symlink or a wrong type is `Refused`, an absent name is `Missing`.
#[cfg(unix)]
pub fn step(parent: &File, name: &str, flags: OFlags) -> io::Result<Stored> {
    match openat(parent, name, flags, Mode::empty()) {
        Ok(handle) => Ok(Stored::Found(File::from(handle))),
        Err(Errno::LOOP | Errno::NOTDIR) => Ok(Stored::Refused),
        Err(Errno::NOENT) => Ok(Stored::Missing),
        Err(errno) => Err(io::Error::from(errno)),
    }
}


#[cfg(unix)]
fn open_below(root: &File, prefix: &str, name: &str) -> io::Result<Stored> {
    match step(root, prefix, DIR_FLAGS)? {
        Stored::Found(directory) => step(&directory, name, FILE_FLAGS),
        Stored::Refused => Ok(Stored::Refused),
        Stored::Missing => Ok(Stored::Missing),
    }
}


/// Opens the stored file by descriptor from the root handle; only the root itself is opened by path (it is configuration).
#[cfg(unix)]
pub fn open_stored(root: &Path, sha256: &str) -> io::Result<Stored> {
    let top = File::from(openat(rustix::fs::CWD, root, DIR_FLAGS, Mode::empty())?);
    match split_name(sha256) {
        Some((prefix, name)) => open_below(&top, prefix, name),
        None => Ok(Stored::Refused),
    }
}


/// Non-unix targets: a symlink check then an open, an accepted check-then-use gap.
#[cfg(not(unix))]
pub fn open_stored(root: &Path, sha256: &str) -> io::Result<Stored> {
    match split_name(sha256) {
        Some((prefix, name)) => {
            let path = root.join(prefix).join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(found) if found.file_type().is_symlink() => Ok(Stored::Refused),
                Ok(_) => File::open(&path).map(Stored::Found),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Stored::Missing),
                Err(error) => Err(error),
            }
        }
        None => Ok(Stored::Refused),
    }
}


/// A file with more than one hard link may be a name planted for a file outside the filestore.
#[cfg(unix)]
pub fn is_shared(metadata: &Metadata) -> bool {
    metadata.nlink() > 1
}


/// Non-unix targets: hard links are not judged.
#[cfg(not(unix))]
pub fn is_shared(_metadata: &Metadata) -> bool {
    false
}


/// Judges the open handle only: not a regular file or several hard links is refused, over the cap is `TooLarge` after `max_bytes + 1` bytes at most.
pub fn load_handle(handle: File, max_bytes: u64) -> io::Result<Loaded> {
    let metadata = handle.metadata()?;
    match metadata.is_file() && !is_shared(&metadata) {
        true => Ok(read_capped(handle, max_bytes)?.map_or(Loaded::TooLarge, Loaded::Content)),
        false => Ok(Loaded::Refused),
    }
}


/// Opens and reads one stored file under the cap.
pub fn load_stored(root: &Path, sha256: &str, max_bytes: u64) -> io::Result<Loaded> {
    match open_stored(root, sha256)? {
        Stored::Found(handle) => load_handle(handle, max_bytes),
        Stored::Refused => Ok(Loaded::Refused),
        Stored::Missing => Ok(Loaded::Missing),
    }
}

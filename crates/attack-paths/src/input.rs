//! The two per-round input files: opened without following a symlink and read through one handle that is stamped before and after the read.


use crate::types::MidRead;
use core_config::error::ConfigError;
use core_config::parse::NOT_REGULAR_REASON;
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;


/// Size, times, mode and owner of an open handle, taken before and after a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
}


/// The hook of production: nothing happens between the read and the second stamp.
pub fn untouched(_path: &Path) -> io::Result<()> {
    Ok(())
}


/// Runs the hook between the read and the second stamp; its failure names the file.
pub fn run_mid_read(hook: MidRead, path: &Path, file: &str) -> Result<(), ConfigError> {
    hook(path).map_err(io_at(file))
}


fn io_at(file: &str) -> impl FnOnce(io::Error) -> ConfigError + '_ {
    move |source| ConfigError::Io {
        file: file.to_string(),
        source,
    }
}


/// `O_NOFOLLOW` refuses a symlink at the last component, `O_NONBLOCK` keeps a FIFO from blocking the open; the handle is judged by `fstat`.
#[cfg(unix)]
pub fn open_nofollow(path: &Path, file: &str) -> Result<File, ConfigError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);
    let handle = options.open(path).map_err(io_at(file))?;
    refuse_unless_regular(&handle, file)?;
    Ok(handle)
}


#[cfg(not(unix))]
pub fn open_nofollow(path: &Path, file: &str) -> Result<File, ConfigError> {
    let handle = OpenOptions::new().read(true).open(path).map_err(io_at(file))?;
    refuse_unless_regular(&handle, file)?;
    Ok(handle)
}


pub fn refuse_unless_regular(handle: &File, file: &str) -> Result<(), ConfigError> {
    handle
        .metadata()
        .map_err(io_at(file))?
        .is_file()
        .then_some(())
        .ok_or_else(|| ConfigError::WatchedFile {
            file: file.to_string(),
            reason: NOT_REGULAR_REASON.to_string(),
        })
}


#[cfg(unix)]
pub fn stamp_of(handle: &File, file: &str) -> Result<Stamp, ConfigError> {
    let metadata = handle.metadata().map_err(io_at(file))?;
    Ok(Stamp {
        size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        mode: metadata.mode(),
        owner: metadata.uid(),
        group: metadata.gid(),
    })
}


#[cfg(not(unix))]
pub fn stamp_of(handle: &File, file: &str) -> Result<Stamp, ConfigError> {
    let metadata = handle.metadata().map_err(io_at(file))?;
    let since = metadata
        .modified()
        .map_err(io_at(file))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| io_at(file)(io::Error::other(error)))?;
    let seconds = i64::try_from(since.as_secs()).unwrap_or_else(|error| {
        tracing::warn!(file, error = %error, "modification time out of range, the stamp keeps the maximum");
        i64::MAX
    });
    Ok(Stamp {
        size: metadata.len(),
        modified: (seconds, i64::from(since.subsec_nanos())),
        changed: (0, 0),
        mode: 0,
        owner: 0,
        group: 0,
    })
}


/// Opens a file for one read: the handle and its first stamp.
pub fn open_stamped(path: &Path, file: &str) -> Result<(File, Stamp), ConfigError> {
    let handle = open_nofollow(path, file)?;
    let stamp = stamp_of(&handle, file)?;
    Ok((handle, stamp))
}


/// True when the handle still carries the stamp taken before the read; a writer that rewrote the file in place meanwhile makes the bytes read untrustworthy.
pub fn is_unchanged(handle: &File, before: &Stamp, file: &str) -> Result<bool, ConfigError> {
    Ok(stamp_of(handle, file)? == *before)
}

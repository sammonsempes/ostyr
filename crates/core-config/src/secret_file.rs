use std::fs::File;
#[cfg(unix)]
use std::fs::{Metadata, OpenOptions};
use std::io;
use std::path::Path;
use thiserror::Error;


pub const GROUP_OTHER_MASK: u32 = 0o077;


pub const ROOT_UID: u32 = 0;


/// Every refusal names the file and the check, never its content.
#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("{file}: cannot read: {source}")]
    Io {
        file: String,
        #[source]
        source: io::Error,
    },
    #[error("{file}: not a regular file")]
    NotRegular { file: String },
    #[error("{file}: secret file is a symlink")]
    Symlink { file: String },
    #[error("{file}: secret file grants permissions to group or other")]
    Mode { file: String },
    #[error("{file}: secret file is owned by neither the process user nor root")]
    Owner { file: String },
}


/// An open that failed on a symlink (`ELOOP` under `O_NOFOLLOW`) is `Symlink`, anything else keeps its cause.
#[cfg(unix)]
pub fn open_failure(file: String, source: io::Error) -> SecretFileError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        SecretFileError::Symlink { file }
    } else {
        SecretFileError::Io { file, source }
    }
}


/// The secret-file checks on the opened handle: a regular file, owned by the process user or root, no group or other bit.
pub fn judge_secret(file: &str, is_file: bool, mode: u32, owner: u32, process_user: u32) -> Result<(), SecretFileError> {
    if !is_file {
        Err(SecretFileError::NotRegular { file: file.to_owned() })
    } else if owner != process_user && owner != ROOT_UID {
        Err(SecretFileError::Owner { file: file.to_owned() })
    } else if mode & GROUP_OTHER_MASK != 0 {
        Err(SecretFileError::Mode { file: file.to_owned() })
    } else {
        Ok(())
    }
}


/// The metadata of the opened handle.
#[cfg(unix)]
pub fn handle_metadata(handle: &File) -> io::Result<Metadata> {
    handle.metadata()
}


/// Opened with `O_NOFOLLOW | O_NONBLOCK`, then judged on the handle; `inspect` is injected so that a failing inspection can be tested.
#[cfg(unix)]
pub fn open_secret_with(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> Result<File, SecretFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = path.display().to_string();
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| open_failure(file.clone(), source))?;
    let metadata = inspect(&handle).map_err(|source| SecretFileError::Io { file: file.clone(), source })?;
    judge_secret(
        &file,
        metadata.is_file(),
        metadata.mode(),
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    )?;
    Ok(handle)
}


/// A secret file read through the checks above.
#[cfg(unix)]
pub fn open_secret(path: &Path) -> Result<File, SecretFileError> {
    open_secret_with(path, handle_metadata)
}


/// A secret file; on a platform without Unix modes only the regular-file check applies.
#[cfg(not(unix))]
pub fn open_secret(path: &Path) -> Result<File, SecretFileError> {
    let file = path.display().to_string();
    let handle = File::open(path).map_err(|source| SecretFileError::Io { file: file.clone(), source })?;
    let is_file = handle
        .metadata()
        .map_err(|source| SecretFileError::Io { file: file.clone(), source })?
        .is_file();
    judge_secret(&file, is_file, 0, ROOT_UID, ROOT_UID).map(|()| handle)
}

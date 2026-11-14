use crate::error::PgError;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;


pub const MAX_PASSWORD_BYTES: u64 = 1024;


pub const PASSWORD_CAPACITY: usize = MAX_PASSWORD_BYTES as usize + 1;


pub const GROUP_OTHER_MASK: u32 = 0o077;


pub const ROOT_UID: u32 = 0;


/// Reads into `bytes`, only the final buffer is zeroed; no unzeroed copy is left only when its capacity exceeds `limit`.
fn read_into(reader: &mut dyn Read, limit: u64, file: &str, mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, PgError> {
    let mut limited = reader.take(limit.saturating_add(1));
    limited.read_to_end(&mut bytes).map_err(|source| PgError::Io {
        file: file.to_owned(),
        source,
    })?;
    if bytes.len() as u64 > limit {
        Err(PgError::TooLarge {
            file: file.to_owned(),
            limit,
        })
    } else {
        Ok(bytes)
    }
}


/// For non-secret files only (CA, request file): no preallocation, so a growing buffer may leave copies.
pub fn read_capped(reader: &mut dyn Read, limit: u64, file: &str) -> Result<Zeroizing<Vec<u8>>, PgError> {
    read_into(reader, limit, file, Zeroizing::new(Vec::new()))
}


/// The one read path for secrets: a limit the preallocated buffer cannot hold is refused before reading, so `read_to_end` never reallocates.
pub fn read_secret(reader: &mut dyn Read, limit: u64, file: &str) -> Result<Zeroizing<Vec<u8>>, PgError> {
    if limit >= PASSWORD_CAPACITY as u64 {
        Err(PgError::SecretLimit {
            file: file.to_owned(),
            limit,
        })
    } else {
        read_into(reader, limit, file, Zeroizing::new(Vec::with_capacity(PASSWORD_CAPACITY)))
    }
}


/// Opened without blocking so a FIFO cannot stall the open, then refused unless the opened handle is a regular file.
pub fn open_regular(path: &Path) -> Result<File, PgError> {
    open_checked(path, |handle| handle.metadata().map(|metadata| metadata.is_file()))
}


/// `is_regular` inspects the opened handle; injected so that a failing inspection can be tested.
pub fn open_checked(path: &Path, is_regular: fn(&File) -> std::io::Result<bool>) -> Result<File, PgError> {
    let file = path.display().to_string();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let handle = options.open(path).map_err(|source| PgError::Io { file: file.clone(), source })?;
    let regular = is_regular(&handle).map_err(|source| PgError::Io { file: file.clone(), source })?;
    if regular {
        Ok(handle)
    } else {
        Err(PgError::NotRegular { file })
    }
}


/// Non-secret files only.
pub fn read_limited(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, PgError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path)?;
    read_capped(&mut handle, limit, &file)
}


/// An open that failed on a symlink (`ELOOP` under `O_NOFOLLOW`) is `SecretSymlink`, anything else keeps its cause.
#[cfg(unix)]
pub fn open_failure(file: String, source: io::Error) -> PgError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        PgError::SecretSymlink { file }
    } else {
        PgError::Io { file, source }
    }
}


/// The secret-file checks on the opened handle: a regular file, owned by the process user or root, no group or other bit.
pub fn judge_secret(file: &str, is_file: bool, mode: u32, owner: u32, process_user: u32) -> Result<(), PgError> {
    if !is_file {
        Err(PgError::NotRegular { file: file.to_owned() })
    } else if owner != process_user && owner != ROOT_UID {
        Err(PgError::SecretOwner { file: file.to_owned() })
    } else if mode & GROUP_OTHER_MASK != 0 {
        Err(PgError::SecretMode { file: file.to_owned() })
    } else {
        Ok(())
    }
}


/// The metadata of the opened handle.
pub fn handle_metadata(handle: &File) -> io::Result<Metadata> {
    handle.metadata()
}


/// Opened with `O_NOFOLLOW | O_NONBLOCK`, then judged on the handle; `inspect` is injected so that a failing inspection can be tested.
#[cfg(unix)]
pub fn open_secret_with(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> Result<File, PgError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = path.display().to_string();
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| open_failure(file.clone(), source))?;
    let metadata = inspect(&handle).map_err(|source| PgError::Io { file: file.clone(), source })?;
    judge_secret(
        &file,
        metadata.is_file(),
        metadata.mode(),
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    )?;
    Ok(handle)
}


/// A secret file; on a platform without Unix modes only the regular-file check applies.
#[cfg(unix)]
pub fn open_secret(path: &Path) -> Result<File, PgError> {
    open_secret_with(path, handle_metadata)
}


/// A secret file; on a platform without Unix modes only the regular-file check applies.
#[cfg(not(unix))]
pub fn open_secret(path: &Path) -> Result<File, PgError> {
    open_regular(path)
}


/// The password bytes without the trailing line break, read afresh at each connect.
pub fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, PgError> {
    let file = path.display().to_string();
    let mut handle = open_secret(path)?;
    let mut bytes = read_secret(&mut handle, MAX_PASSWORD_BYTES, &file)?;
    let kept = bytes.iter().rposition(|byte| *byte != b'\n' && *byte != b'\r').map_or(0, |last| last + 1);
    bytes.truncate(kept);
    if bytes.is_empty() {
        Err(PgError::EmptyPassword { file })
    } else {
        Ok(bytes)
    }
}

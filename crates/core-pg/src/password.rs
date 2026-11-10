use crate::error::PgError;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;


pub const MAX_PASSWORD_BYTES: u64 = 1024;


/// At most `limit` bytes: a larger source is refused rather than cut.
pub fn read_capped(reader: &mut dyn Read, limit: u64, file: &str) -> Result<Vec<u8>, PgError> {
    let capacity = usize::try_from(limit.min(MAX_PASSWORD_BYTES) + 1).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = reader.take(limit + 1);
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


pub fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, PgError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path)?;
    read_capped(&mut handle, limit, &file)
}


/// The password bytes without the trailing line break, read afresh at each connect.
pub fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, PgError> {
    let mut bytes = Zeroizing::new(read_limited(path, MAX_PASSWORD_BYTES)?);
    let kept = bytes.iter().rposition(|byte| *byte != b'\n' && *byte != b'\r').map_or(0, |last| last + 1);
    bytes.truncate(kept);
    if bytes.is_empty() {
        Err(PgError::EmptyPassword {
            file: path.display().to_string(),
        })
    } else {
        Ok(bytes)
    }
}

use crate::error::PgError;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_PASSWORD_BYTES: u64 = 1024;


/// At most `limit` bytes: a larger source is refused rather than cut.
pub fn read_capped(reader: &mut dyn Read, limit: u64, file: &str) -> Result<Vec<u8>, PgError> {
    let mut bytes = Vec::new();
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


pub fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, PgError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| PgError::Io { file: file.clone(), source })?;
    read_capped(&mut handle, limit, &file)
}


/// The password bytes without the trailing line break, read afresh at each connect.
pub fn read_password(path: &Path) -> Result<Vec<u8>, PgError> {
    let mut bytes = read_limited(path, MAX_PASSWORD_BYTES)?;
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

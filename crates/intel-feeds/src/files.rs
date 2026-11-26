//! A CA file read through the trusted-file check: no-follow regular file owned by the process user or root, capped.

use crate::retro_state::open_state;
use core_config::secret_file::SecretFileError;
use core_pg::error::PgError;
use core_pg::password::read_capped;
use std::path::Path;
use zeroize::Zeroizing;


/// The pem bytes of a non-secret file, opened as `retro_state::open_state` does and read at most `limit` bytes.
pub fn read_trusted(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, PgError> {
    let file = path.display().to_string();
    let mut handle = open_state(path).map_err(pg_error)?;
    read_capped(&mut handle, limit, &file)
}


/// Each refusal keeps its category; the cause text stays with `Io` only.
pub fn pg_error(failure: SecretFileError) -> PgError {
    match failure {
        SecretFileError::Io { file, source } => PgError::Io { file, source },
        SecretFileError::NotRegular { file } => PgError::NotRegular { file },
        SecretFileError::Symlink { file } => PgError::SecretSymlink { file },
        SecretFileError::Mode { file } => PgError::SecretMode { file },
        SecretFileError::Owner { file } => PgError::SecretOwner { file },
    }
}

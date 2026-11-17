use crate::error::KeyError;
use crate::limits::{MAX_LINK_KEY_BYTES, MIN_LINK_KEY_BYTES};
use crate::types::LinkKey;
use core_config::secret_file::{open_secret, SecretFileError};
use core_pg::password::read_secret;
use std::path::Path;
use zeroize::Zeroizing;


/// Mode and owner refusals keep their own variants; every other refusal is `Open`.
pub fn key_refusal(error: SecretFileError) -> KeyError {
    match error {
        SecretFileError::Mode { .. } => KeyError::Mode(error),
        SecretFileError::Owner { .. } => KeyError::Owner(error),
        SecretFileError::Io { .. } | SecretFileError::NotRegular { .. } | SecretFileError::Symlink { .. } => KeyError::Open(error),
    }
}


pub fn key_from_bytes(key: Zeroizing<Vec<u8>>) -> Result<LinkKey, KeyError> {
    if key.len() < MIN_LINK_KEY_BYTES {
        Err(KeyError::TooShort { min: MIN_LINK_KEY_BYTES })
    } else {
        Ok(LinkKey(key))
    }
}


/// The key file checks need Unix modes and owners: elsewhere the key is refused before any read.
#[cfg(unix)]
pub fn require_unix() -> Result<(), KeyError> {
    Ok(())
}


#[cfg(not(unix))]
pub fn require_unix() -> Result<(), KeyError> {
    Err(KeyError::Unsupported)
}


/// Reads the signing key of the acknowledgement links: opened through the shared secret-file checks, then a bounded read.
pub fn read_link_key(path: &Path) -> Result<LinkKey, KeyError> {
    require_unix()?;
    let mut handle = open_secret(path).map_err(key_refusal)?;
    let bytes = read_secret(&mut handle, MAX_LINK_KEY_BYTES, &path.display().to_string())?;
    key_from_bytes(bytes)
}

use crate::error::KeyError;
use crate::limits::{MAX_LINK_KEY_BYTES, MIN_LINK_KEY_BYTES};
use crate::types::LinkKey;
use core_pg::password::{open_regular, read_capped};
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;


pub const GROUP_OTHER_MASK: u32 = 0o077;


/// Mode bits and owner of the opened handle, with the effective user of the process.
#[cfg(unix)]
pub fn mode_and_owners(metadata: &Metadata) -> (u32, u32, u32) {
    (metadata.mode(), metadata.uid(), rustix::process::geteuid().as_raw())
}


#[cfg(not(unix))]
pub fn mode_and_owners(_metadata: &Metadata) -> (u32, u32, u32) {
    (0, 0, 0)
}


/// The key file must grant nothing to group or other and belong to the process user.
pub fn check_owner_and_mode(mode: u32, owner: u32, process_user: u32) -> Result<(), KeyError> {
    if mode & GROUP_OTHER_MASK != 0 {
        Err(KeyError::Mode)
    } else if owner != process_user {
        Err(KeyError::Owner)
    } else {
        Ok(())
    }
}


pub fn key_from_bytes(bytes: Vec<u8>) -> Result<LinkKey, KeyError> {
    let key = Zeroizing::new(bytes);
    if key.len() < MIN_LINK_KEY_BYTES {
        Err(KeyError::TooShort { min: MIN_LINK_KEY_BYTES })
    } else {
        Ok(key)
    }
}


/// Reads the signing key of the acknowledgement links: opened without blocking, regular file, mode and owner judged on the opened handle, bounded read.
pub fn read_link_key(path: &Path) -> Result<LinkKey, KeyError> {
    let mut handle = open_regular(path)?;
    let metadata = handle.metadata().map_err(KeyError::Inspect)?;
    let (mode, owner, process_user) = mode_and_owners(&metadata);
    check_owner_and_mode(mode, owner, process_user)?;
    let bytes = read_capped(&mut handle, MAX_LINK_KEY_BYTES, &path.display().to_string())?;
    key_from_bytes(bytes)
}

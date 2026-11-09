use crate::error::ScriptError;
use crate::model::Manifest;
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};


/// Digests the bytes it is given and returns those same bytes, so the caller runs exactly what was checked.
pub fn check_digest(manifest: &Manifest, script_bytes: Vec<u8>) -> Result<Vec<u8>, ScriptError> {
    let actual = HEXLOWER.encode(&Sha256::digest(&script_bytes));
    if actual == manifest.sha256 {
        Ok(script_bytes)
    } else {
        Err(ScriptError::DigestMismatch)
    }
}

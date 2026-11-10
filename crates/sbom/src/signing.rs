//! Detached Ed25519 signatures over the exact SBOM bytes, bound to tenant, artefact and version.

use crate::diff::diff;
use crate::error::SigningError;
use crate::limits::{KEY_FILE_BUFFER_CAPACITY, KEY_FILE_HEX_LENGTH, KEY_FILE_READ_LIMIT, SBOM_SIGNING_CONTEXT};
use crate::model::{DocumentMeta, DocumentSignature, Limits, Sbom, SbomDiff, SignedDocument, TrustedKey};
use crate::parse::parse_cyclonedx;
use crate::types::{SignerFn, TrustedKeys};
use core_audit::log::check_private;
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Signer, SigningKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read};
use std::path::Path;
use tracing::warn;
use zeroize::Zeroizing;


pub fn length_prefixed(text: &str) -> Vec<u8> {
    let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
    [length.to_be_bytes().as_slice(), text.as_bytes()].concat()
}


/// Context, length-prefixed tenant and artefact, version, then the SHA-256 of the exact document bytes.
pub fn signing_message(bytes: &[u8], meta: &DocumentMeta) -> Vec<u8> {
    [
        SBOM_SIGNING_CONTEXT,
        &length_prefixed(&meta.tenant),
        &length_prefixed(&meta.artefact),
        &meta.version.to_be_bytes(),
        &Sha256::digest(bytes),
    ]
    .concat()
}


pub fn check_size(bytes: &[u8], limits: &Limits) -> Result<(), SigningError> {
    if bytes.len() > limits.max_bytes {
        Err(SigningError::TooLarge { max: limits.max_bytes })
    } else {
        Ok(())
    }
}


pub fn sign_document(bytes: &[u8], meta: &DocumentMeta, key_id: &str, signer: &SignerFn, limits: &Limits) -> Result<DocumentSignature, SigningError> {
    check_size(bytes, limits)?;
    let signature = signer(&signing_message(bytes, meta)).map_err(SigningError::Signer)?;
    Ok(DocumentSignature {
        key_id: key_id.to_owned(),
        bytes: signature,
    })
}


/// A signer over an in-memory key.
pub fn memory_signer(key: SigningKey) -> Box<SignerFn> {
    Box::new(move |message| Ok(key.sign(message).to_bytes().to_vec()))
}


pub fn check_key(key: &TrustedKey, now: u64) -> Result<(), SigningError> {
    if key.revoked {
        Err(SigningError::KeyRevoked)
    } else if now < key.not_before || now > key.not_after {
        Err(SigningError::KeyOutsideValidity)
    } else {
        Ok(())
    }
}


pub fn check_signature(key: &TrustedKey, message: &[u8], signature: &DocumentSignature) -> Result<(), SigningError> {
    let array = <[u8; SIGNATURE_LENGTH]>::try_from(signature.bytes.as_slice()).map_err(|_| SigningError::BadSignature)?;
    key.public_key
        .verify_strict(message, &Signature::from_bytes(&array))
        .map_err(|_| SigningError::BadSignature)
}


pub fn check_document(
    bytes: &[u8],
    meta: &DocumentMeta,
    signature: &DocumentSignature,
    trusted_keys: &TrustedKeys,
    now: u64,
    limits: &Limits,
) -> Result<(), SigningError> {
    check_size(bytes, limits)?;
    let key = trusted_keys.get(&signature.key_id).ok_or(SigningError::UnknownKey)?;
    check_key(key, now)?;
    check_signature(key, &signing_message(bytes, meta), signature)
}


/// Fails closed; the refusal is logged with its reason only.
pub fn verify_document(
    bytes: &[u8],
    meta: &DocumentMeta,
    signature: &DocumentSignature,
    trusted_keys: &TrustedKeys,
    now: u64,
    limits: &Limits,
) -> Result<(), SigningError> {
    check_document(bytes, meta, signature, trusted_keys, now, limits).inspect_err(|refusal| warn!(reason = %refusal, "SBOM signature refused"))
}


pub fn check_version(previous: u64, next: u64) -> Result<(), SigningError> {
    if next > previous {
        Ok(())
    } else {
        Err(SigningError::VersionNotIncreasing { previous, next })
    }
}


/// Verifies the bytes, then parses those same bytes.
pub fn parse_verified(document: &SignedDocument, trusted_keys: &TrustedKeys, now: u64, limits: &Limits) -> Result<Sbom, SigningError> {
    verify_document(&document.bytes, &document.meta, &document.signature, trusted_keys, now, limits)?;
    Ok(parse_cyclonedx(
        Cursor::new(&document.bytes),
        &document.meta.tenant,
        &document.meta.artefact,
        limits,
    )?)
}


/// Both documents are verified before anything is compared.
pub fn diff_signed(
    old: &SignedDocument,
    new: &SignedDocument,
    trusted_keys: &TrustedKeys,
    now: u64,
    limits: &Limits,
) -> Result<SbomDiff, SigningError> {
    let old_sbom = parse_verified(old, trusted_keys, now, limits)?;
    let new_sbom = parse_verified(new, trusted_keys, now, limits)?;
    check_version(old.meta.version, new.meta.version)?;
    Ok(diff(&old_sbom, &new_sbom)?)
}


pub fn check_owner(file_owner: u32, process_owner: u32) -> Result<(), SigningError> {
    if file_owner == process_owner {
        Ok(())
    } else {
        Err(SigningError::KeyWrongOwner)
    }
}


#[cfg(unix)]
pub fn check_key_owner(file: &File) -> Result<(), SigningError> {
    use std::os::unix::fs::MetadataExt;
    check_owner(file.metadata()?.uid(), rustix::process::geteuid().as_raw())
}


#[cfg(not(unix))]
pub fn check_key_owner(_file: &File) -> Result<(), SigningError> {
    Err(SigningError::KeyUnsupported)
}


/// The seed is 64 hexadecimal characters; no error carries it.
pub fn parse_seed(text: &str) -> Result<SigningKey, SigningError> {
    let trimmed = text.trim();
    if trimmed.len() == KEY_FILE_HEX_LENGTH {
        let bytes = Zeroizing::new(HEXLOWER.decode(trimmed.as_bytes())?);
        let seed = Zeroizing::new(<[u8; SECRET_KEY_LENGTH]>::try_from(bytes.as_slice())?);
        Ok(SigningKey::from_bytes(&seed))
    } else {
        Err(SigningError::KeyLength)
    }
}


/// Mode and owner are checked on the open handle, and the seed is read from that same handle; one byte over the limit is refused.
pub fn read_signing_key(file: File) -> Result<SigningKey, SigningError> {
    parse_seed(&read_private_text(file, KEY_FILE_READ_LIMIT, KEY_FILE_BUFFER_CAPACITY)?)
}


/// The text sits in a zeroised buffer pre-sized to `capacity`; one byte over `limit` is refused.
pub fn read_private_text(file: File, limit: u64, capacity: usize) -> Result<Zeroizing<String>, SigningError> {
    check_private(&file)?;
    check_key_owner(&file)?;
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    let mut capped = file.take(limit.saturating_add(1));
    capped.read_to_string(&mut text)?;
    if capped.limit() == 0 {
        Err(SigningError::KeyTooLarge)
    } else {
        Ok(text)
    }
}


pub fn load_private_text(path: &Path, limit: u64, capacity: usize) -> Result<Zeroizing<String>, SigningError> {
    read_private_text(open_regular(path)?, limit, capacity)
}


/// Opens without blocking on a FIFO or device and refuses anything but a regular file, judged on the opened handle.
pub fn open_regular(path: &Path) -> Result<File, SigningError> {
    let file = non_blocking(OpenOptions::new().read(true)).open(path)?;
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(SigningError::KeyNotRegular)
    }
}


#[cfg(unix)]
pub fn non_blocking(options: &mut OpenOptions) -> &mut OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
}


#[cfg(not(unix))]
pub fn non_blocking(options: &mut OpenOptions) -> &mut OpenOptions {
    options
}


pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    read_signing_key(open_regular(path)?)
}

//! Signed SBOM versions in an S3-compatible bucket, under `<tenant>/<artefact>/<version>.cdx.json` with the signature beside it.

use crate::error::StoreError;
use crate::limits::{HTTP_OK_FIRST, HTTP_OK_LAST, MAX_NAME_BYTES, MAX_SIGNATURE_OBJECT_BYTES, STORE_DOCUMENT_SUFFIX, STORE_SIGNATURE_SUFFIX};
use crate::model::{DocumentMeta, DocumentSignature, HttpRequest, Limits, ObjectKeys, SbomDiff, SignedDocument, Store, StoreMethod, StoreScope};
use crate::settings::ensure;
use crate::signing::{check_size, check_version, diff_signed, verify_document};
use crate::types::TrustedKeys;
use data_encoding::HEXLOWER;
use rusty_s3::S3Action;


/// A name is one path segment: no separator, no `..`, no leading `-` or `.`, no whitespace or control character.
pub fn validate_name(field: &'static str, value: &str) -> Result<(), StoreError> {
    let unusable = value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.starts_with(['-', '.'])
        || value.contains("..")
        || value.contains(['/', '\\'])
        || value.chars().any(|character| character.is_control() || character.is_whitespace());
    ensure(!unusable, StoreError::InvalidName(field))
}


pub fn object_keys(meta: &DocumentMeta) -> Result<ObjectKeys, StoreError> {
    validate_name("tenant", &meta.tenant)?;
    validate_name("artefact", &meta.artefact)?;
    let base = format!("{}/{}/{}", meta.tenant, meta.artefact, meta.version);
    Ok(ObjectKeys {
        document: format!("{base}{STORE_DOCUMENT_SUFFIX}"),
        signature: format!("{base}{STORE_SIGNATURE_SUFFIX}"),
    })
}


pub fn check_scope(scope: &StoreScope, tenant: &str) -> Result<(), StoreError> {
    ensure(scope.tenant == tenant, StoreError::OutsideScope)
}


/// The presigned URL is a bearer for its short lifetime: it is never logged.
pub fn presign(store: &Store, method: StoreMethod, key: &str) -> String {
    let credentials = Some(&store.credentials);
    match method {
        StoreMethod::Get => store.bucket.get_object(credentials, key).sign(store.expiry).to_string(),
        StoreMethod::Put => store.bucket.put_object(credentials, key).sign(store.expiry).to_string(),
    }
}


/// Only a 2xx answer counts; a redirect is a failure.
pub fn exchange(store: &Store, method: StoreMethod, key: &str, body: Vec<u8>, max_response: usize) -> Result<Vec<u8>, StoreError> {
    let request = HttpRequest {
        method,
        url: presign(store, method, key),
        body,
        max_response,
    };
    let response = (store.http)(&request).map_err(StoreError::Transport)?;
    ensure(
        (HTTP_OK_FIRST..=HTTP_OK_LAST).contains(&response.status),
        StoreError::Status(response.status),
    )?;
    Ok(response.body)
}


pub fn encode_signature(signature: &DocumentSignature) -> Result<Vec<u8>, StoreError> {
    validate_name("key id", &signature.key_id)?;
    Ok(format!("{} {}\n", signature.key_id, HEXLOWER.encode(&signature.bytes)).into_bytes())
}


pub fn decode_signature(bytes: &[u8]) -> Result<DocumentSignature, StoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::BadSignatureObject)?;
    let (key_id, hex) = text.trim_end().split_once(' ').ok_or(StoreError::BadSignatureObject)?;
    validate_name("key id", key_id).map_err(|_| StoreError::BadSignatureObject)?;
    let decoded = HEXLOWER.decode(hex.as_bytes()).map_err(|_| StoreError::BadSignatureObject)?;
    Ok(DocumentSignature {
        key_id: key_id.to_owned(),
        bytes: decoded,
    })
}


/// Document first, signature second; a reader that finds no signature refuses the version.
pub fn put_version(store: &Store, scope: &StoreScope, document: &SignedDocument, limits: &Limits) -> Result<(), StoreError> {
    check_scope(scope, &document.meta.tenant)?;
    check_size(&document.bytes, limits)?;
    let keys = object_keys(&document.meta)?;
    let signature = encode_signature(&document.signature)?;
    exchange(store, StoreMethod::Put, &keys.document, document.bytes.clone(), 0)?;
    exchange(store, StoreMethod::Put, &keys.signature, signature, 0)?;
    Ok(())
}


/// Downloads under `max_bytes + 1`; the result is not verified, use `read_version`.
pub fn fetch_signed(store: &Store, scope: &StoreScope, meta: &DocumentMeta, limits: &Limits) -> Result<SignedDocument, StoreError> {
    check_scope(scope, &meta.tenant)?;
    let keys = object_keys(meta)?;
    let bytes = exchange(store, StoreMethod::Get, &keys.document, Vec::new(), limits.max_bytes + 1)?;
    ensure(bytes.len() <= limits.max_bytes, StoreError::TooLarge { max: limits.max_bytes })?;
    let signature_bytes = exchange(store, StoreMethod::Get, &keys.signature, Vec::new(), MAX_SIGNATURE_OBJECT_BYTES + 1)?;
    ensure(signature_bytes.len() <= MAX_SIGNATURE_OBJECT_BYTES, StoreError::BadSignatureObject)?;
    Ok(SignedDocument {
        bytes,
        meta: meta.clone(),
        signature: decode_signature(&signature_bytes)?,
    })
}


/// The signature is checked on the bytes just read, against the requested tenant, artefact and version.
pub fn read_version(
    store: &Store,
    scope: &StoreScope,
    meta: &DocumentMeta,
    trusted_keys: &TrustedKeys,
    now: u64,
    limits: &Limits,
) -> Result<SignedDocument, StoreError> {
    let document = fetch_signed(store, scope, meta, limits)?;
    verify_document(&document.bytes, &document.meta, &document.signature, trusted_keys, now, limits)?;
    Ok(document)
}


/// Both versions are read, verified and parsed before any comparison; the newer one must have the higher version.
pub fn diff_versions(
    store: &Store,
    scope: &StoreScope,
    old: &DocumentMeta,
    new: &DocumentMeta,
    trusted_keys: &TrustedKeys,
    now: u64,
    limits: &Limits,
) -> Result<SbomDiff, StoreError> {
    check_version(old.version, new.version)?;
    let old_document = fetch_signed(store, scope, old, limits)?;
    let new_document = fetch_signed(store, scope, new, limits)?;
    Ok(diff_signed(&old_document, &new_document, trusted_keys, now, limits)?)
}

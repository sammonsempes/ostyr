use crate::error::ConnectorError;
use crate::keys::load_signing_key;
use crate::manifest::{parse_manifest, valid_name};
use crate::model::{FileDigest, Package, SignatureFile, TrustedKeys, Verified, SIGNATURE_NAME};
use crate::package::{io_at, io_error, read_package};
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Signer, SigningKey, SIGNATURE_LENGTH};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;


pub const MAGIC_LINE: &str = "ostyr-connector-v1\n";


pub const SIGNATURE_PARTS: usize = 3;


/// The signed document: the magic line, then one `<path> <sha256> <size>` line per file, sorted by path, the signature file excluded.
pub fn signed_document(files: &BTreeMap<String, FileDigest>) -> String {
    files.iter().fold(MAGIC_LINE.to_owned(), |mut text, (path, digest)| {
        text.push_str(&format!("{path} {} {}\n", digest.sha256, digest.size));
        text
    })
}


pub fn parse_file_line(line: &str) -> Result<(String, FileDigest), ConnectorError> {
    match line.split(' ').collect::<Vec<&str>>().as_slice() {
        [path, sha256, size] => Ok((
            (*path).to_owned(),
            FileDigest {
                sha256: (*sha256).to_owned(),
                size: size.parse().map_err(|_| ConnectorError::MalformedSignature)?,
            },
        )),
        _ => Err(ConnectorError::MalformedSignature),
    }
}


/// The signed file list back from its text; a path listed twice is malformed.
pub fn read_document(text: &str) -> Result<BTreeMap<String, FileDigest>, ConnectorError> {
    let body = text.strip_prefix(MAGIC_LINE).ok_or(ConnectorError::MalformedSignature)?;
    body.lines().try_fold(BTreeMap::new(), |mut files, line| {
        let (path, digest) = parse_file_line(line)?;
        files
            .insert(path, digest)
            .is_none()
            .then_some(files)
            .ok_or(ConnectorError::MalformedSignature)
    })
}


/// `key <id>`, `signature <hex>`, then the signed document; the key id obeys the name grammar so it can be shown.
pub fn parse_signature_file(bytes: &[u8]) -> Result<SignatureFile, ConnectorError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ConnectorError::MalformedSignature)?;
    let mut parts = text.splitn(SIGNATURE_PARTS, '\n');
    match (
        parts.next().and_then(|line| line.strip_prefix("key ")),
        parts.next().and_then(|line| line.strip_prefix("signature ")),
        parts.next(),
    ) {
        (Some(key_id), Some(hex), Some(document)) if valid_name(key_id) => {
            let decoded = HEXLOWER.decode(hex.as_bytes()).map_err(|_| ConnectorError::MalformedSignature)?;
            let array = <[u8; SIGNATURE_LENGTH]>::try_from(decoded.as_slice()).map_err(|_| ConnectorError::MalformedSignature)?;
            Ok(SignatureFile {
                key_id: key_id.to_owned(),
                signature: Signature::from_bytes(&array),
                document: document.to_owned(),
            })
        }
        _ => Err(ConnectorError::MalformedSignature),
    }
}


/// The first file whose digest differs from the signed list: added, changed, then removed.
pub fn first_difference(signed: &BTreeMap<String, FileDigest>, actual: &BTreeMap<String, FileDigest>) -> Option<ConnectorError> {
    actual
        .iter()
        .find_map(|(path, digest)| match signed.get(path) {
            None => Some(ConnectorError::FileAdded { path: path.clone() }),
            Some(expected) if expected != digest => Some(ConnectorError::FileChanged { path: path.clone() }),
            Some(_) => None,
        })
        .or_else(|| {
            signed
                .keys()
                .find(|path| !actual.contains_key(*path))
                .map(|path| ConnectorError::FileRemoved { path: path.clone() })
        })
}


/// Signature first, against the signed list; the actual files are compared with that list only once it is authentic.
pub fn check_package(package: &Package, keys: &TrustedKeys, now: u64) -> Result<Verified, ConnectorError> {
    let signature = parse_signature_file(package.signature.as_deref().ok_or(ConnectorError::MissingSignature)?)?;
    let key = keys.keys.get(&signature.key_id).ok_or_else(|| ConnectorError::UnknownKey {
        key_id: signature.key_id.clone(),
    })?;
    (now <= key.not_after).then_some(()).ok_or_else(|| ConnectorError::KeyExpired {
        key_id: signature.key_id.clone(),
    })?;
    key.public_key
        .verify_strict(signature.document.as_bytes(), &signature.signature)
        .map_err(|_| ConnectorError::BadSignature)?;
    first_difference(&read_document(&signature.document)?, &package.files).map_or(Ok(()), Err)?;
    let manifest = parse_manifest(&package.manifest)?;
    (manifest.publisher == key.publisher)
        .then_some(())
        .ok_or(ConnectorError::WrongPublisher)?;
    Ok(Verified {
        manifest,
        files: package.files.keys().cloned().collect(),
    })
}


pub fn verify_package(directory: &Path, keys: &TrustedKeys, now: u64) -> Result<Verified, ConnectorError> {
    check_package(&read_package(directory)?, keys, now)
}


/// The signature file text for an already read package; a manifest that does not validate is never signed.
pub fn sign_package(package: &Package, key_id: &str, key: &SigningKey) -> Result<String, ConnectorError> {
    parse_manifest(&package.manifest)?;
    let document = signed_document(&package.files);
    let signature = key.sign(document.as_bytes());
    Ok(format!("key {key_id}\nsignature {}\n{document}", HEXLOWER.encode(&signature.to_bytes())))
}


/// Written to a temporary file in the directory then renamed over `connector.sig`, so a symlink there is replaced, never followed.
pub fn write_signature(directory: &Path, text: &str) -> Result<(), ConnectorError> {
    let label = directory.display().to_string();
    let mut staged = NamedTempFile::new_in(directory).map_err(io_at(&label))?;
    staged.write_all(text.as_bytes()).map_err(io_at(&label))?;
    staged
        .persist(directory.join(SIGNATURE_NAME))
        .map(|_| ())
        .map_err(|error| io_error(&label, error.error))
}


/// Reads the package, signs it with the key file's key and writes `connector.sig`; returns the number of files covered.
pub fn sign_directory(directory: &Path, key_file: &Path) -> Result<usize, ConnectorError> {
    let (key_id, key) = load_signing_key(key_file)?;
    let package = read_package(directory)?;
    let text = sign_package(&package, &key_id, &key)?;
    write_signature(directory, &text).map(|()| package.files.len())
}

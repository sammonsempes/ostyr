use crate::error::ConnectorError;
use crate::model::{FileDigest, Limits, Package, DEFAULT_LIMITS, MANIFEST_NAME};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::Path;


pub fn io_error(path: &str, source: io::Error) -> ConnectorError {
    ConnectorError::Io {
        path: path.to_owned(),
        source,
    }
}


pub fn io_at(path: &str) -> impl Fn(io::Error) -> ConnectorError + '_ {
    move |source| io_error(path, source)
}


/// Reads at most `max` bytes; one byte more is refused naming `path`.
pub fn read_capped(source: &mut dyn Read, max: u64, path: &str) -> Result<Vec<u8>, ConnectorError> {
    let mut bytes = Vec::new();
    source.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(io_at(path))?;
    (bytes.len() as u64 <= max)
        .then_some(bytes)
        .ok_or_else(|| ConnectorError::FileTooLarge { path: path.to_owned(), max })
}


pub fn digest_bytes(bytes: &[u8]) -> FileDigest {
    FileDigest {
        sha256: HEXLOWER.encode(&Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}


/// Hashes a stream of at most `max` bytes without keeping it; one byte more is refused naming `path`.
pub fn hash_capped(source: &mut dyn Read, max: u64, path: &str) -> Result<FileDigest, ConnectorError> {
    let mut hasher = Sha256::new();
    let size = io::copy(&mut source.take(max.saturating_add(1)), &mut hasher).map_err(io_at(path))?;
    let digest = FileDigest {
        sha256: HEXLOWER.encode(&hasher.finalize()),
        size,
    };
    (size <= max)
        .then_some(digest)
        .ok_or_else(|| ConnectorError::FileTooLarge { path: path.to_owned(), max })
}


/// The package is complete only with its manifest.
pub fn finish_package(package: Package) -> Result<Package, ConnectorError> {
    package
        .files
        .contains_key(MANIFEST_NAME)
        .then_some(package)
        .ok_or(ConnectorError::MissingManifest)
}


#[cfg(target_os = "linux")]
pub fn read_package_with(directory: &Path, limits: &Limits) -> Result<Package, ConnectorError> {
    crate::scan::scan_directory(directory, limits).and_then(finish_package)
}


#[cfg(not(target_os = "linux"))]
pub fn read_package_with(_directory: &Path, _limits: &Limits) -> Result<Package, ConnectorError> {
    Err(ConnectorError::Unsupported)
}


/// The directory is opened once; every file is read and hashed through the handle opened in it.
pub fn read_package(directory: &Path) -> Result<Package, ConnectorError> {
    read_package_with(directory, &DEFAULT_LIMITS)
}

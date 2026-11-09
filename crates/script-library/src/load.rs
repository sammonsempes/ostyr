use crate::check::{check_manifest, ensure};
use crate::error::ScriptError;
use crate::model::{Manifest, MAX_MANIFEST_BYTES};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
#[cfg(unix)]
use rustix::fs::OFlags;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;


/// Reads at most `MAX_MANIFEST_BYTES`, parses strictly and bounds every field; `file` only labels errors.
pub fn read_manifest<Source: Read>(source: Source, file: &str) -> Result<Manifest, ScriptError> {
    let mut limited = source.take(MAX_MANIFEST_BYTES as u64 + 1);
    let text = read_text(&mut limited, file)?;
    ensure(
        text.len() <= MAX_MANIFEST_BYTES,
        ScriptError::ManifestTooLarge { max: MAX_MANIFEST_BYTES },
    )?;
    let manifest: Manifest = parse_document(&text, file)?;
    check_manifest(&manifest)?;
    Ok(manifest)
}


/// `O_NONBLOCK` so that opening a FIFO returns at once; the handle is then checked with `fstat`, not the path.
#[cfg(unix)]
pub fn open_without_blocking(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(OFlags::NONBLOCK.bits() as i32).open(path)
}


#[cfg(not(unix))]
pub fn open_without_blocking(path: &Path) -> io::Result<File> {
    File::open(path)
}


pub fn load_manifest(path: &Path) -> Result<Manifest, ScriptError> {
    let file = path.display().to_string();
    let (handle, regular) = open_without_blocking(path)
        .and_then(|opened| opened.metadata().map(|metadata| (opened, metadata.is_file())))
        .map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    ensure(regular, ScriptError::NotRegularFile(file.clone()))?;
    read_manifest(handle, &file)
}

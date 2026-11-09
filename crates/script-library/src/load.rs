use crate::check::{check_manifest, ensure};
use crate::error::ScriptError;
use crate::model::{Manifest, MAX_MANIFEST_BYTES};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
use std::fs::File;
use std::io::Read;
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


pub fn load_manifest(path: &Path) -> Result<Manifest, ScriptError> {
    let file = path.display().to_string();
    let handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    read_manifest(handle, &file)
}

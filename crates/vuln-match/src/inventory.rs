//! Package inventory files: one `<asset>.json` per asset in a directory, each a JSON list of `{ecosystem, name, version}`.

use crate::limits::MAX_LOGGED_NAME_CHARS;
use crate::model::Package;
use crate::store::is_field;
use crate::text::bounded_text;
use core_config::error::ConfigError;
use core_config::parse::read_bytes_capped;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::ffi::OsStr;
use std::fs::{read_dir, DirEntry};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::warn;


pub const MAX_INVENTORY_FILES: usize = 10_000;


pub const MAX_INVENTORY_BYTES: u64 = 8_388_608;


pub const MAX_INVENTORY_PACKAGES: usize = 50_000;


pub const INVENTORY_SUFFIX: &str = ".json";


#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("the inventory directory cannot be read")]
    Directory(#[source] io::Error),
    #[error("the inventory file cannot be read: {0}")]
    Read(#[source] ConfigError),
    #[error("the inventory is not a JSON list")]
    NotList,
    #[error("the inventory holds {count} entries, the limit is {max}")]
    TooMany { count: usize, max: usize },
    #[error("{bad} inventory entries are not ecosystem, name and version texts")]
    BadEntries { bad: usize },
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}


/// The inventory files found: asset id and path, the entries refused, and whether the directory held more than the cap.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub files: Vec<(String, PathBuf)>,
    pub refused: usize,
    pub over_cap: bool,
}


/// The asset id of a file name: `<asset>.json`, the asset in the store grammar and not starting with a dot.
pub fn asset_of(name: &OsStr) -> Option<String> {
    name.to_str()
        .and_then(|text| text.strip_suffix(INVENTORY_SUFFIX))
        .filter(|asset| is_field(asset) && !asset.starts_with('.'))
        .map(str::to_owned)
}


/// A file name made loggable: printable ASCII, cut, debug-escaped.
pub fn loggable(name: &OsStr) -> String {
    format!("{:?}", bounded_text(&name.to_string_lossy(), MAX_LOGGED_NAME_CHARS))
}


/// The list is counted as borrowed raw values before any entry is parsed; one bad entry refuses the whole file.
pub fn parse_inventory_capped(bytes: &[u8], max_packages: usize) -> Result<Vec<Package>, InventoryError> {
    let raw: Vec<&RawValue> = serde_json::from_slice(bytes).map_err(|_not_list| InventoryError::NotList)?;
    if raw.len() > max_packages {
        Err(InventoryError::TooMany {
            count: raw.len(),
            max: max_packages,
        })
    } else {
        let parsed: Vec<Option<Package>> = raw.iter().map(|entry| entry_of(entry)).collect();
        let bad = parsed.iter().filter(|entry| entry.is_none()).count();
        if bad > 0 {
            Err(InventoryError::BadEntries { bad })
        } else {
            Ok(parsed.into_iter().flatten().collect())
        }
    }
}


pub fn entry_of(raw: &RawValue) -> Option<Package> {
    serde_json::from_str::<InventoryEntry>(raw.get())
        .ok()
        .filter(|entry| is_field(&entry.ecosystem) && is_field(&entry.name) && is_field(&entry.version))
        .map(|entry| Package {
            ecosystem: entry.ecosystem,
            name: entry.name,
            version: entry.version,
        })
}


pub fn read_inventory_capped(path: &Path, max_bytes: u64, max_packages: usize) -> Result<Vec<Package>, InventoryError> {
    let bytes = read_bytes_capped(path, max_bytes).map_err(InventoryError::Read)?;
    parse_inventory_capped(&bytes, max_packages)
}


pub fn read_inventory(path: &Path) -> Result<Vec<Package>, InventoryError> {
    read_inventory_capped(path, MAX_INVENTORY_BYTES, MAX_INVENTORY_PACKAGES)
}


/// The asset and path of a regular file named `<asset>.json`; anything else (a link, a FIFO, a directory) is refused without being opened.
pub fn accepted(found: io::Result<DirEntry>) -> Option<(String, PathBuf)> {
    match found {
        Ok(entry) => {
            let name = entry.file_name();
            let regular = entry.file_type().is_ok_and(|kind| kind.is_file());
            let asset = asset_of(&name).filter(|_asset| regular);
            if asset.is_none() {
                let shown = loggable(&name);
                warn!(name = shown, "inventory entry refused, not a regular file named <asset>.json");
            }
            asset.map(|id| (id, entry.path()))
        }
        Err(error) => {
            warn!(%error, "inventory entry unreadable");
            None
        }
    }
}


/// Reads the first `max_files` entries of the directory; one more sets `over_cap`.
pub fn list_inventory_capped(dir: &Path, max_files: usize) -> Result<Listing, InventoryError> {
    let mut entries = read_dir(dir).map_err(InventoryError::Directory)?;
    let kept: Vec<io::Result<DirEntry>> = entries.by_ref().take(max_files).collect();
    let over_cap = entries.next().is_some();
    let seen = kept.len();
    let mut files: Vec<(String, PathBuf)> = kept.into_iter().filter_map(accepted).collect();
    files.sort();
    let refused = seen - files.len();
    Ok(Listing { files, refused, over_cap })
}


pub fn list_inventory(dir: &Path) -> Result<Listing, InventoryError> {
    list_inventory_capped(dir, MAX_INVENTORY_FILES)
}

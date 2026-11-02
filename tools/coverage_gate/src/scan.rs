use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};

use crate::error::GateError;

const SOURCE_DIR: &str = "src";
const SOURCE_EXTENSION: &str = "rs";
const BUILD_DIR: &str = "target";
const HIDDEN_PREFIX: &str = ".";

pub fn is_skipped(name: &OsStr) -> bool {
    name == BUILD_DIR || name.to_str().is_some_and(|text| text.starts_with(HIDDEN_PREFIX))
}

pub fn is_source(entry: &DirEntry, root_depth: usize) -> bool {
    entry.file_type().is_file()
        && entry.path().extension() == Some(OsStr::new(SOURCE_EXTENSION))
        && entry.path().components().skip(root_depth).any(|part| part.as_os_str() == SOURCE_DIR)
}

pub fn find_sources(root: &Path) -> Result<Vec<PathBuf>, GateError> {
    let root_depth = root.components().count();
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || !is_skipped(entry.file_name()))
        .filter_map(|walked| {
            walked
                .map_err(GateError::from)
                .map(|entry| is_source(&entry, root_depth).then(|| entry.into_path()))
                .transpose()
        })
        .collect()
}

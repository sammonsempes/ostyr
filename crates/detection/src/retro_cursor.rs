//! Retro cursors: per (tenant, rule source fingerprint) the next second to read and the current step, in one file saved atomically.

use crate::error::CursorError;
use crate::store::{open_new, sync_directory, temp_name};
use crate::types::{FileSyncFn, RenameFn, SyncDirFn};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;


pub const CURSOR_VERSION: u32 = 1;


pub const MAX_CURSOR_BYTES: u64 = 16_777_216;


/// Where one rule stands for one tenant: `next` is the first epoch second not yet settled, `step` the current window length in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorEntry {
    pub tenant: String,
    pub fingerprint: String,
    pub next: i64,
    pub step: i64,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetroCursors {
    pub entries: Vec<CursorEntry>,
}


#[derive(Debug, Serialize)]
pub struct CursorView<'a> {
    pub version: u32,
    pub cursors: &'a RetroCursors,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorDocument {
    pub version: u32,
    pub cursors: RetroCursors,
}


pub fn find_entry<'a>(cursors: &'a RetroCursors, tenant: &str, fingerprint: &str) -> Option<&'a CursorEntry> {
    cursors
        .entries
        .iter()
        .find(|entry| entry.tenant == tenant && entry.fingerprint == fingerprint)
}


/// The cursors with this entry replacing any entry of the same tenant and fingerprint, in a stable order.
pub fn upsert_entry(cursors: &RetroCursors, entry: CursorEntry) -> RetroCursors {
    let mut entries: Vec<CursorEntry> = cursors
        .entries
        .iter()
        .filter(|held| held.tenant != entry.tenant || held.fingerprint != entry.fingerprint)
        .cloned()
        .collect();
    entries.push(entry);
    entries.sort_by(|left, right| (&left.tenant, &left.fingerprint).cmp(&(&right.tenant, &right.fingerprint)));
    RetroCursors { entries }
}


/// Keeps the entries whose (tenant, fingerprint) is still live, so the file never outgrows tenants x retro rules.
pub fn prune_cursors(cursors: &RetroCursors, live: &[(String, String)]) -> RetroCursors {
    RetroCursors {
        entries: cursors
            .entries
            .iter()
            .filter(|entry| {
                live.iter()
                    .any(|(tenant, fingerprint)| *tenant == entry.tenant && *fingerprint == entry.fingerprint)
            })
            .cloned()
            .collect(),
    }
}


/// A cursor is an epoch second a `u32` holds; the step is clamped at use, never trusted.
pub fn check_cursors(cursors: &RetroCursors) -> Result<(), CursorError> {
    if cursors.entries.iter().all(|entry| u32::try_from(entry.next).is_ok()) {
        Ok(())
    } else {
        Err(CursorError::Range)
    }
}


/// One JSON document, flushed.
pub fn write_cursors<Output: Write>(output: &mut Output, cursors: &RetroCursors) -> Result<(), CursorError> {
    serde_json::to_writer(
        &mut *output,
        &CursorView {
            version: CURSOR_VERSION,
            cursors,
        },
    )
    .map_err(|error| CursorError::Write(io::Error::from(error)))?;
    output.flush().map_err(CursorError::Write)
}


/// Writes the `.new` sibling, syncs it, renames it over `path`, then syncs the directory: a crash leaves the old or the new file, never a half one.
pub fn save_cursors_with(
    path: &Path,
    cursors: &RetroCursors,
    sync_file: FileSyncFn,
    rename: RenameFn,
    sync_dir: SyncDirFn,
) -> Result<(), CursorError> {
    let temporary = temp_name(path);
    let mut file = open_new(&temporary).map_err(CursorError::Write)?;
    write_cursors(&mut file, cursors)?;
    sync_file(&file).map_err(CursorError::Write)?;
    rename(&temporary, path).map_err(CursorError::Write)?;
    sync_dir(path).map_err(CursorError::Write)
}


pub fn rename_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}


pub fn save_cursors(path: &Path, cursors: &RetroCursors) -> Result<(), CursorError> {
    save_cursors_with(path, cursors, File::sync_all, rename_file, sync_directory)
}


/// An absent file is no cursor yet; a file over the cap, one that does not parse, another version or a cursor out of range is an error, never an empty state.
pub fn load_cursors(path: &Path) -> Result<RetroCursors, CursorError> {
    match File::open(path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(RetroCursors::default()),
        Err(source) => Err(CursorError::Read(source)),
        Ok(file) => parse_cursors(file),
    }
}


fn parse_cursors(file: File) -> Result<RetroCursors, CursorError> {
    let mut bytes = Vec::new();
    file.take(MAX_CURSOR_BYTES + 1).read_to_end(&mut bytes).map_err(CursorError::Read)?;
    if bytes.len() as u64 > MAX_CURSOR_BYTES {
        Err(CursorError::TooLarge(MAX_CURSOR_BYTES))
    } else {
        let document: CursorDocument = serde_json::from_slice(&bytes).map_err(|_| CursorError::Corrupt)?;
        check_cursors(&document.cursors)?;
        if document.version == CURSOR_VERSION {
            Ok(document.cursors)
        } else {
            Err(CursorError::Version(document.version))
        }
    }
}

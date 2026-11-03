use crate::error::StoreError;
use crate::model::{Counter, LimitName};
use crate::types::SyncFn;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;


pub const HOUR_SECONDS: i64 = 3600;


pub const DAY_SECONDS: i64 = 86_400;


pub const TEMP_EXTENSION: &str = "tmp";


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at: i64,
    pub tenant: String,
    pub counter: Counter,
}


/// An administrator's lifting of one limit for one tenant until `until` (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub tenant: String,
    pub limit: LimitName,
    pub until: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreState {
    pub events: Vec<Event>,
    pub overrides: Vec<Override>,
}


/// `state` is replaced only after the new content is on disk.
pub struct Store {
    pub path: PathBuf,
    pub sync: SyncFn,
    pub state: Mutex<StoreState>,
}


fn io_error(context: &str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        context: format!("{context} {}", path.display()),
        source,
    }
}


/// Flushes a file or, on Unix, a directory to stable storage.
pub fn sync_path(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        sync_directory(path)
    } else {
        File::options().write(true).open(path).and_then(|file| file.sync_all())
    }
}


#[cfg(unix)]
pub fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|directory| directory.sync_all())
}


#[cfg(not(unix))]
pub fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}


/// A missing file is an empty store; an unreadable or malformed one is an error, so a damaged store never reads as empty.
pub fn open_store(path: &Path, sync: SyncFn) -> Result<Store, StoreError> {
    let state = match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(StoreError::from),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(StoreState::default()),
        Err(error) => Err(io_error("read", path, error)),
    }?;
    Ok(Store {
        path: path.to_path_buf(),
        sync,
        state: Mutex::new(state),
    })
}


pub fn parent_of(file: &Path) -> &Path {
    file.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}


/// Temporary file, fsync, rename, fsync of the directory: the state is complete on disk or the old one stays.
pub fn persist(path: &Path, state: &StoreState, sync: SyncFn) -> Result<(), StoreError> {
    let temporary = path.with_extension(TEMP_EXTENSION);
    serde_json::to_string(state)
        .map_err(StoreError::from)
        .and_then(|text| fs::write(&temporary, text).map_err(|source| io_error("write", &temporary, source)))?;
    sync(&temporary).map_err(|source| io_error("fsync", &temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error("rename", &temporary, source))?;
    sync(parent_of(path)).map_err(|source| io_error("fsync", parent_of(path), source))
}


/// Drops what no window or override can need any more.
pub fn prune(state: &StoreState, now: i64) -> StoreState {
    StoreState {
        events: state
            .events
            .iter()
            .filter(|event| now.saturating_sub(event.at) < DAY_SECONDS)
            .cloned()
            .collect(),
        overrides: state.overrides.iter().filter(|lifted| lifted.until > now).cloned().collect(),
    }
}


/// Events of one tenant and counter inside the last `window` seconds (the window is open at its far end).
pub fn count_in_window(state: &StoreState, tenant: &str, counter: Counter, now: i64, window: i64) -> u64 {
    state
        .events
        .iter()
        .filter(|event| event.tenant == tenant && event.counter == counter && now.saturating_sub(event.at) < window)
        .fold(0, |count, _| count.saturating_add(1))
}


pub fn is_overridden(state: &StoreState, tenant: &str, limit: LimitName, now: i64) -> bool {
    state
        .overrides
        .iter()
        .any(|lifted| lifted.tenant == tenant && lifted.limit == limit && lifted.until > now)
}

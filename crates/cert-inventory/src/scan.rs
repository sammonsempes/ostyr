//! Bounded scan of local directories for certificate files (spec section 23); each file is opened once and judged on its handle.

use crate::error::ScanError;
use crate::model::{FoundCert, ScanOutcome, SkipCounts};
use crate::parse::{parse_input, MAX_INPUT_BYTES};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};


pub const DEFAULT_MAX_DEPTH: usize = 8;


pub const MAX_DEPTH_CEILING: usize = 32;


pub const DEFAULT_MAX_FILES: usize = 1_000;


pub const MAX_FILES_CEILING: usize = 10_000;


pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 18;


pub const MAX_FILE_BYTES_CEILING: u64 = MAX_INPUT_BYTES as u64;


pub const MAX_ROOTS: usize = 64;


pub const MAX_EXTENSIONS: usize = 16;


pub const MAX_EXTENSION_BYTES: usize = 16;


pub const MAX_PATHS_PER_CERT: usize = 16;


pub const MAX_ERRORS: usize = 16;


pub const MAX_PATH_CHARS: usize = 256;


pub const CUT_MARKER: &str = "...[cut]";


pub const DEFAULT_EXTENSIONS: [&str; 4] = ["pem", "crt", "cer", "der"];


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSettings {
    pub roots: Vec<PathBuf>,
    pub max_depth: usize,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub extensions: Vec<String>,
}


impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            max_depth: DEFAULT_MAX_DEPTH,
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            extensions: DEFAULT_EXTENSIONS.iter().map(|extension| (*extension).to_string()).collect(),
        }
    }
}


/// What one candidate file turned out to be, judged on its open handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    Bytes(Vec<u8>),
    NotRegular,
    TooLarge,
}


#[derive(Default)]
struct ScanState {
    found: BTreeMap<String, FoundCert>,
    examined: usize,
    skipped: SkipCounts,
    private_keys_refused: usize,
    errors: Vec<String>,
    errors_omitted: usize,
}


/// Every bound is at least 1 and at most its ceiling; roots and extensions are counted the same way.
pub fn check_settings(settings: &ScanSettings) -> Result<(), ScanError> {
    check_bound("max_depth", settings.max_depth as u64, MAX_DEPTH_CEILING as u64)?;
    check_bound("max_files", settings.max_files as u64, MAX_FILES_CEILING as u64)?;
    check_bound("max_file_bytes", settings.max_file_bytes, MAX_FILE_BYTES_CEILING)?;
    check_bound("roots", settings.roots.len() as u64, MAX_ROOTS as u64)?;
    check_bound("extensions", settings.extensions.len() as u64, MAX_EXTENSIONS as u64)?;
    settings.extensions.iter().try_for_each(|extension| check_extension(extension))
}


fn check_bound(name: &'static str, value: u64, max: u64) -> Result<(), ScanError> {
    if value == 0 {
        Err(ScanError::Zero { name })
    } else if value > max {
        Err(ScanError::AboveCeiling { name, value, max })
    } else {
        Ok(())
    }
}


fn check_extension(extension: &str) -> Result<(), ScanError> {
    if extension.is_empty() || extension.len() > MAX_EXTENSION_BYTES || extension.contains(['.', '/', '\\']) {
        Err(ScanError::BadExtension { max: MAX_EXTENSION_BYTES })
    } else {
        Ok(())
    }
}


/// Scans every root; invalid settings scan nothing and are reported as one error.
pub fn scan(settings: &ScanSettings) -> ScanOutcome {
    let mut state = ScanState::default();
    match check_settings(settings) {
        Err(error) => record_error(&mut state, format!("invalid settings: {error}")),
        Ok(()) => settings.roots.iter().for_each(|root| scan_root(settings, root, &mut state)),
    }
    ScanOutcome {
        records: state.found.into_values().collect(),
        examined: state.examined,
        skipped: state.skipped,
        private_keys_refused: state.private_keys_refused,
        errors: state.errors,
        errors_omitted: state.errors_omitted,
    }
}


fn scan_root(settings: &ScanSettings, root: &Path, state: &mut ScanState) {
    WalkDir::new(root)
        .follow_links(false)
        .max_depth(settings.max_depth)
        .into_iter()
        .for_each(|entry| match entry {
            Err(error) => record_walk_error(state, error),
            Ok(found) if is_candidate(settings, &found) => examine(settings, state, found.path()),
            Ok(_) => (),
        });
}


fn is_candidate(settings: &ScanSettings, entry: &DirEntry) -> bool {
    !entry.file_type().is_dir()
        && entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| settings.extensions.iter().any(|wanted| wanted.eq_ignore_ascii_case(extension)))
}


fn examine(settings: &ScanSettings, state: &mut ScanState, path: &Path) {
    if state.examined >= settings.max_files {
        state.skipped.over_count += 1;
    } else {
        state.examined += 1;
        match load(path, settings.max_file_bytes) {
            Ok(Loaded::Bytes(bytes)) => absorb(state, path, &bytes),
            Ok(Loaded::NotRegular) => state.skipped.not_regular += 1,
            Ok(Loaded::TooLarge) => state.skipped.too_large += 1,
            Err(error) => {
                state.skipped.unreadable += 1;
                record_error(state, format!("{}: {}", error.kind(), cut_path(path)));
            }
        }
    }
}


/// Opens the path once without following a symlink, then judges and reads that handle only.
pub fn load(path: &Path, max_bytes: u64) -> Result<Loaded, io::Error> {
    match open_candidate(path) {
        Err(error) if is_symlink_refusal(&error) => Ok(Loaded::NotRegular),
        Err(error) => Err(error),
        Ok(file) => load_handle(file, max_bytes),
    }
}


fn load_handle(file: File, max_bytes: u64) -> Result<Loaded, io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        Ok(Loaded::NotRegular)
    } else if metadata.len() > max_bytes {
        Ok(Loaded::TooLarge)
    } else {
        read_bounded(file, max_bytes)
    }
}


/// Reads at most `max_bytes` plus one byte, so a file that grew past the cap after its size check is `TooLarge`.
pub fn read_bounded<Source: Read>(reader: Source, max_bytes: u64) -> Result<Loaded, io::Error> {
    let mut bytes = Vec::new();
    reader.take(max_bytes + 1).read_to_end(&mut bytes)?;
    Ok(if bytes.len() as u64 > max_bytes {
        Loaded::TooLarge
    } else {
        Loaded::Bytes(bytes)
    })
}


#[cfg(unix)]
fn open_candidate(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
}


#[cfg(unix)]
fn is_symlink_refusal(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}


#[cfg(not(unix))]
fn open_candidate(path: &Path) -> io::Result<File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    } else {
        File::open(path)
    }
}


#[cfg(not(unix))]
fn is_symlink_refusal(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidInput
}


fn absorb(state: &mut ScanState, path: &Path, bytes: &[u8]) {
    match parse_input(bytes) {
        Err(_) => state.skipped.malformed += 1,
        Ok(outcome) => {
            state.private_keys_refused += outcome.private_keys_refused;
            let text = cut_path(path);
            outcome.records.into_iter().for_each(|record| {
                let found = state.found.entry(record.fingerprint_sha256.clone()).or_insert_with(|| FoundCert {
                    record,
                    paths: Vec::new(),
                    paths_omitted: 0,
                });
                add_path(found, &text);
            });
        }
    }
}


fn add_path(found: &mut FoundCert, text: &str) {
    if found.paths.iter().all(|known| known != text) {
        if found.paths.len() < MAX_PATHS_PER_CERT {
            found.paths.push(text.to_string());
        } else {
            found.paths_omitted += 1;
        }
    }
}


fn record_walk_error(state: &mut ScanState, error: walkdir::Error) {
    let path_text = error.path().into_iter().map(cut_path).collect::<String>();
    let kind = io::Error::from(error).kind();
    record_error(state, format!("{kind}: {path_text}"));
}


fn record_error(state: &mut ScanState, text: String) {
    if state.errors.len() < MAX_ERRORS {
        state.errors.push(text);
    } else {
        state.errors_omitted += 1;
    }
}


/// Debug-escaped path text cut at `MAX_PATH_CHARS` characters with a visible marker.
pub fn cut_path(path: &Path) -> String {
    let escaped = path.to_string_lossy().escape_debug().to_string();
    if escaped.chars().count() > MAX_PATH_CHARS {
        format!("{}{CUT_MARKER}", escaped.chars().take(MAX_PATH_CHARS).collect::<String>())
    } else {
        escaped
    }
}

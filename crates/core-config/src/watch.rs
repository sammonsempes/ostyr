use crate::error::WatchError;
use crate::reload::{reload, ReloadEngine};
use crate::types::{NameEqFn, PathCheckFn};
use notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};


/// Reloads once per debounced batch holding an event on a watched file name; other events are only counted in `ignored`, never logged; a watcher error is logged.
pub fn handle_events<Config>(engine: &ReloadEngine<Config>, names: &[OsString], ignored: &AtomicUsize, result: DebounceEventResult) {
    match result {
        Ok(events) if events.iter().any(|event| is_watched(event, names)) => {
            let outcome = reload(engine);
            debug!(?outcome, "reload after file change");
        }
        Ok(batch) => {
            ignored.fetch_add(batch.len(), Ordering::Relaxed);
        }
        Err(watch_errors) => error!(?watch_errors, "file watch error"),
    }
}


pub fn is_watched(event: &DebouncedEvent, names: &[OsString]) -> bool {
    !event.kind.is_access()
        && event
            .paths
            .iter()
            .filter_map(|path| path.file_name())
            .any(|name| names.iter().any(|watched| same_name(watched, name)))
}


const MAX_SHORT_BASE: usize = 6;


const MAX_SHORT_EXTENSION: usize = 3;


const DRIVE_LEN: usize = 2;


#[cfg(windows)]
pub const NAME_EQ: NameEqFn = names_equal_ignoring_case;


#[cfg(not(windows))]
pub const NAME_EQ: NameEqFn = names_equal_exact;


#[cfg(windows)]
pub const PATH_CHECK: PathCheckFn = check_windows_path;


#[cfg(not(windows))]
pub const PATH_CHECK: PathCheckFn = accept_path;


pub fn same_name(watched: &OsStr, event: &OsStr) -> bool {
    NAME_EQ(watched, event)
}


pub fn names_equal_exact(left: &OsStr, right: &OsStr) -> bool {
    left == right
}


/// NTFS is case-insensitive, so a rename to another case is the same file.
pub fn names_equal_ignoring_case(left: &OsStr, right: &OsStr) -> bool {
    left.eq_ignore_ascii_case(right)
}


pub fn accept_path(_file: &Path) -> Result<(), WatchError> {
    Ok(())
}


fn is_separator(character: char) -> bool {
    character == '\\' || character == '/'
}


/// True for `SETTIN~1.YAM`: at most 6 characters, `~`, digits, then an optional dot and at most 3 characters.
pub fn is_short_name(component: &str) -> bool {
    component.split_once('~').is_some_and(|(base, rest)| {
        let tail = rest.trim_start_matches(|character: char| character.is_ascii_digit());
        base.chars().count() <= MAX_SHORT_BASE
            && tail.len() < rest.len()
            && (tail.is_empty()
                || tail
                    .strip_prefix('.')
                    .is_some_and(|extension| extension.chars().count() <= MAX_SHORT_EXTENSION))
    })
}


/// The text after an optional `\\?\` or `\\.\` prefix and an optional `X:` drive, where no `:` may remain.
pub fn after_drive(text: &str) -> &str {
    let unprefixed = text.strip_prefix(r"\\?\").or_else(|| text.strip_prefix(r"\\.\")).unwrap_or(text);
    unprefixed
        .get(..DRIVE_LEN)
        .filter(|head| {
            let mut characters = head.chars();
            characters.next().is_some_and(|letter| letter.is_ascii_alphabetic()) && characters.next() == Some(':')
        })
        .and_then(|_| unprefixed.get(DRIVE_LEN..))
        .unwrap_or(unprefixed)
}


/// True for a file name made of `[A-Za-z0-9._-]` only and not ending in a dot: Win32 strips trailing dots and spaces, NTFS folds case with Unicode.
pub fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with('.')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
}


/// Windows only: refuses `C:x` (drive without root), `\x` (root without drive), a `:` past the drive, a file name off the ASCII allowlist and any 8.3 short name component; `\\?\`, `\\.\` and UNC stay allowed.
pub fn check_windows_path(file: &Path) -> Result<(), WatchError> {
    let text = file.to_string_lossy();
    let mut characters = text.chars();
    let first = characters.next();
    let second = characters.next();
    let third = characters.next();
    let drive_without_root = first.is_some_and(|letter| letter.is_ascii_alphabetic()) && second == Some(':') && !third.is_some_and(is_separator);
    let root_without_drive = first.is_some_and(is_separator) && !second.is_some_and(is_separator);
    if drive_without_root {
        Err(WatchError::DriveRelative(file.to_path_buf()))
    } else if root_without_drive {
        Err(WatchError::RootRelative(file.to_path_buf()))
    } else if after_drive(&text).contains(':') {
        Err(WatchError::StreamSyntax(file.to_path_buf()))
    } else if text.split(is_separator).any(is_short_name) {
        Err(WatchError::ShortName(file.to_path_buf()))
    } else if !text.rsplit(is_separator).next().is_some_and(is_plain_file_name) {
        Err(WatchError::FileName(file.to_path_buf()))
    } else {
        Ok(())
    }
}


pub fn parent_of(file: &Path) -> PathBuf {
    file.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}


/// Watches the directories of `files` (atomic replace is seen), reloads only on events about these names; drop the result to stop.
pub fn watch_files<Config: Send + Sync + 'static>(
    engine: Arc<ReloadEngine<Config>>,
    files: &[PathBuf],
    debounce: Duration,
) -> Result<Debouncer<RecommendedWatcher, RecommendedCache>, WatchError> {
    watch_files_counted(engine, files, debounce, Arc::new(AtomicUsize::new(0)))
}


/// Same as `watch_files`, and `ignored` counts the events on other files of the watched directories.
pub fn watch_files_counted<Config: Send + Sync + 'static>(
    engine: Arc<ReloadEngine<Config>>,
    files: &[PathBuf],
    debounce: Duration,
    ignored: Arc<AtomicUsize>,
) -> Result<Debouncer<RecommendedWatcher, RecommendedCache>, WatchError> {
    watch_checked(engine, files, debounce, ignored, PATH_CHECK)
}


/// Same as `watch_files_counted` with the path rule injected, so every platform can run the Windows rule.
pub fn watch_checked<Config: Send + Sync + 'static>(
    engine: Arc<ReloadEngine<Config>>,
    files: &[PathBuf],
    debounce: Duration,
    ignored: Arc<AtomicUsize>,
    check: PathCheckFn,
) -> Result<Debouncer<RecommendedWatcher, RecommendedCache>, WatchError> {
    files.iter().try_for_each(|file| check(file))?;
    let names: Vec<OsString> = files.iter().filter_map(|file| file.file_name().map(OsString::from)).collect();
    let mut debouncer = new_debouncer(debounce, None, move |result| handle_events(&engine, &names, &ignored, result))?;
    files
        .iter()
        .try_for_each(|file| debouncer.watch(parent_of(file), RecursiveMode::NonRecursive))?;
    Ok(debouncer)
}


/// Stops the watcher and waits for its event thread, so no reload starts after it returns (dropping it only sets a flag).
pub fn stop_watcher(debouncer: Debouncer<RecommendedWatcher, RecommendedCache>) {
    debouncer.stop();
}

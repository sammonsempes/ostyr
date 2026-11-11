use crate::error::WatchError;
use crate::reload::{reload, ReloadEngine};
use notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache};
use std::ffi::OsString;
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
            .any(|name| names.iter().any(|watched| watched == name))
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
    let names: Vec<OsString> = files.iter().filter_map(|file| file.file_name().map(OsString::from)).collect();
    let mut debouncer = new_debouncer(debounce, None, move |result| handle_events(&engine, &names, &ignored, result))?;
    files
        .iter()
        .try_for_each(|file| debouncer.watch(parent_of(file), RecursiveMode::NonRecursive))?;
    Ok(debouncer)
}

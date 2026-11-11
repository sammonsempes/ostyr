#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::error::WatchError;
use core_config::reload::{reload, ReloadOutcome};
use core_config::watch::{handle_events, parent_of, watch_files, watch_files_counted};
use notify::event::{AccessKind, AccessMode, ModifyKind, RenameMode};
use notify::{Event, EventKind};
use notify_debouncer_full::DebouncedEvent;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;
use wait::wait_until;


fn event_on(kind: EventKind, path: PathBuf) -> DebouncedEvent {
    DebouncedEvent::new(Event::new(kind).add_path(path), Instant::now())
}


const DEBOUNCE: Duration = Duration::from_millis(200);


const SETTLE: Duration = Duration::from_millis(1000);


#[test]
fn a_file_change_causes_exactly_one_reload_and_dropping_stops_the_watcher() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let watcher = watch_files(Arc::clone(&engine), std::slice::from_ref(&path), DEBOUNCE)?;
    replace_file(&path, &module_text("90d"))?;
    assert!(wait_until(|| retention(&engine).as_deref() == Some("90d")));
    thread::sleep(SETTLE);
    assert_eq!(entries(&recorded)?.len(), 1);
    drop(watcher);
    thread::sleep(DEBOUNCE);
    replace_file(&path, &module_text("120d"))?;
    thread::sleep(SETTLE);
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    assert_eq!(entries(&recorded)?.len(), 1);
    Ok(())
}


#[test]
fn events_reload_and_watcher_errors_are_only_logged() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    replace_file(&path, &module_text("90d"))?;
    let names = [OsString::from("module.yaml")];
    let ignored = AtomicUsize::new(0);
    handle_events(&engine, &names, &ignored, Err(vec![notify::Error::generic("injected")]));
    handle_events(&engine, &names, &ignored, Ok(Vec::new()));
    let pathless = DebouncedEvent::new(Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To))), Instant::now());
    let other = event_on(EventKind::Modify(ModifyKind::Name(RenameMode::To)), dir.path().join("audit.jsonl"));
    let read_only = event_on(EventKind::Access(AccessKind::Open(AccessMode::Read)), path.clone());
    handle_events(&engine, &names, &ignored, Ok(vec![pathless, other, read_only]));
    assert_eq!(retention(&engine).as_deref(), Some("30d"));
    assert_eq!(entries(&recorded)?.len(), 0);
    assert_eq!(ignored.load(Ordering::Relaxed), IGNORED_IN_BATCH);
    let watched = event_on(EventKind::Modify(ModifyKind::Name(RenameMode::To)), path.clone());
    handle_events(&engine, &names, &ignored, Ok(vec![watched]));
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn parent_of_falls_back_to_the_current_directory() -> TestResult {
    assert_eq!(parent_of(Path::new("conf/module.yaml")), PathBuf::from("conf"));
    assert_eq!(parent_of(Path::new("module.yaml")), PathBuf::from("."));
    assert_eq!(parent_of(Path::new("/")), PathBuf::from("."));
    assert_eq!(parent_of(Path::new("/etc/module.yaml")), PathBuf::from("/etc"));
    Ok(())
}


#[test]
fn watching_a_missing_path_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let result = watch_files(engine, &[dir.path().join("absent").join("module.yaml")], DEBOUNCE);
    assert!(matches!(result, Err(WatchError::Notify(_))));
    Ok(())
}


const FILE_EVENTS: usize = 5;


const IGNORED_IN_BATCH: usize = 3;


struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
fn ignored_events_are_counted_and_never_logged() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || SharedBuffer(Arc::clone(&sink)))
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|error| error.to_string())?;
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let ignored = Arc::new(AtomicUsize::new(0));
    let watcher = watch_files_counted(engine, std::slice::from_ref(&path), DEBOUNCE, Arc::clone(&ignored))?;
    (0..FILE_EVENTS).try_for_each(|index| File::create(dir.path().join(format!("module.log.{index}"))).map(drop))?;
    assert!(wait_until(|| ignored.load(Ordering::Relaxed) >= FILE_EVENTS));
    drop(watcher);
    let text = String::from_utf8(captured.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert!(!text.contains("ignored"));
    Ok(())
}

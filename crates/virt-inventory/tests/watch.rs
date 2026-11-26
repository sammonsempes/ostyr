#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_config::reload::{open_engine, ReloadContext};
use core_config::types::ConfigState;
use core_config::watch::watch_files;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{spawn, yield_now};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;
use virt_inventory::serve::Watch;


const HANG_GUARD: Duration = Duration::from_secs(120);


const DEBOUNCE: Duration = Duration::from_millis(50);


const YIELDS: usize = 20_000;


const CONFIG: u8 = 0;


fn no_state(_config: &u8) -> ConfigState {
    ConfigState::new()
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "all".to_owned(),
        module: "virt-inventory".to_owned(),
        target: "watch".to_owned(),
        request_id: "watch".to_owned(),
    }
}


#[test]
fn stopping_the_watch_waits_for_the_reload_its_thread_is_running() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("settings.yaml");
    fs::write(&file, "a: 1\n")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered, reached) = channel();
    let (release, waiting): (_, Receiver<()>) = channel();
    let held = Mutex::new(waiting);
    let counter = Arc::clone(&calls);
    let engine = Arc::new(open_engine(
        Box::new(move || {
            let before = counter.fetch_add(1, Ordering::SeqCst);
            if before == 1 {
                entered.send(()).map_err(|_| core_config::error::ConfigError::WatchedFile {
                    file: "watch".to_owned(),
                    reason: "no listener".to_owned(),
                })?;
                held.lock()
                    .map_err(|_| core_config::error::ConfigError::WatchedFile {
                        file: "watch".to_owned(),
                        reason: "poisoned".to_owned(),
                    })?
                    .recv_timeout(HANG_GUARD)
                    .map_err(|_| core_config::error::ConfigError::WatchedFile {
                        file: "watch".to_owned(),
                        reason: "never released".to_owned(),
                    })?;
            }
            Ok(CONFIG)
        }),
        no_state,
        Vec::new(),
        Box::new(|_entry| Err(AuditError::LogPoisoned)),
        context(),
    )?);
    let watch = Watch(Some(watch_files(Arc::clone(&engine), std::slice::from_ref(&file), DEBOUNCE)?));
    fs::write(&file, "a: 2\n")?;
    reached.recv_timeout(HANG_GUARD)?;
    let finished = Arc::new(AtomicBool::new(false));
    let stopper = {
        let flag = Arc::clone(&finished);
        spawn(move || {
            drop(watch);
            flag.store(true, Ordering::SeqCst);
        })
    };
    (0..YIELDS).for_each(|_| yield_now());
    assert!(!finished.load(Ordering::SeqCst), "the watch returned while its reload was running");
    release.send(())?;
    stopper.join().map_err(|_| "stopper panicked")?;
    assert!(finished.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn an_empty_watch_drops_quietly() -> TestResult {
    drop(Watch(None));
    Ok(())
}

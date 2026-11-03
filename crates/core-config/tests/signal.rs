#![cfg(unix)]


#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::signal::reload_on_signals;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use signal_hook::low_level::raise;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;
use wait::wait_until;


const SETTLE: Duration = Duration::from_millis(500);


const INVALID_SIGNAL: i32 = 0;


#[test]
fn sighup_causes_exactly_one_reload_and_dropping_the_guard_stops_it() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let keep_alive = Signals::new([SIGHUP])?;
    let guard = reload_on_signals(Arc::clone(&engine), &[SIGHUP])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    assert!(wait_until(|| retention(&engine).as_deref() == Some("90d")));
    thread::sleep(SETTLE);
    assert_eq!(entries(&recorded)?.len(), 1);
    drop(guard);
    thread::sleep(SETTLE);
    replace_file(&path, &module_text("120d"))?;
    raise(SIGHUP)?;
    thread::sleep(SETTLE);
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    drop(keep_alive);
    Ok(())
}


#[test]
fn an_unhandleable_signal_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    assert!(reload_on_signals(engine, &[INVALID_SIGNAL]).is_err());
    Ok(())
}

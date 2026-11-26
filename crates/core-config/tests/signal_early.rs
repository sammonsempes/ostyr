#![cfg(unix)]


#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::signal::{early_signals, reload_on_stream, stop_signals};
use signal_hook::consts::{SIGHUP, SIGTERM};
use signal_hook::low_level::raise;
use std::sync::Arc;
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;
use wait::wait_until;


#[test]
fn a_sighup_queued_before_the_engine_exists_is_handled_after_it() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let early = early_signals()?;
    raise(SIGHUP)?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    replace_file(&path, &module_text("120d"))?;
    let guard = reload_on_stream(early.reload, Arc::clone(&engine));
    assert!(wait_until(|| retention(&engine).as_deref() == Some("120d")));
    assert!(stop_signals(guard));
    assert_eq!(entries(&recorded)?.len(), 1);
    Ok(())
}


#[test]
fn sigterm_is_registered_by_the_early_set() -> TestResult {
    let mut early = early_signals()?;
    raise(SIGTERM)?;
    assert_eq!(early.stop.forever().next(), Some(SIGTERM));
    Ok(())
}

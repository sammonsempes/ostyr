#[path = "common/types.rs"]
mod types;


use cmdb::model::{DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome, RELOAD_DECLARED_KEYS};
use k8s_inventory::serve::{boxed_reload_audit, drain_reloads};
use k8s_inventory::service::{
    limits_of, load_service_settings, open_service_settings_from, settings_state, start_only_changed, ServiceSettings, MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
};
use std::fs;
use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const HANG_GUARD: Duration = Duration::from_secs(60);


const NOT_DONE_YET: Duration = Duration::from_millis(300);


const OVER: usize = 1;


const CAP_ASSETS: usize = 5;


const CAP_ROWS: usize = 7;


fn text(interval: u64, extra: &str, audit: &str) -> String {
    format!("fetch_settings: /etc/f.yaml\npg_settings: /etc/p.yaml\naudit_file: {audit}\ninterval_seconds: {interval}\n{extra}")
}


fn service_file(dir: &Path, body: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let file = dir.join("service.yaml");
    fs::write(&file, body)?;
    Ok(file)
}


fn refused(dir: &Path, body: &str, marker: &str) -> TestResult {
    let error = load_service_settings(&service_file(dir, body)?)
        .err()
        .ok_or("the settings were accepted")?;
    assert!(error.to_string().contains(marker), "{error}");
    Ok(())
}


#[test]
fn the_ranges_are_enforced_and_the_edges_are_accepted() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log").display().to_string();
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS - 1, "", &audit), "interval_seconds")?;
    refused(dir.path(), &text(MAX_INTERVAL_SECONDS + 1, "", &audit), "interval_seconds")?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "max_assets: 0\n", &audit), "max_assets")?;
    refused(
        dir.path(),
        &text(MIN_INTERVAL_SECONDS, &format!("max_assets: {}\n", DEFAULT_MAX_ASSETS + OVER), &audit),
        "max_assets",
    )?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "max_child_rows: 0\n", &audit), "max_child_rows")?;
    refused(
        dir.path(),
        &text(
            MIN_INTERVAL_SECONDS,
            &format!("max_child_rows: {}\n", DEFAULT_MAX_CHILD_ROWS + OVER),
            &audit,
        ),
        "max_child_rows",
    )?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "", "relative.log"), "audit_file")?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "surprise: 1\n", &audit), "unknown field")?;
    let low = load_service_settings(&service_file(dir.path(), &text(MIN_INTERVAL_SECONDS, "", &audit))?)?;
    let high = load_service_settings(&service_file(
        dir.path(),
        &text(
            MAX_INTERVAL_SECONDS,
            &format!("max_assets: {DEFAULT_MAX_ASSETS}\nmax_child_rows: {DEFAULT_MAX_CHILD_ROWS}\n"),
            &audit,
        ),
    )?)?;
    assert_eq!(low.interval_seconds, MIN_INTERVAL_SECONDS);
    assert_eq!(limits_of(&low).max_assets, DEFAULT_MAX_ASSETS);
    assert_eq!(limits_of(&high).max_child_rows, DEFAULT_MAX_CHILD_ROWS);
    assert!(settings_state(&low).contains_key("audit_file"));
    Ok(())
}


#[test]
fn a_cap_setting_reaches_the_cmdb_limits() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log").display().to_string();
    let settings = load_service_settings(&service_file(
        dir.path(),
        &text(MIN_INTERVAL_SECONDS, "max_assets: 5\nmax_child_rows: 7\n", &audit),
    )?)?;
    let limits = limits_of(&settings);
    assert_eq!((limits.max_assets, limits.max_child_rows), (CAP_ASSETS, CAP_ROWS));
    Ok(())
}


#[test]
fn a_live_change_is_applied_audited_under_all_and_a_start_only_change_is_refused() -> TestResult {
    let dir = tempdir()?;
    let audit_path = dir.path().join("audit.log");
    let audit = audit_path.display().to_string();
    let file = service_file(dir.path(), &text(MIN_INTERVAL_SECONDS, "", &audit))?;
    let first = load_service_settings(&file)?;
    let log = Arc::new(open_file_log(&audit_path)?);
    let engine = open_service_settings_from(&file, first.clone(), boxed_reload_audit(&log))?;
    fs::write(&file, text(MIN_INTERVAL_SECONDS + OVER as u64, "max_assets: 3\n", &audit))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).interval_seconds, MIN_INTERVAL_SECONDS + OVER as u64);
    assert!(!start_only_changed(&first, &current_config(&engine)));
    fs::write(&file, text(MIN_INTERVAL_SECONDS, "", &dir.path().join("other.log").display().to_string()))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("start-only")),
        "{outcome:?}"
    );
    assert_eq!(current_config(&engine).interval_seconds, MIN_INTERVAL_SECONDS + OVER as u64);
    let records = fs::read_to_string(&audit_path)?;
    assert!(records.contains("\"tenant\":\"all\""), "{records}");
    assert!(records.contains("k8s-inventory"), "{records}");
    Ok(())
}


#[test]
fn a_stop_waits_for_the_reload_in_flight_to_finish_its_audit_record() -> TestResult {
    let dir = tempdir()?;
    let audit_path = dir.path().join("audit.log");
    let audit = audit_path.display().to_string();
    let file = service_file(dir.path(), &text(MIN_INTERVAL_SECONDS, "", &audit))?;
    let first = load_service_settings(&file)?;
    let log = Arc::new(open_file_log(&audit_path)?);
    let (inside, entered) = channel();
    let (release, release_rx) = channel::<()>();
    let released = Mutex::new(release_rx);
    let finished = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let order = Arc::clone(&finished);
    let engine: Arc<ReloadEngine<ServiceSettings>> = Arc::new(open_service_settings_from(
        &file,
        first,
        Box::new(move |entry| {
            inside.send(()).map_err(|_closed| AuditError::LogPoisoned)?;
            released
                .lock()
                .map_err(|_poisoned| AuditError::LogPoisoned)?
                .recv_timeout(HANG_GUARD)
                .map_err(|_late| AuditError::LogPoisoned)?;
            let record = append_declared(&log, entry, &RELOAD_DECLARED_KEYS);
            order.lock().map_err(|_poisoned| AuditError::LogPoisoned)?.push("audit written");
            record
        }),
    )?);
    fs::write(&file, text(MIN_INTERVAL_SECONDS + OVER as u64, "", &audit))?;
    let reloading = Arc::clone(&engine);
    let reload_thread = spawn(move || reload(&reloading));
    entered.recv_timeout(HANG_GUARD)?;
    let (drained_tx, drained_rx) = channel();
    let draining = Arc::clone(&engine);
    let order_at_drain = Arc::clone(&finished);
    let drain_thread = spawn(move || {
        drain_reloads(&draining);
        let written = order_at_drain.lock().map_or(usize::MAX, |done| done.len());
        drained_tx.send(written)
    });
    assert_eq!(drained_rx.recv_timeout(NOT_DONE_YET), Err(RecvTimeoutError::Timeout));
    release.send(())?;
    assert_eq!(drained_rx.recv_timeout(HANG_GUARD)?, 1);
    drain_thread.join().map_err(|_panic| "the drain thread panicked")??;
    assert!(matches!(
        reload_thread.join().map_err(|_panic| "the reload thread panicked")?,
        ReloadOutcome::Applied { .. }
    ));
    Ok(())
}

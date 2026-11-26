#[path = "common/engine.rs"]
mod engine;
#[path = "common/types.rs"]
mod types;


use agent_windows::settings::{
    accept_entries, audit_file_of, observed_load, open_settings_from, validate_audit_file, validate_settings, Settings, SettingsError,
    MAX_AUDIT_FILE_BYTES,
};
use agent_windows::types::SharedObserved;
use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::fs;
use std::io;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tempfile::tempdir;
use types::TestResult;


const FILE: &str = "settings.yaml";


#[test]
fn a_plain_file_name_is_accepted() -> TestResult {
    ["audit", "audit-log", "A_1", "x", "console", "com10"]
        .iter()
        .try_for_each(|name| validate_audit_file(name))?;
    validate_audit_file(&"a".repeat(MAX_AUDIT_FILE_BYTES))?;
    Ok(())
}


#[test]
fn a_name_that_is_not_plain_is_refused() -> TestResult {
    let long = "a".repeat(MAX_AUDIT_FILE_BYTES + 1);
    [
        "",
        "-x",
        "a.b",
        "a/b",
        "a\\b",
        "a b",
        "a:b",
        "..",
        "audit.log",
        "NUL",
        "nul",
        "COM0",
        "lpt0",
        "Con",
        "COM1",
        "lpt9",
        "aux",
        "prn",
        "é",
        &long,
    ]
    .iter()
    .for_each(|name| assert!(matches!(validate_audit_file(name), Err(SettingsError::BadAuditFile)), "{name:?}"));
    Ok(())
}


#[test]
fn a_settings_file_without_an_audit_file_is_named_missing() -> TestResult {
    assert!(matches!(audit_file_of(&Settings::default()), Err(SettingsError::NoAuditFile)));
    let named = Settings {
        audit_file: Some("audit".to_owned()),
        ..Settings::default()
    };
    assert_eq!(audit_file_of(&named)?, "audit");
    validate_settings(&named)?;
    Ok(())
}


#[test]
fn a_bad_audit_file_makes_the_settings_invalid() -> TestResult {
    let bad = Settings {
        audit_file: Some("a.b".to_owned()),
        ..Settings::default()
    };
    assert!(matches!(validate_settings(&bad), Err(SettingsError::BadAuditFile)));
    Ok(())
}


#[test]
fn a_reload_that_moves_the_audit_file_is_refused_and_the_start_value_stays() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join(FILE);
    fs::write(&path, "audit_file: first\n")?;
    let denied = Arc::new(AtomicUsize::new(0));
    let engine = engine::open_at(&path, Arc::clone(&denied), SharedObserved::default())?;
    fs::write(&path, "audit_file: second\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).audit_file.as_deref(), Some("first"));
    fs::write(&path, "audit_file: first\nbatch: 7\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).audit_file.as_deref(), Some("first"));
    Ok(())
}


#[test]
fn the_engine_opens_on_the_start_read_and_not_on_the_file_as_it_is_later() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join(FILE);
    fs::write(&path, "audit_file: first\n")?;
    let observed = SharedObserved::default();
    let first = observed_load(&path, &observed)?;
    fs::write(&path, "audit_file: second\n")?;
    let log = genesis_log(io::sink());
    let engine = open_settings_from(
        path.clone(),
        first,
        Box::new(move |entry| append(&log, entry)),
        engine::context(),
        Arc::clone(&observed),
        accept_entries(),
    )?;
    assert_eq!(current_config(&engine).audit_file.as_deref(), Some("first"));
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    Ok(())
}

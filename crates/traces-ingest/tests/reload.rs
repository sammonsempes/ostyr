mod common;


use common::types::TestResult;
use core_config::error::ConfigError;
use metrics_ingest::settings::{LoadError, SettingsError};
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use traces_ingest::reload::{load_sampling, sampling_loader, sampling_refusal, sampling_state, settings_loader, settings_refusal, settings_state};
use traces_ingest::sampling::{Sampling, SamplingError};


const SETTINGS: &str = "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: /run/pw\ndatabase: ostyr\ntable: trace_spans\n";


const HALF: f64 = 0.5;


const QUARTER: f64 = 0.25;


const ALL: f64 = 1.0;


const OVER_BYTES: usize = 70_000;


fn watched_reason(error: ConfigError) -> Result<String, Box<dyn std::error::Error>> {
    match error {
        ConfigError::WatchedFile { reason, .. } => Ok(reason),
        other => Err(format!("not a watched file refusal: {other}").into()),
    }
}


#[test]
fn the_settings_loader_applies_the_same_checks_and_names_a_refused_limit() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, SETTINGS)?;
    let loaded = settings_loader(path.clone())()?;
    assert_eq!(loaded.table, "trace_spans");
    fs::write(&path, format!("{SETTINGS}limits:\n  max_spans: 0\n"))?;
    let reason = watched_reason(settings_loader(path.clone())().err().ok_or("accepted")?)?;
    assert!(reason.contains("limits.max_spans must be within"), "{reason}");
    fs::write(&path, "url: [\n")?;
    assert!(matches!(
        settings_loader(path.clone())(),
        Err(ConfigError::Parse { .. } | ConfigError::WatchedFile { .. })
    ));
    Ok(())
}


#[test]
fn a_settings_error_keeps_its_fixed_text() -> TestResult {
    let config = settings_refusal(
        Path::new("x.yaml"),
        LoadError::Config(ConfigError::TooLarge {
            file: "x".to_owned(),
            max: 1,
        }),
    );
    assert!(matches!(config, ConfigError::TooLarge { .. }));
    let invalid = settings_refusal(Path::new("x.yaml"), LoadError::Invalid(SettingsError::User));
    assert!(watched_reason(invalid)?.contains("user must be"));
    Ok(())
}


#[test]
fn the_settings_state_shows_a_changed_limit_and_never_the_password() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, SETTINGS)?;
    let first = settings_loader(path.clone())()?;
    fs::write(&path, format!("{SETTINGS}ca_file: /run/ca.pem\nlimits:\n  max_batch_rows: 7\n"))?;
    let second = settings_loader(path.clone())()?;
    let before = settings_state(&first);
    let after = settings_state(&second);
    assert_ne!(before.get("limits"), after.get("limits"));
    assert_eq!(before.get("ca_file").map(String::as_str), Some(""));
    assert_eq!(after.get("ca_file").map(String::as_str), Some("/run/ca.pem"));
    assert_eq!(before.get("password_file").map(String::as_str), Some("/run/pw"));
    Ok(())
}


#[test]
fn the_sampling_loader_reads_validates_and_refuses_each_defect() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sampling.yaml");
    fs::write(&path, "default_ratio: 0.5\nservices:\n  web: 0.25\nerror_ratio: 1.0\n")?;
    let loaded = sampling_loader(path.clone())()?;
    assert_eq!(loaded.default_ratio, HALF);
    fs::write(&path, "default_ratio: 2.0\n")?;
    assert!(watched_reason(load_sampling(&path).err().ok_or("accepted")?)?.contains("outside 0 to 1"));
    fs::write(&path, "default_ratio: [\n")?;
    assert!(matches!(load_sampling(&path), Err(ConfigError::Parse { .. })));
    fs::write(&path, " ".repeat(OVER_BYTES))?;
    assert!(matches!(load_sampling(&path), Err(ConfigError::TooLarge { .. })));
    assert!(load_sampling(&dir.path().join("missing.yaml")).is_err());
    let other = sampling_refusal(Path::new("s.yaml"), SamplingError::TooManyServices);
    assert!(watched_reason(other)?.contains("more than"));
    Ok(())
}


#[test]
fn the_sampling_state_lists_every_ratio() -> TestResult {
    let plain = sampling_state(&Sampling::default());
    assert_eq!(plain.get("default_ratio").map(String::as_str), Some("1"));
    assert_eq!(plain.get("error_ratio").map(String::as_str), Some(""));
    let rich = Sampling {
        default_ratio: HALF,
        services: [("web".to_owned(), QUARTER)].into_iter().collect(),
        error_ratio: Some(ALL),
    };
    let state = sampling_state(&rich);
    assert_eq!(state.get("services.web").map(String::as_str), Some("0.25"));
    assert_eq!(state.get("error_ratio").map(String::as_str), Some("1"));
    assert_ne!(plain, state);
    Ok(())
}

#[path = "common/types.rs"]
mod types;


use cloud_cost::settings::{validate_config, CostLoadConfig, CostSettingsError, DEFAULT_TIMEOUT_MS, DEFAULT_TTL_DAYS, MAX_TIMEOUT_MS, MAX_TTL_DAYS};
use core_config::load::load_file;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use types::TestResult;


const MINIMAL: &str =
    "url: http://127.0.0.1:8123\nuser: ostyr\npassword_file: /run/secrets/ch\ndatabase: ostyr\ntable: cloud_cost_daily\ntenant: acme\n";


const LONG_USER: usize = 65;


fn config() -> CostLoadConfig {
    CostLoadConfig {
        url: "http://127.0.0.1:8123".to_owned(),
        user: "ostyr".to_owned(),
        password_file: PathBuf::from("/x"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "cloud_cost_daily".to_owned(),
        timeout_ms: 1,
        ttl_days: 1,
        tenant: "acme".to_owned(),
    }
}


#[test]
fn defaults_apply_and_unknown_fields_are_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, MINIMAL)?;
    let loaded: CostLoadConfig = load_file(&path)?;
    assert_eq!(loaded.timeout_ms, DEFAULT_TIMEOUT_MS);
    assert_eq!(loaded.ttl_days, DEFAULT_TTL_DAYS);
    assert!(validate_config(&loaded).is_ok());
    fs::write(&path, format!("{MINIMAL}extra: 1\n"))?;
    assert!(load_file::<CostLoadConfig>(&path).is_err());
    Ok(())
}


#[test]
fn every_field_is_bounded() -> TestResult {
    assert!(validate_config(&config()).is_ok());
    let tenant = CostLoadConfig {
        tenant: "-x".to_owned(),
        ..config()
    };
    assert!(matches!(validate_config(&tenant), Err(CostSettingsError::Tenant(_))));
    let url = CostLoadConfig {
        url: "http://example.com".to_owned(),
        ..config()
    };
    assert!(matches!(validate_config(&url), Err(CostSettingsError::Url(_))));
    let database = CostLoadConfig {
        database: "a`b".to_owned(),
        ..config()
    };
    assert!(matches!(validate_config(&database), Err(CostSettingsError::Identifier(_))));
    let table = CostLoadConfig {
        table: String::new(),
        ..config()
    };
    assert!(matches!(validate_config(&table), Err(CostSettingsError::Identifier(_))));
    [String::new(), "a".repeat(LONG_USER), "a b".to_owned()]
        .into_iter()
        .try_for_each(|user| -> TestResult {
            let bad = CostLoadConfig { user, ..config() };
            assert!(matches!(validate_config(&bad), Err(CostSettingsError::User)));
            Ok(())
        })?;
    [0, MAX_TIMEOUT_MS + 1].into_iter().try_for_each(|timeout_ms| -> TestResult {
        let bad = CostLoadConfig { timeout_ms, ..config() };
        assert!(matches!(validate_config(&bad), Err(CostSettingsError::Timeout)));
        Ok(())
    })?;
    [0, MAX_TTL_DAYS + 1].into_iter().try_for_each(|ttl_days| -> TestResult {
        let bad = CostLoadConfig { ttl_days, ..config() };
        assert!(matches!(validate_config(&bad), Err(CostSettingsError::Ttl)));
        Ok(())
    })?;
    Ok(())
}

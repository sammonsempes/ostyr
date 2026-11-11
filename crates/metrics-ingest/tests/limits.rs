mod common;
#[path = "limits/types.rs"]
mod types;


use common::types::TestResult;
use core_pg::error::PgError;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::cli::{error_text, run_cli, CliError, USAGE};
use metrics_ingest::insert::EncodeError;
use metrics_ingest::model::Limits;
use metrics_ingest::run::{run_insert, RunError};
use metrics_ingest::send::SendError;
use metrics_ingest::settings::*;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use types::{Row, Setter};


fn base() -> MetricsSettings {
    MetricsSettings {
        url: "http://127.0.0.1:1".to_string(),
        user: "ostyr".to_string(),
        password_file: PathBuf::from("password"),
        ca_file: None,
        database: "ostyr".to_string(),
        table: "metric_samples".to_string(),
        timeout_ms: DEFAULT_TIMEOUT_MS,
        limits: Limits::default(),
    }
}


fn with(setter: Setter, value: u64) -> MetricsSettings {
    let mut settings = base();
    setter(&mut settings.limits, value);
    settings
}


fn size(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}


fn table() -> Vec<Row> {
    vec![
        (
            "max_request_bytes",
            |limits, value| limits.max_request_bytes = size(value),
            1,
            MAX_REQUEST_BYTES_CEILING,
        ),
        (
            "max_resources",
            |limits, value| limits.max_resources = size(value),
            1,
            MAX_RESOURCES_CEILING,
        ),
        (
            "max_data_points",
            |limits, value| limits.max_data_points = size(value),
            1,
            MAX_DATA_POINTS_CEILING,
        ),
        (
            "max_total_attributes",
            |limits, value| limits.max_total_attributes = size(value),
            1,
            MAX_TOTAL_ATTRIBUTES_CEILING,
        ),
        ("max_labels", |limits, value| limits.max_labels = size(value), 1, MAX_LABELS_CEILING),
        (
            "max_label_key_bytes",
            |limits, value| limits.max_label_key_bytes = size(value),
            1,
            MAX_LABEL_KEY_BYTES_CEILING,
        ),
        (
            "max_label_value_bytes",
            |limits, value| limits.max_label_value_bytes = size(value),
            1,
            MAX_LABEL_VALUE_BYTES_CEILING,
        ),
        (
            "max_name_bytes",
            |limits, value| limits.max_name_bytes = size(value),
            1,
            MAX_NAME_BYTES_CEILING,
        ),
        ("max_buckets", |limits, value| limits.max_buckets = size(value), 1, MAX_BUCKETS_CEILING),
        (
            "max_series_per_tenant",
            |limits, value| limits.max_series_per_tenant = size(value),
            1,
            MAX_SERIES_PER_TENANT_CEILING,
        ),
        (
            "max_values_per_label",
            |limits, value| limits.max_values_per_label = size(value),
            1,
            MAX_VALUES_PER_LABEL_CEILING,
        ),
        (
            "max_label_keys_per_tenant",
            |limits, value| limits.max_label_keys_per_tenant = size(value),
            1,
            MAX_LABEL_KEYS_PER_TENANT_CEILING,
        ),
        (
            "max_state_bytes_per_tenant",
            |limits, value| limits.max_state_bytes_per_tenant = size(value),
            1,
            MAX_STATE_BYTES_PER_TENANT_CEILING,
        ),
        (
            "max_batch_rows",
            |limits, value| limits.max_batch_rows = size(value),
            1,
            MAX_BATCH_ROWS_CEILING,
        ),
        (
            "max_batch_bytes",
            |limits, value| limits.max_batch_bytes = size(value),
            1,
            MAX_BATCH_BYTES_CEILING,
        ),
        (
            "max_future_skew_seconds",
            |limits, value| limits.max_future_skew_seconds = value,
            0,
            MAX_FUTURE_SKEW_SECONDS_CEILING,
        ),
        (
            "raw_retention_seconds",
            |limits, value| limits.raw_retention_seconds = value,
            1,
            RAW_RETENTION_SECONDS_CEILING,
        ),
    ]
}


#[test]
fn every_limit_is_accepted_at_its_ceiling_and_refused_above_or_below() -> TestResult {
    assert!(validate_settings(&base()).is_ok());
    assert_eq!(table().len(), LIMIT_COUNT);
    table().iter().try_for_each(|&(name, setter, floor, ceiling)| -> TestResult {
        assert!(validate_settings(&with(setter, ceiling)).is_ok(), "{name} at ceiling");
        assert!(validate_settings(&with(setter, floor)).is_ok(), "{name} at floor");
        let above = validate_settings(&with(setter, ceiling + 1));
        assert!(matches!(above, Err(SettingsError::Limit { field, .. }) if field == name), "{name} above");
        assert!(above.err().map(|error| error.to_string()).is_some_and(|text| text.contains(name)));
        if floor > 0 {
            assert!(
                matches!(validate_settings(&with(setter, 0)), Err(SettingsError::Limit { field, .. }) if field == name),
                "{name} zero"
            );
        }
        Ok(())
    })?;
    assert_eq!(to_u64(usize::MAX), u64::try_from(usize::MAX)?);
    Ok(())
}


#[test]
fn a_loaded_file_above_a_ceiling_is_refused_with_the_field_name() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    let body = format!(
        "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: password\ndatabase: ostyr\ntable: t\nlimits:\n  max_labels: {}\n",
        MAX_LABELS_CEILING + 1
    );
    fs::write(&path, body)?;
    let failed = load_settings(&path);
    assert!(matches!(
        failed,
        Err(LoadError::Invalid(SettingsError::Limit { field: "max_labels", .. }))
    ));
    Ok(())
}


#[test]
fn the_command_line_prints_a_fixed_text_per_failure() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    let settings = path.display().to_string();
    let go = |name: &str| run_insert(&path, &[], name, &mut CardinalityState::default(), 0, &|| Duration::ZERO);
    let pg = || PgError::NotRegular { file: "secret".to_string() };
    let refused_tenant = go("-x").err().ok_or("tenant")?;
    let config = go("acme").err().ok_or("config")?;
    fs::write(&path, "url: http://127.0.0.1:1\nuser: \"\"\npassword_file: p\ndatabase: d\ntable: t\n")?;
    let invalid = go("acme").err().ok_or("invalid")?;
    fs::write(
        &path,
        "url: http://127.0.0.1:1\nuser: u\npassword_file: p\ndatabase: d\ntable: t\nlimits:\n  max_labels: 0\n",
    )?;
    let limit = go("acme").err().ok_or("limit")?;
    let settings_text = |what: &str| format!("the settings file {settings} {what}");
    let cases = [
        (CliError::Usage, USAGE.to_string()),
        (CliError::Request(pg()), "the request file could not be read".to_string()),
        (
            CliError::Output(std::io::Error::other("secret")),
            "the report could not be written".to_string(),
        ),
        (CliError::BatchFailed(1), "batch 1 failed, see the report".to_string()),
        (CliError::Run(refused_tenant), "the tenant name is refused".to_string()),
        (CliError::Run(config), settings_text("could not be loaded")),
        (CliError::Run(invalid), settings_text("is invalid")),
        (CliError::Run(limit), settings_text("refuses limits.max_labels")),
        (
            CliError::Run(RunError::Encode(EncodeError::ZeroBatchRows)),
            "the rows could not be encoded".to_string(),
        ),
        (
            CliError::Run(RunError::Send(SendError::Password(pg()))),
            "the sender could not be built".to_string(),
        ),
    ];
    cases.iter().for_each(|(error, expected)| {
        let text = error_text(error, &settings);
        assert_eq!(&text, expected);
        assert!(!text.contains("secret") && !text.contains('{'));
    });
    let usage = run_cli(&[], 0, &|| Duration::ZERO, &mut Vec::new())
        .err()
        .map(|error| error_text(&error, ""));
    assert_eq!(usage, Some(USAGE.to_string()));
    Ok(())
}

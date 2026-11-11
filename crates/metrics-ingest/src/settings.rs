use crate::model::Limits;
use crate::types::LimitRow;
use core_config::error::ConfigError;
use core_config::load::load_file;
use serde::Deserialize;
use siem_ingest::error::SettingsError as UrlError;
use siem_ingest::settings::check_url;
use siem_schema::error::SchemaError;
use siem_schema::identifier::quote_identifier;
use std::path::{Path, PathBuf};
use thiserror::Error;


pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MAX_USER_BYTES: usize = 128;


pub const LIMIT_COUNT: usize = 17;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const MAX_REQUEST_BYTES_CEILING: u64 = 41_943_040;


pub const MAX_RESOURCES_CEILING: u64 = 2_560;


pub const MAX_DATA_POINTS_CEILING: u64 = 500_000;


pub const MAX_TOTAL_ATTRIBUTES_CEILING: u64 = 20_000_000;


pub const MAX_LABELS_CEILING: u64 = 320;


pub const MAX_LABEL_KEY_BYTES_CEILING: u64 = 1_280;


pub const MAX_LABEL_VALUE_BYTES_CEILING: u64 = 2_560;


pub const MAX_NAME_BYTES_CEILING: u64 = 2_560;


pub const MAX_BUCKETS_CEILING: u64 = 1_600;


pub const MAX_SERIES_PER_TENANT_CEILING: u64 = 1_000_000;


pub const MAX_VALUES_PER_LABEL_CEILING: u64 = 100_000;


pub const MAX_LABEL_KEYS_PER_TENANT_CEILING: u64 = 10_000;


pub const MAX_STATE_BYTES_PER_TENANT_CEILING: u64 = 671_088_640;


pub const MAX_BATCH_ROWS_CEILING: u64 = 100_000;


pub const MAX_BATCH_BYTES_CEILING: u64 = 41_943_040;


pub const MAX_FUTURE_SKEW_SECONDS_CEILING: u64 = 3_000;


pub const RAW_RETENTION_SECONDS_CEILING: u64 = 6_048_000;


/// Read afresh at every run; the password is only a path here, and `limits` keeps the decode and batch caps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSettings {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub table: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub limits: Limits,
}


pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("url refused")]
    Url(#[from] UrlError),
    #[error("identifier refused")]
    Identifier(#[from] SchemaError),
    #[error("user must be 1 to {MAX_USER_BYTES} printable ASCII characters")]
    User,
    #[error("timeout_ms must be within 1..={MAX_TIMEOUT_MS}")]
    Timeout,
    #[error("limits.{field} must be within {floor}..={ceiling}")]
    Limit { field: &'static str, floor: u64, ceiling: u64 },
}


#[derive(Debug, Error)]
pub enum LoadError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] SettingsError),
}


/// URL by siem-ingest's rule (https, or http on loopback), identifiers by the siem-schema grammar, user and timeout bounded; returns the INSERT statement.
pub fn validated_statement(settings: &MetricsSettings) -> Result<String, SettingsError> {
    check_url(&settings.url)?;
    validate_limits(&settings.limits)?;
    let statement = insert_statement(settings)?;
    let user_ok =
        !settings.user.is_empty() && settings.user.len() <= MAX_USER_BYTES && settings.user.chars().all(|character| character.is_ascii_graphic());
    if !user_ok {
        Err(SettingsError::User)
    } else if settings.timeout_ms == 0 || settings.timeout_ms > MAX_TIMEOUT_MS {
        Err(SettingsError::Timeout)
    } else {
        Ok(statement)
    }
}


pub fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}


/// Every field of `Limits` within its floor and its ceiling; the first one outside is named.
pub fn validate_limits(limits: &Limits) -> Result<(), SettingsError> {
    let rows: [LimitRow; LIMIT_COUNT] = [
        ("max_request_bytes", to_u64(limits.max_request_bytes), 1, MAX_REQUEST_BYTES_CEILING),
        ("max_resources", to_u64(limits.max_resources), 1, MAX_RESOURCES_CEILING),
        ("max_data_points", to_u64(limits.max_data_points), 1, MAX_DATA_POINTS_CEILING),
        (
            "max_total_attributes",
            to_u64(limits.max_total_attributes),
            1,
            MAX_TOTAL_ATTRIBUTES_CEILING,
        ),
        ("max_labels", to_u64(limits.max_labels), 1, MAX_LABELS_CEILING),
        ("max_label_key_bytes", to_u64(limits.max_label_key_bytes), 1, MAX_LABEL_KEY_BYTES_CEILING),
        (
            "max_label_value_bytes",
            to_u64(limits.max_label_value_bytes),
            1,
            MAX_LABEL_VALUE_BYTES_CEILING,
        ),
        ("max_name_bytes", to_u64(limits.max_name_bytes), 1, MAX_NAME_BYTES_CEILING),
        ("max_buckets", to_u64(limits.max_buckets), 1, MAX_BUCKETS_CEILING),
        (
            "max_series_per_tenant",
            to_u64(limits.max_series_per_tenant),
            1,
            MAX_SERIES_PER_TENANT_CEILING,
        ),
        (
            "max_values_per_label",
            to_u64(limits.max_values_per_label),
            1,
            MAX_VALUES_PER_LABEL_CEILING,
        ),
        (
            "max_label_keys_per_tenant",
            to_u64(limits.max_label_keys_per_tenant),
            1,
            MAX_LABEL_KEYS_PER_TENANT_CEILING,
        ),
        (
            "max_state_bytes_per_tenant",
            to_u64(limits.max_state_bytes_per_tenant),
            1,
            MAX_STATE_BYTES_PER_TENANT_CEILING,
        ),
        ("max_batch_rows", to_u64(limits.max_batch_rows), 1, MAX_BATCH_ROWS_CEILING),
        ("max_batch_bytes", to_u64(limits.max_batch_bytes), 1, MAX_BATCH_BYTES_CEILING),
        (
            "max_future_skew_seconds",
            limits.max_future_skew_seconds,
            0,
            MAX_FUTURE_SKEW_SECONDS_CEILING,
        ),
        ("raw_retention_seconds", limits.raw_retention_seconds, 1, RAW_RETENTION_SECONDS_CEILING),
    ];
    rows.iter().try_for_each(|&(field, value, floor, ceiling)| {
        if value < floor || value > ceiling {
            Err(SettingsError::Limit { field, floor, ceiling })
        } else {
            Ok(())
        }
    })
}


pub fn validate_settings(settings: &MetricsSettings) -> Result<(), SettingsError> {
    validated_statement(settings).map(drop)
}


/// Strict YAML through core-config, then validated; called once per run so a changed file applies at the next one.
pub fn load_settings(path: &Path) -> Result<MetricsSettings, LoadError> {
    let settings = load_file::<MetricsSettings>(path)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// The INSERT statement; the body of the request carries the rows.
pub fn insert_statement(settings: &MetricsSettings) -> Result<String, SettingsError> {
    Ok(format!(
        "INSERT INTO {}.{} FORMAT JSONEachRow",
        quote_identifier(&settings.database)?,
        quote_identifier(&settings.table)?
    ))
}

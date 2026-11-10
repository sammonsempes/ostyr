use crate::model::Limits;
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


pub const MAX_CA_BYTES: u64 = 65_536;


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

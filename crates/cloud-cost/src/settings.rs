use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use siem_ingest::error::SettingsError;
use siem_ingest::settings::check_url;
use siem_schema::error::SchemaError;
use siem_schema::identifier::validate_identifier;
use std::path::PathBuf;
use thiserror::Error;


pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;


pub const MAX_TIMEOUT_MS: u64 = 600_000;


pub const DEFAULT_TTL_DAYS: u32 = 400;


pub const MAX_TTL_DAYS: u32 = 36_500;


pub const MAX_USER_BYTES: usize = 64;


pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}


pub fn default_ttl_days() -> u32 {
    DEFAULT_TTL_DAYS
}


/// Where the daily aggregates are loaded: every row carries `tenant`; the password is read from `password_file` at each load.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostLoadConfig {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub table: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ttl_days")]
    pub ttl_days: u32,
    pub tenant: String,
}


#[derive(Debug, Error)]
pub enum CostSettingsError {
    #[error("tenant is not a valid tenant name")]
    Tenant(#[source] PgError),
    #[error("identifier refused")]
    Identifier(#[from] SchemaError),
    #[error("url refused")]
    Url(#[from] SettingsError),
    #[error("user must be 1 to {MAX_USER_BYTES} printable ASCII characters")]
    User,
    #[error("timeout_ms must be within 1..={MAX_TIMEOUT_MS}")]
    Timeout,
    #[error("ttl_days must be within 1..={MAX_TTL_DAYS}")]
    Ttl,
}


/// Tenant by core-pg's grammar, URL by siem-ingest's rule, identifiers by siem-schema's, user, timeout and ttl bounded; nothing is read or sent.
pub fn validate_config(config: &CostLoadConfig) -> Result<(), CostSettingsError> {
    tenant_scope(&config.tenant).map_err(CostSettingsError::Tenant)?;
    check_url(&config.url)?;
    [&config.database, &config.table]
        .into_iter()
        .try_for_each(|name| validate_identifier(name).map(drop))?;
    let user_ok = !config.user.is_empty() && config.user.len() <= MAX_USER_BYTES && config.user.chars().all(|character| character.is_ascii_graphic());
    if !user_ok {
        Err(CostSettingsError::User)
    } else if config.timeout_ms == 0 || config.timeout_ms > MAX_TIMEOUT_MS {
        Err(CostSettingsError::Timeout)
    } else if config.ttl_days == 0 || config.ttl_days > MAX_TTL_DAYS {
        Err(CostSettingsError::Ttl)
    } else {
        Ok(())
    }
}

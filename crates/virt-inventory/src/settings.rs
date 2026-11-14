use crate::error::{FetchError, InventoryError};
use crate::limits::Limits;
use core_config::load::load_file;
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use ureq::http::Uri;


pub const MIN_TIMEOUT_MS: u64 = 1_000;


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MAX_URL_BYTES: usize = 256;


pub const MAX_BYTES_CAP: u64 = 67_108_864;


pub const ROOT_PATH: &str = "/";


/// The token is only a path here, read afresh at every run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchSettings {
    pub api_url: String,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
    pub tenant: String,
    pub cluster: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub limits: Limits,
}


/// `https://host[:port]` only: no userinfo, query, fragment or path, so the token can only go to that host.
pub fn check_url(value: &str) -> Result<(), FetchError> {
    let parsed = value.parse::<Uri>().map_err(|_| FetchError::Url)?;
    let sound = [
        parsed.scheme_str() == Some("https"),
        parsed.host().is_some_and(|host| !host.is_empty()),
        parsed.path() == ROOT_PATH,
        !value.contains(['@', '#', '?']),
        value.len() <= MAX_URL_BYTES,
    ];
    if sound.iter().all(|check| *check) {
        Ok(())
    } else {
        Err(FetchError::Url)
    }
}


/// The URL, the scope, the deadline and the byte cap are checked before any file is opened.
pub fn validate_settings(settings: &FetchSettings) -> Result<(), FetchError> {
    check_url(&settings.api_url)?;
    tenant_scope(&settings.tenant).map_err(InventoryError::Tenant)?;
    tenant_scope(&settings.cluster).map_err(InventoryError::Cluster)?;
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&settings.timeout_ms) {
        Err(FetchError::Timeout)
    } else if !(1..=MAX_BYTES_CAP).contains(&settings.limits.max_bytes) {
        Err(FetchError::MaxBytes)
    } else {
        Ok(())
    }
}


/// Strict YAML through core-config (unknown fields refused), then validated.
pub fn load_settings(path: &Path) -> Result<FetchSettings, FetchError> {
    let settings = load_file::<FetchSettings>(path)?;
    validate_settings(&settings)?;
    Ok(settings)
}

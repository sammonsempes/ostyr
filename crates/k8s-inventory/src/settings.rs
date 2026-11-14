use crate::error::{FetchError, InventoryError};
use crate::limits::{
    Limits, PageLimits, CEILING_PAGES, CEILING_TOTAL_ITEMS, DEFAULT_MAX_BYTES, DEFAULT_MAX_ITEMS, DEFAULT_MAX_PAGES, DEFAULT_MAX_TOTAL_ITEMS,
};
use core_config::load::load_file;
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use ureq::http::Uri;


pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MIN_TIMEOUT_MS: u64 = 1_000;


pub const DEFAULT_RUN_BYTES: u64 = 268_435_456;


pub const CEILING_RUN_BYTES: u64 = 2_147_483_648;


pub const CEILING_PAGE_BYTES: u64 = 67_108_864;


pub const DEFAULT_MAX_NAMESPACES: usize = 1_000;


pub const CEILING_NAMESPACES: usize = 10_000;


pub const MAX_URL_BYTES: usize = 255;


pub const HTTPS_PREFIX: &str = "https://";


/// Read from a file at every run; the token is only a path here. Every limit is optional and defaults to the parser's own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchSettings {
    pub api_url: String,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
    pub tenant: String,
    pub cluster: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    pub page_size: Option<usize>,
    pub max_bytes: Option<u64>,
    pub max_run_bytes: Option<u64>,
    pub max_pages: Option<usize>,
    pub max_total_items: Option<usize>,
    pub max_namespaces: Option<usize>,
}


pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}


/// `https://` and an authority only: a path, a query, a fragment or userinfo is refused.
pub fn check_api_url(url: &str) -> Result<(), FetchError> {
    let authority = url.strip_prefix(HTTPS_PREFIX).unwrap_or("");
    let bare = !authority.is_empty() && !authority.contains(['/', '?', '#', '@']) && url.len() <= MAX_URL_BYTES;
    if bare && url.parse::<Uri>().is_ok() {
        Ok(())
    } else {
        Err(FetchError::ApiUrl)
    }
}


pub fn check_range(field: &'static str, value: u64, min: u64, max: u64) -> Result<(), FetchError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(FetchError::Range { field, min, max })
    }
}


pub fn limits_of(settings: &FetchSettings) -> Limits {
    Limits {
        max_bytes: settings.max_bytes.unwrap_or(DEFAULT_MAX_BYTES),
        ..Limits::default()
    }
}


pub fn page_limits_of(settings: &FetchSettings) -> PageLimits {
    PageLimits {
        max_pages: settings.max_pages.unwrap_or(DEFAULT_MAX_PAGES),
        max_total_items: settings.max_total_items.unwrap_or(DEFAULT_MAX_TOTAL_ITEMS),
    }
}


pub fn run_bytes_of(settings: &FetchSettings) -> u64 {
    settings.max_run_bytes.unwrap_or(DEFAULT_RUN_BYTES)
}


pub fn namespaces_of(settings: &FetchSettings) -> usize {
    settings.max_namespaces.unwrap_or(DEFAULT_MAX_NAMESPACES)
}


pub fn validate_settings(settings: &FetchSettings) -> Result<(), FetchError> {
    check_api_url(&settings.api_url)?;
    tenant_scope(&settings.tenant).map_err(InventoryError::Tenant)?;
    tenant_scope(&settings.cluster).map_err(InventoryError::Cluster)?;
    let page_limits = page_limits_of(settings);
    check_range("timeout_ms", settings.timeout_ms, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)?;
    check_range("max_bytes", limits_of(settings).max_bytes, 1, CEILING_PAGE_BYTES)?;
    check_range("max_run_bytes", run_bytes_of(settings), 1, CEILING_RUN_BYTES)?;
    check_range("max_pages", page_limits.max_pages as u64, 1, CEILING_PAGES as u64)?;
    check_range("max_total_items", page_limits.max_total_items as u64, 1, CEILING_TOTAL_ITEMS as u64)?;
    check_range("max_namespaces", namespaces_of(settings) as u64, 1, CEILING_NAMESPACES as u64)?;
    check_range("page_size", settings.page_size.unwrap_or(1) as u64, 1, DEFAULT_MAX_ITEMS as u64)?;
    Ok(())
}


/// Strict YAML through core-config, then validated.
pub fn load_settings(path: &Path) -> Result<FetchSettings, FetchError> {
    let settings = load_file::<FetchSettings>(path)?;
    validate_settings(&settings)?;
    Ok(settings)
}

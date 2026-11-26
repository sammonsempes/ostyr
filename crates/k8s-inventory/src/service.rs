//! The service settings of `ostyr-k8s-inventory`: one tenant per process, the live values, the start-only baseline and the reload engine.

use crate::error::FetchError;
use crate::settings::{load_settings, FetchSettings};
use cmdb::model::{Limits, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use serde::Deserialize;
use std::path::{Path, PathBuf};


pub const MIN_INTERVAL_SECONDS: u64 = 60;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MODULE: &str = "k8s-inventory";


pub const SETTINGS_REQUEST: &str = "settings";


/// Start-only: `fetch_settings`, `pg_settings` and `audit_file`. Live: `interval_seconds`, `max_assets` and `max_child_rows`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub fetch_settings: PathBuf,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub interval_seconds: u64,
    pub max_assets: Option<usize>,
    pub max_child_rows: Option<usize>,
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


pub fn within(field: &str, value: u64, low: u64, high: u64) -> Result<(), ConfigError> {
    if (low..=high).contains(&value) {
        Ok(())
    } else {
        Err(setting_error(field, &format!("must be between {low} and {high}")))
    }
}


pub fn validate_settings(settings: &ServiceSettings) -> Result<(), ConfigError> {
    let limits = limits_of(settings);
    within("interval_seconds", settings.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("max_assets", limits.max_assets as u64, 1, DEFAULT_MAX_ASSETS as u64)?;
    within("max_child_rows", limits.max_child_rows as u64, 1, DEFAULT_MAX_CHILD_ROWS as u64)?;
    if settings.audit_file.is_absolute() {
        Ok(())
    } else {
        Err(setting_error("audit_file", "must be an absolute path"))
    }
}


/// The CMDB caps of one round: a setting below the store's own maxima, or the maximum itself.
pub fn limits_of(settings: &ServiceSettings) -> Limits {
    let defaults = Limits::default();
    Limits {
        max_assets: settings.max_assets.unwrap_or(defaults.max_assets),
        max_child_rows: settings.max_child_rows.unwrap_or(defaults.max_child_rows),
        ..defaults
    }
}


/// Both files of one snapshot: a round and every reload use one read of each, never a fresh read of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSettings {
    pub service: ServiceSettings,
    pub fetch: FetchSettings,
}


/// Everything except the live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        interval_seconds: baseline.interval_seconds,
        max_assets: baseline.max_assets,
        max_child_rows: baseline.max_child_rows,
        ..current.clone()
    };
    same_live != *baseline
}


pub fn load_service_settings(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// Only the timeout and the limits are live: the tenant, the cluster, the API URL and the two credential paths pin what one process may reach.
pub fn fetch_start_only_changed(baseline: &FetchSettings, current: &FetchSettings) -> bool {
    let same_live = FetchSettings {
        timeout_ms: baseline.timeout_ms,
        page_size: baseline.page_size,
        max_bytes: baseline.max_bytes,
        max_run_bytes: baseline.max_run_bytes,
        max_pages: baseline.max_pages,
        max_total_items: baseline.max_total_items,
        max_namespaces: baseline.max_namespaces,
        ..current.clone()
    };
    same_live != *baseline
}


pub fn settings_state(live: &LiveSettings) -> ConfigState {
    let settings = &live.service;
    let fetch = &live.fetch;
    [
        ("fetch_settings", settings.fetch_settings.display().to_string()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("max_assets", format!("{:?}", settings.max_assets)),
        ("max_child_rows", format!("{:?}", settings.max_child_rows)),
        ("fetch::api_url", fetch.api_url.clone()),
        ("fetch::ca_file", fetch.ca_file.display().to_string()),
        ("fetch::token_file", fetch.token_file.display().to_string()),
        ("fetch::tenant", fetch.tenant.clone()),
        ("fetch::cluster", fetch.cluster.clone()),
        ("fetch::timeout_ms", fetch.timeout_ms.to_string()),
        ("fetch::page_size", format!("{:?}", fetch.page_size)),
        ("fetch::max_bytes", format!("{:?}", fetch.max_bytes)),
        ("fetch::max_run_bytes", format!("{:?}", fetch.max_run_bytes)),
        ("fetch::max_pages", format!("{:?}", fetch.max_pages)),
        ("fetch::max_total_items", format!("{:?}", fetch.max_total_items)),
        ("fetch::max_namespaces", format!("{:?}", fetch.max_namespaces)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// A fetch settings refusal keeps its fixed text; every `FetchError` text is fixed.
pub fn fetch_refusal(error: FetchError) -> ConfigError {
    match error {
        FetchError::Config(refused) => refused,
        other => setting_error("fetch_settings", &other.to_string()),
    }
}


/// One read of each file per load: a start-only change in either is refused, so the old snapshot stays.
pub fn settings_loader(file: PathBuf, fetch_file: PathBuf, baseline: LiveSettings) -> Box<LoaderFn<LiveSettings>> {
    Box::new(move || {
        let service = load_service_settings(&file)?;
        if start_only_changed(&baseline.service, &service) {
            Err(setting_error(
                "start-only",
                "fetch_settings, pg_settings and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            let fetch = load_settings(&fetch_file).map_err(fetch_refusal)?;
            if fetch_start_only_changed(&baseline.fetch, &fetch) {
                Err(setting_error(
                    "start-only",
                    "tenant, cluster, api_url, ca_file and token_file are read at start only, restart the service to change them",
                ))
            } else {
                Ok(LiveSettings { service, fetch })
            }
        }
    })
}


pub fn reload_context(file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    }
}


/// The engine of one start snapshot of both files (the caller read each once); `file` is the audit target, an absolute path.
pub fn open_service_settings_from(
    file: &Path,
    fetch_file: &Path,
    baseline: LiveSettings,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<LiveSettings>, ConfigError> {
    open_engine(
        settings_loader(file.to_path_buf(), fetch_file.to_path_buf(), baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}

//! The service settings of `ostyr-k8s-inventory`: one tenant per process, the live values, the start-only baseline and the reload engine.

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


/// Start-only: `pg_settings` and `audit_file`. Live: `fetch_settings`, `interval_seconds`, `max_assets` and `max_child_rows`.
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


/// Everything except the live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        fetch_settings: baseline.fetch_settings.clone(),
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


pub fn settings_state(settings: &ServiceSettings) -> ConfigState {
    [
        ("fetch_settings", settings.fetch_settings.display().to_string()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("max_assets", format!("{:?}", settings.max_assets)),
        ("max_child_rows", format!("{:?}", settings.max_child_rows)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn settings_loader(file: PathBuf, baseline: ServiceSettings) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || {
        let current = load_service_settings(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "pg_settings and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
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


/// The engine of one settings snapshot: the caller read the file once and that value is the baseline.
pub fn open_service_settings_from(
    file: &Path,
    baseline: ServiceSettings,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    open_engine(
        settings_loader(file.to_path_buf(), baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}

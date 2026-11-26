//! The `ostyr-attack-paths` settings file: strict YAML, validated, with the start-only fields held fixed across reloads.


use crate::model::{MAX_DEPTH, MAX_PATHS};
use core_audit::log::{append_declared, AuditLog};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::read_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};


pub const MIN_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_DEADLINE_SECONDS: u64 = 3_600;


pub const MAX_TENANTS: usize = 100;


pub const MODULE: &str = "attack-paths";


pub const SETTINGS_REQUEST: &str = "settings";


pub const ACTOR: &str = "ostyr-attack-paths";


/// One tenant's inputs: the latest `ad-posture` snapshot (JSON) and the manual tag file (YAML), both overwritten in place by their producers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    pub tenant: String,
    pub snapshot_file: PathBuf,
    pub tags_file: PathBuf,
}


/// Start-only: `tenants`, `pg_settings` and `audit_file`. Live: the interval, the statement deadline and the two search limits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackSettings {
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub tenants: Vec<TenantEntry>,
    pub interval_seconds: u64,
    pub deadline_seconds: u64,
    pub max_depth: usize,
    pub max_paths: usize,
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


pub fn require(holds: bool, field: &str, reason: &str) -> Result<(), ConfigError> {
    if holds {
        Ok(())
    } else {
        Err(setting_error(field, reason))
    }
}


pub fn validate_tenants(tenants: &[TenantEntry]) -> Result<(), ConfigError> {
    within("tenants", tenants.len() as u64, 1, MAX_TENANTS as u64)?;
    tenants
        .iter()
        .try_for_each(|entry| tenant_scope(&entry.tenant).map(|_scope| ()))
        .map_err(|_refused| setting_error("tenants", "every tenant must be a valid tenant name"))?;
    let names: BTreeSet<&str> = tenants.iter().map(|entry| entry.tenant.as_str()).collect();
    require(names.len() == tenants.len(), "tenants", "a tenant is listed twice")?;
    require(
        tenants
            .iter()
            .all(|entry| entry.snapshot_file.is_absolute() && entry.tags_file.is_absolute()),
        "tenants",
        "every snapshot_file and tags_file must be an absolute path",
    )
}


pub fn validate_settings(settings: &AttackSettings) -> Result<(), ConfigError> {
    validate_tenants(&settings.tenants)?;
    require(settings.pg_settings.is_absolute(), "pg_settings", "must be an absolute path")?;
    require(settings.audit_file.is_absolute(), "audit_file", "must be an absolute path")?;
    within("interval_seconds", settings.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("deadline_seconds", settings.deadline_seconds, 1, MAX_DEADLINE_SECONDS)?;
    within("max_depth", settings.max_depth as u64, 1, MAX_DEPTH as u64)?;
    within("max_paths", settings.max_paths as u64, 1, MAX_PATHS as u64)
}


pub fn load_settings(file: &Path) -> Result<AttackSettings, ConfigError> {
    let settings: AttackSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// The first start-only field that differs from the start-up snapshot; the four live values may change.
pub fn start_only_field(baseline: &AttackSettings, current: &AttackSettings) -> Option<&'static str> {
    [
        (baseline.tenants != current.tenants).then_some("tenants"),
        (baseline.pg_settings != current.pg_settings).then_some("pg_settings"),
        (baseline.audit_file != current.audit_file).then_some("audit_file"),
    ]
    .into_iter()
    .flatten()
    .next()
}


pub fn settings_state(settings: &AttackSettings) -> ConfigState {
    [
        ("tenants", format!("{:?}", settings.tenants)),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("deadline_seconds", settings.deadline_seconds.to_string()),
        ("max_depth", settings.max_depth.to_string()),
        ("max_paths", settings.max_paths.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn pg_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}


/// The `pg_settings` file is read at start only: a later reload that finds other bytes in it is refused and audited `denied`.
pub fn settings_loader(file: PathBuf, baseline: AttackSettings, pg_baseline: String) -> Box<LoaderFn<AttackSettings>> {
    Box::new(move || {
        let current = load_settings(&file)?;
        let pg_now = pg_digest(&read_file(&baseline.pg_settings)?);
        let pg_field = (pg_now != pg_baseline).then_some("pg_settings (its file content)");
        match start_only_field(&baseline, &current).or(pg_field) {
            Some(field) => Err(setting_error(
                "start-only",
                &format!("{field} changed: it is read at start only, restart the service to change it"),
            )),
            None => Ok(current),
        }
    })
}


/// The audit identity of a reload: the tenant is the non-customer `all`, never a customer tenant the service stores for.
pub fn reload_context(file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: ACTOR.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    }
}


/// The first read is the baseline; a later reload may change only the live values, any other change is refused and audited `denied`.
pub fn open_attack_settings(
    file: &Path,
    baseline: AttackSettings,
    pg_baseline: String,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<AttackSettings>, ConfigError> {
    open_engine(
        settings_loader(file.to_path_buf(), baseline, pg_baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}


pub fn boxed_reload_audit(log: AuditLog<File>) -> Box<SharedAuditFn> {
    Box::new(move |entry| append_declared(&log, entry, &RELOAD_DECLARED_KEYS))
}

//! The `ostyr-grc` declarations: one reload engine over the settings file, the database settings, the manual evidence and the frameworks.

use crate::builtin::{resolve_framework, BUILTIN_PREFIX};
use crate::error::GrcError;
use crate::inputs::load_manual;
use crate::model::{Framework, ManualEvidence};
use crate::store::MAX_REPORTS_PER_TENANT;
use crate::types::DeclarationsReader;
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::tenant_scope;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;


pub const MODULE: &str = "grc";


pub const SETTINGS_REQUEST: &str = "settings";


pub const MIN_INTERVAL_SECONDS: u64 = 300;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_FRAMEWORKS: usize = 8;


/// Start-only: `tenant`, `pg_settings`, `audit_file`, `indicators_dir`, `manual_file` and the database connection fields. Live: the rest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub indicators_dir: PathBuf,
    pub manual_file: PathBuf,
    pub frameworks: Vec<String>,
    pub interval_seconds: u64,
    pub max_reports: i64,
}


/// Everything one round reads: the engine swaps the whole value, so a round never sees a mix of two reloads.
#[derive(Debug, Clone)]
pub struct Declarations {
    pub settings: ServiceSettings,
    pub pg: PgSettings,
    pub frameworks: Vec<Framework>,
    pub manual: Vec<ManualEvidence>,
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


/// A configuration error stays itself; any other refusal is named by its file and its fixed text.
pub fn declaration_error(file: &str, error: GrcError) -> ConfigError {
    match error {
        GrcError::Config(config) => config,
        other => ConfigError::WatchedFile {
            file: file.to_owned(),
            reason: other.to_string(),
        },
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
    tenant_scope(&settings.tenant).map_err(|_refused| setting_error("tenant", "is not a valid customer tenant name"))?;
    within("interval_seconds", settings.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("frameworks", settings.frameworks.len() as u64, 1, MAX_FRAMEWORKS as u64)?;
    within(
        "max_reports",
        u64::try_from(settings.max_reports).unwrap_or(0),
        1,
        MAX_REPORTS_PER_TENANT as u64,
    )?;
    let distinct: BTreeSet<&String> = settings.frameworks.iter().collect();
    if distinct.len() != settings.frameworks.len() {
        Err(setting_error("frameworks", "an entry is listed twice"))
    } else if settings.audit_file.is_absolute() {
        Ok(())
    } else {
        Err(setting_error("audit_file", "must be an absolute path"))
    }
}


/// A manual record of another tenant or a control given twice refuses the whole reload, so a round never meets it.
pub fn validate_manual(tenant: &str, manual: &[ManualEvidence]) -> Result<(), ConfigError> {
    let controls: BTreeSet<&str> = manual.iter().map(|record| record.control.as_str()).collect();
    if manual.iter().any(|record| record.tenant != tenant) {
        Err(setting_error("manual_file", "a record belongs to another tenant"))
    } else if controls.len() != manual.len() {
        Err(setting_error("manual_file", "a control is given twice"))
    } else {
        Ok(())
    }
}


pub fn validate_frameworks(frameworks: &[Framework]) -> Result<(), ConfigError> {
    let names: BTreeSet<&str> = frameworks.iter().map(|framework| framework.framework.as_str()).collect();
    if names.len() == frameworks.len() {
        Ok(())
    } else {
        Err(setting_error("frameworks", "two entries name the same framework"))
    }
}


/// Reads the settings file, then every file it names, once; each file is judged on the bytes parsed.
pub fn load_declarations(file: &Path) -> Result<Declarations, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_settings(&settings)?;
    let pg = load_pg_settings(&settings.pg_settings)?;
    let frameworks = settings
        .frameworks
        .iter()
        .map(|argument| resolve_framework(argument).map_err(|error| declaration_error(argument, error)))
        .collect::<Result<Vec<Framework>, ConfigError>>()?;
    validate_frameworks(&frameworks)?;
    let manual = load_manual(&settings.manual_file).map_err(|error| declaration_error(&settings.manual_file.display().to_string(), error))?;
    validate_manual(&settings.tenant, &manual)?;
    Ok(Declarations {
        settings,
        pg,
        frameworks,
        manual,
    })
}


/// True when a start-only setting differs: the tenant, every path, and every field that says where the database is or who connects.
pub fn start_only_changed(baseline: &Declarations, current: &Declarations) -> bool {
    let settings_changed = ServiceSettings {
        frameworks: baseline.settings.frameworks.clone(),
        interval_seconds: baseline.settings.interval_seconds,
        max_reports: baseline.settings.max_reports,
        ..current.settings.clone()
    } != baseline.settings;
    let pg_changed = PgSettings {
        connect_timeout_secs: baseline.pg.connect_timeout_secs,
        statement_timeout_secs: baseline.pg.statement_timeout_secs,
        ..current.pg.clone()
    } != baseline.pg;
    settings_changed || pg_changed
}


pub fn digest_text(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}


/// One entry per setting, per framework (by digest of its parsed form) and per manual record, so a reload audit names what changed.
pub fn declarations_state(declarations: &Declarations) -> ConfigState {
    let settings = &declarations.settings;
    let pg = &declarations.pg;
    let fixed = [
        ("tenant", settings.tenant.clone()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("indicators_dir", settings.indicators_dir.display().to_string()),
        ("manual_file", settings.manual_file.display().to_string()),
        ("frameworks", settings.frameworks.join(",")),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("max_reports", settings.max_reports.to_string()),
        ("pg.host", pg.host.clone()),
        ("pg.port", pg.port.to_string()),
        ("pg.database", pg.database.clone()),
        ("pg.user", pg.user.clone()),
        ("pg.password_file", pg.password_file.clone()),
        ("pg.ca_file", pg.ca_file.clone()),
        ("pg.connect_timeout_secs", pg.connect_timeout_secs.to_string()),
        ("pg.statement_timeout_secs", pg.statement_timeout_secs.to_string()),
    ];
    let frameworks = declarations
        .frameworks
        .iter()
        .map(|framework| (format!("framework.{}", framework.framework), digest_text(&format!("{framework:?}"))));
    let manual = declarations
        .manual
        .iter()
        .map(|record| (format!("manual.{}", record.control), digest_text(&format!("{record:?}"))));
    fixed
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .chain(frameworks)
        .chain(manual)
        .collect()
}


pub fn declarations_loader(file: PathBuf, read: DeclarationsReader, baseline: Arc<Declarations>) -> Box<LoaderFn<Declarations>> {
    Box::new(move || {
        let current = read(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "tenant, paths and database connection fields are read at start only, restart the service to change them",
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


/// What the signal task and the engine's apply hook tell the round loop; a flag is set before the wake.
#[derive(Debug, Default)]
pub struct Signals {
    pub stop: AtomicBool,
    pub hangup: AtomicBool,
    pub applied: AtomicBool,
    pub wake: Notify,
}


/// An applied reload wakes the round loop, so a changed declaration is evaluated now and not after the pause.
pub fn wake_on_apply(signals: Arc<Signals>) -> Subscriber<Declarations> {
    Subscriber {
        section: MODULE.to_owned(),
        validate: Box::new(|_declarations| Ok(())),
        apply: Box::new(move |_declarations| {
            signals.applied.store(true, Ordering::SeqCst);
            signals.wake.notify_one();
        }),
    }
}


/// The engine of one start read: `baseline` is that read, and the engine's own first read must agree on every start-only value.
pub fn open_declarations(
    file: &Path,
    read: DeclarationsReader,
    baseline: Declarations,
    audit: Box<SharedAuditFn>,
    signals: Arc<Signals>,
) -> Result<ReloadEngine<Declarations>, ConfigError> {
    open_engine(
        declarations_loader(file.to_path_buf(), read, Arc::new(baseline)),
        declarations_state,
        vec![wake_on_apply(signals)],
        audit,
        reload_context(file),
    )
}


/// The files the engine must watch: the settings file, the database settings, the manual evidence and each framework that is a file.
pub fn watched_files(settings_file: &Path, declarations: &Declarations) -> Vec<PathBuf> {
    let settings = &declarations.settings;
    let frameworks = settings
        .frameworks
        .iter()
        .filter(|argument| !argument.starts_with(BUILTIN_PREFIX))
        .map(PathBuf::from);
    [settings_file.to_path_buf(), settings.pg_settings.clone(), settings.manual_file.clone()]
        .into_iter()
        .chain(frameworks)
        .collect()
}

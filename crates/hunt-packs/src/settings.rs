use crate::schedule::MAX_GRACE_SECONDS;
use crate::tick::{check_limits, TickError, TickLimits, DEFAULT_MAX_RUNS, DEFAULT_MAX_RUNS_PER_TICK, DEFAULT_MAX_TENANTS};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;


pub const HUNT_SECTION: &str = "hunt";


pub const MIN_TICK_SECONDS: u64 = 10;


pub const MAX_TICK_SECONDS: u64 = 3_600;


pub fn default_max_runs_per_tick() -> usize {
    DEFAULT_MAX_RUNS_PER_TICK
}


/// The service settings. `tenants` are checked by the tick one by one (a refused one is counted); `pg_settings` and `audit_file` are start-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntSettings {
    pub pg_settings: PathBuf,
    pub clickhouse_settings: PathBuf,
    pub packs_dir: PathBuf,
    pub audit_file: PathBuf,
    pub tenants: Vec<String>,
    pub tick_seconds: u64,
    #[serde(default)]
    pub grace_seconds: i64,
    #[serde(default = "default_max_runs_per_tick")]
    pub max_runs_per_tick: usize,
}


#[derive(Debug, Error)]
pub enum HuntSettingsError {
    #[error("tick_seconds must be {MIN_TICK_SECONDS} to {MAX_TICK_SECONDS}")]
    TickSeconds,
    #[error("grace_seconds must be 0 to {MAX_GRACE_SECONDS}")]
    Grace,
    #[error("pg_settings and audit_file can only change with a restart")]
    StartOnly,
    #[error("audit_file must be an absolute path")]
    AuditFile,
    #[error("tick limits refused")]
    Limits(#[from] TickError),
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] HuntSettingsError),
}


/// The limits one tick runs under, from the settings.
pub fn tick_limits(settings: &HuntSettings) -> TickLimits {
    TickLimits {
        grace_seconds: settings.grace_seconds,
        max_runs: DEFAULT_MAX_RUNS,
        max_tenants: DEFAULT_MAX_TENANTS,
        max_runs_per_tick: settings.max_runs_per_tick,
    }
}


pub fn validate_hunt(settings: &HuntSettings) -> Result<(), HuntSettingsError> {
    if !(MIN_TICK_SECONDS..=MAX_TICK_SECONDS).contains(&settings.tick_seconds) {
        Err(HuntSettingsError::TickSeconds)
    } else if !(0..=MAX_GRACE_SECONDS).contains(&settings.grace_seconds) {
        Err(HuntSettingsError::Grace)
    } else if !settings.audit_file.is_absolute() {
        Err(HuntSettingsError::AuditFile)
    } else {
        check_limits(&tick_limits(settings), settings.tenants.len()).map_err(HuntSettingsError::from)
    }
}


pub fn hunt_state(settings: &HuntSettings) -> ConfigState {
    [
        ("pg_settings", format!("{:?}", settings.pg_settings)),
        ("clickhouse_settings", format!("{:?}", settings.clickhouse_settings)),
        ("packs_dir", format!("{:?}", settings.packs_dir)),
        ("audit_file", format!("{:?}", settings.audit_file)),
        ("tenants", format!("{:?}", settings.tenants)),
        ("tick_seconds", settings.tick_seconds.to_string()),
        ("grace_seconds", settings.grace_seconds.to_string()),
        ("max_runs_per_tick", settings.max_runs_per_tick.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Validates a reload: the bounds, and `pg_settings` and `audit_file` equal to the ones the service started with.
pub fn hunt_subscriber(started_with: PathBuf, started_audit: PathBuf) -> Subscriber<HuntSettings> {
    Subscriber {
        section: HUNT_SECTION.to_owned(),
        validate: Box::new(move |config| {
            validate_hunt(config)?;
            (config.pg_settings == started_with && config.audit_file == started_audit)
                .then_some(())
                .ok_or(HuntSettingsError::StartOnly)?;
            Ok(())
        }),
        apply: Box::new(|_config| ()),
    }
}


/// Loads and validates the first settings; later reloads go through the subscriber and are refused (and audited `denied`) when invalid.
pub fn open_hunt(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<HuntSettings>, OpenError> {
    let first = load_file::<HuntSettings>(&path)?;
    open_hunt_from(path, first, audit, context)
}


/// Opens the engine on settings the caller already read: that value is the baseline, the file is read again only by reloads.
pub fn open_hunt_from(
    path: PathBuf,
    first: HuntSettings,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<HuntSettings>, OpenError> {
    validate_hunt(&first)?;
    let seeded = AtomicBool::new(false);
    let seed = first.clone();
    let loader = move || {
        if seeded.swap(true, Ordering::SeqCst) {
            load_file::<HuntSettings>(&path)
        } else {
            Ok(seed.clone())
        }
    };
    let mut engine = open_engine(Box::new(loader), hunt_state, Vec::new(), audit, context)?;
    engine
        .subscribers
        .push(hunt_subscriber(first.pg_settings.clone(), first.audit_file.clone()));
    Ok(engine)
}

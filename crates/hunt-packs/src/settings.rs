use crate::schedule::MAX_GRACE_SECONDS;
use crate::tick::{check_limits, TickError, TickLimits, DEFAULT_MAX_RUNS, DEFAULT_MAX_RUNS_PER_TICK, DEFAULT_MAX_TENANTS};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;


pub const HUNT_SECTION: &str = "hunt";


pub const MIN_TICK_SECONDS: u64 = 10;


pub const MAX_TICK_SECONDS: u64 = 3_600;


pub fn default_max_runs_per_tick() -> usize {
    DEFAULT_MAX_RUNS_PER_TICK
}


/// The service settings. `tenants` are checked by the tick one by one (a refused one is counted); `pg_settings` is start-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntSettings {
    pub pg_settings: PathBuf,
    pub clickhouse_settings: PathBuf,
    pub packs_dir: PathBuf,
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
    #[error("pg_settings can only change with a restart")]
    StartOnly,
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
    } else {
        check_limits(&tick_limits(settings), settings.tenants.len()).map_err(HuntSettingsError::from)
    }
}


pub fn hunt_state(settings: &HuntSettings) -> ConfigState {
    [
        ("pg_settings", format!("{:?}", settings.pg_settings)),
        ("clickhouse_settings", format!("{:?}", settings.clickhouse_settings)),
        ("packs_dir", format!("{:?}", settings.packs_dir)),
        ("tenants", format!("{:?}", settings.tenants)),
        ("tick_seconds", settings.tick_seconds.to_string()),
        ("grace_seconds", settings.grace_seconds.to_string()),
        ("max_runs_per_tick", settings.max_runs_per_tick.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Validates a reload: the bounds, and `pg_settings` equal to the one the service started with.
pub fn hunt_subscriber(started_with: PathBuf) -> Subscriber<HuntSettings> {
    Subscriber {
        section: HUNT_SECTION.to_owned(),
        validate: Box::new(move |config| {
            validate_hunt(config)?;
            (config.pg_settings == started_with).then_some(()).ok_or(HuntSettingsError::StartOnly)?;
            Ok(())
        }),
        apply: Box::new(|_config| ()),
    }
}


/// Loads and validates the first settings; later reloads go through the subscriber and are refused (and audited `denied`) when invalid.
pub fn open_hunt(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<HuntSettings>, OpenError> {
    let mut engine = open_engine(Box::new(move || load_file::<HuntSettings>(&path)), hunt_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_hunt(&first)?;
    engine.subscribers.push(hunt_subscriber(first.pg_settings.clone()));
    Ok(engine)
}

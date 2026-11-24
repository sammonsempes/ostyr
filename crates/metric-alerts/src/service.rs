//! The service rounds: settings, the rules and settings reload engines, one pass over every tenant and the round loop.

use crate::error::RuleError;
use crate::fetch::FetchError;
use crate::model::RuleFile;
use crate::query::{parse_tenant_id, MetricQuery};
use crate::recover::{recover_states, recovery_class};
use crate::round::{evaluate_round, store_round, RoundError, RoundStates};
use crate::rules::load_rules;
use crate::types::{FetchFn, FetchResult, LiveFn, NowFn, PassFn, TenantStates, Timestamp, WaitFn};
use alerts::error::StoreError;
use alerts::types::Executor;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::{tenant_of, TenantScope};
use serde::Deserialize;
use siem_schema::metrics::MetricsRetention;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};


pub const MIN_ROUND_SECONDS: u64 = 30;


pub const MAX_ROUND_SECONDS: u64 = 3600;


pub const MAX_TENANTS: usize = 100;


pub const MAX_ROUNDS: u64 = 10_000_000;


pub const MODULE: &str = "metric-alerts";


pub const AUDIT_TENANT: &str = "platform";


pub const SETTINGS_REQUEST: &str = "settings";


pub const RULES_REQUEST: &str = "rules";


/// Start-only: `rules_file`, `pg_settings` and `audit_file`. Live: `fetch_settings`, `tenants`, `round_seconds` and `max_tenants`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub fetch_settings: PathBuf,
    pub rules_file: PathBuf,
    pub pg_settings: PathBuf,
    pub tenants: Vec<String>,
    pub round_seconds: u64,
    pub max_tenants: usize,
    pub audit_file: PathBuf,
}


/// One round's snapshot: the settings and the rules in force when it starts, and the stop flag the signal path sets.
#[derive(Debug, Clone)]
pub struct Live {
    pub settings: Arc<ServiceSettings>,
    pub rules: Arc<RuleFile>,
    pub stop: Arc<AtomicBool>,
}


/// Fixed-size counts of one pass: tenants run, tenants refused by name, tenants whose round failed, and passes not run at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassReport {
    pub tenants: usize,
    pub refused: usize,
    pub failed: usize,
    pub unavailable: usize,
}


/// What one tenant's round did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantReport {
    pub recovered: usize,
    pub evaluated: usize,
    pub firings: usize,
    pub stored: usize,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServeEnd {
    pub rounds: u64,
    pub clock_skips: u64,
}


#[derive(Debug, Error)]
pub enum TenantFault {
    #[error("the round states do not belong to this tenant")]
    Round(#[from] RoundError),
    #[error("the alerts could not be stored")]
    Store(#[from] StoreError),
    #[error("the service is stopping, the evaluation was dropped")]
    Stopped,
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
    within("round_seconds", settings.round_seconds, MIN_ROUND_SECONDS, MAX_ROUND_SECONDS)?;
    within("max_tenants", settings.max_tenants as u64, 1, MAX_TENANTS as u64)?;
    within("tenants", settings.tenants.len() as u64, 1, settings.max_tenants as u64)?;
    if settings.audit_file.is_absolute() {
        Ok(())
    } else {
        Err(setting_error("audit_file", "must be an absolute path"))
    }
}


/// Everything except the four live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        fetch_settings: baseline.fetch_settings.clone(),
        tenants: baseline.tenants.clone(),
        round_seconds: baseline.round_seconds,
        max_tenants: baseline.max_tenants,
        ..current.clone()
    };
    same_live != *baseline
}


pub fn load_settings(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


pub fn settings_state(settings: &ServiceSettings) -> ConfigState {
    [
        ("fetch_settings", settings.fetch_settings.display().to_string()),
        ("rules_file", settings.rules_file.display().to_string()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("tenants", format!("{:?}", settings.tenants)),
        ("round_seconds", settings.round_seconds.to_string()),
        ("max_tenants", settings.max_tenants.to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn settings_loader(file: PathBuf, baseline: ServiceSettings) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || {
        let current = load_settings(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "rules_file, pg_settings and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


pub fn reload_context(file: &Path, request: &str) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: request.to_owned(),
    }
}


/// The first read is the baseline; a later reload may change only the live values, any other change is refused and audited.
pub fn open_service_settings(file: &Path, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    let baseline = load_settings(file)?;
    open_engine(
        settings_loader(file.to_path_buf(), baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file, SETTINGS_REQUEST),
    )
}


pub fn rules_error(file: &Path, error: RuleError) -> ConfigError {
    match error {
        RuleError::Config(config) => config,
        other => ConfigError::WatchedFile {
            file: file.display().to_string(),
            reason: other.to_string(),
        },
    }
}


pub fn rules_loader(file: PathBuf) -> Box<LoaderFn<RuleFile>> {
    Box::new(move || load_rules(&file).map_err(|error| rules_error(&file, error)))
}


/// One entry per rule id, so a reload audit names the rules that changed.
pub fn rules_state(rules: &RuleFile) -> ConfigState {
    rules
        .rules
        .iter()
        .map(|rule| (format!("rule.{}", rule.id), format!("{rule:?}")))
        .collect()
}


pub fn open_rules(file: &Path, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<RuleFile>, ConfigError> {
    open_engine(
        rules_loader(file.to_path_buf()),
        rules_state,
        Vec::new(),
        audit,
        reload_context(file, RULES_REQUEST),
    )
}


/// The distinct tenants of the list that pass core-pg's grammar, and how many were refused; a refused name never stops the others.
pub fn tenants_of(settings: &ServiceSettings) -> (Vec<(String, TenantScope)>, usize) {
    let distinct: BTreeSet<&String> = settings.tenants.iter().collect();
    let scopes: Vec<(String, TenantScope)> = distinct
        .iter()
        .filter_map(|name| match parse_tenant_id(name) {
            Ok(scope) => Some((tenant_of(&scope).to_owned(), scope)),
            Err(error) => {
                warn!(%error, "tenant refused, skipped");
                None
            }
        })
        .collect();
    let refused = distinct.len() - scopes.len();
    (scopes, refused)
}


/// A reading not later than the previous round's runs nothing, so the store never gets an evaluation in the past.
pub fn next_now(previous: Option<Timestamp>, reading: Timestamp) -> Option<Timestamp> {
    match previous {
        Some(last) if reading <= last => None,
        _ if reading == 0 => None,
        _ => Some(reading),
    }
}


pub fn fault_class(fault: &TenantFault) -> &'static str {
    match fault {
        TenantFault::Round(_) => "tenant_mismatch",
        TenantFault::Store(_) => "store",
        TenantFault::Stopped => "stopped",
    }
}


/// Answers a fetch only while the service runs: once the flag is set no query is sent.
pub fn guarded_fetch(stop: &AtomicBool, fetch: FetchFn<'_>, query: &MetricQuery) -> FetchResult {
    if stop.load(Ordering::SeqCst) {
        Err(FetchError::Stopped)
    } else {
        fetch(query)
    }
}


/// A store fault of the recovery is logged by class and retried next round; the evaluation still runs. A stop drops the evaluation unstored.
pub async fn attempt(
    exec: Executor<'_, '_>,
    fetch: FetchFn<'_>,
    stop: &AtomicBool,
    scope: &TenantScope,
    rules: &RuleFile,
    now: Timestamp,
    states: &mut RoundStates,
) -> Result<TenantReport, TenantFault> {
    let recovered = match recover_states(exec, scope, rules, now, states).await {
        Err(RoundError::Store(fault)) => {
            let class = recovery_class(&fault);
            warn!(class, "recovery failed, retrying next round");
            Ok(states.candidates.len())
        }
        other => other,
    }?;
    let guarded = |query: &MetricQuery| guarded_fetch(stop, fetch, query);
    let outcome = evaluate_round(rules, scope, now, &MetricsRetention::default(), &guarded, states)?;
    let stored = if stop.load(Ordering::SeqCst) {
        Err(TenantFault::Stopped)
    } else {
        Ok(store_round(exec, scope, &outcome, now).await?)
    }?;
    Ok(TenantReport {
        recovered,
        evaluated: outcome.counts.evaluated,
        firings: outcome.firings.len(),
        stored,
    })
}


/// Runs one tenant's round; answers whether it succeeded, a failure is logged by class and never reaches another tenant.
pub async fn tenant_round(
    exec: Executor<'_, '_>,
    fetch: FetchFn<'_>,
    stop: &AtomicBool,
    scope: &TenantScope,
    rules: &RuleFile,
    now: Timestamp,
    states: &mut RoundStates,
) -> bool {
    let tenant = tenant_of(scope);
    match attempt(exec, fetch, stop, scope, rules, now, states).await {
        Ok(report) => {
            let TenantReport {
                recovered,
                evaluated,
                firings,
                stored,
            } = report;
            info!(tenant, recovered, evaluated, firings, stored, "tenant round done");
            true
        }
        Err(fault) => {
            let class = fault_class(&fault);
            warn!(tenant, class, "tenant round failed");
            false
        }
    }
}


/// One round over every tenant, each with its own `RoundStates`; the stop flag is read before each tenant and each fetch.
pub async fn run_pass(exec: Executor<'_, '_>, fetch: FetchFn<'_>, live: &Live, now: Timestamp, states: &mut TenantStates) -> PassReport {
    let (scopes, refused) = tenants_of(&live.settings);
    let listed: BTreeSet<&String> = scopes.iter().map(|(name, _)| name).collect();
    states.retain(|name, _| listed.contains(name));
    let mut failed = 0;
    let stop: &AtomicBool = &live.stop;
    for (name, scope) in scopes.iter().take_while(|_| !stop.load(Ordering::SeqCst)) {
        let tenant_states = states.entry(name.clone()).or_default();
        if !tenant_round(exec, fetch, stop, scope, &live.rules, now, tenant_states).await {
            failed += 1;
        }
    }
    let tenants = scopes.len();
    info!(tenants, refused, failed, "round done");
    PassReport {
        tenants,
        refused,
        failed,
        unavailable: 0,
    }
}


/// Runs at most `max_rounds` rounds, one clock reading each, pausing between them; the caller stops it by dropping the future.
pub async fn serve(max_rounds: u64, live: &LiveFn<'_>, now: &NowFn<'_>, pass: &mut PassFn<'_>, wait: &WaitFn<'_>) -> ServeEnd {
    let mut rounds = 0;
    let mut clock_skips = 0;
    let mut previous: Option<Timestamp> = None;
    while rounds < MAX_ROUNDS.min(max_rounds) {
        let snapshot = live();
        let pause = Duration::from_secs(snapshot.settings.round_seconds);
        let reading = now();
        match next_now(previous, reading) {
            Some(at) => {
                pass(snapshot, at).await;
                previous = Some(at);
            }
            None => {
                clock_skips += 1;
                warn!(reading, clock_skips, "clock_not_advancing, round not run");
            }
        }
        rounds += 1;
        wait(pause).await;
    }
    ServeEnd { rounds, clock_skips }
}

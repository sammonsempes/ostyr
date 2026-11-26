//! The `ostyr-dhcp` service: follows Kea's lease file, stores the lease history and raises the unknown-device alerts of one tenant.

use crate::alerting::{advance_cursor, lookup_batch, micros_of, path_digest, plan_alerts, store_unknown_device_alerts, RoundKey};
use crate::cursor::{MIGRATIONS as CURSOR_MIGRATIONS, MIGRATION_NAMESPACE as CURSOR_NAMESPACE};
use crate::error::{KeaError, RoundError};
use crate::follow::{malformed_summary, poll, Counts, FollowState, Limits};
use crate::history::{store_history, HistoryCounts, HistorySettings};
use crate::row::{normalise_mac, Converted};
use crate::types::{InterruptWait, WaitFn};
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::read_bytes_capped;
use core_config::reload::{check_watched_files, current_config, open_engine, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::stderr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{error, info, warn};


const USAGE: &str = "usage: ostyr-dhcp <settings.yaml>";


const MODULE: &str = "dhcp";


const SETTINGS_REQUEST: &str = "settings";


const KNOWN_REQUEST: &str = "known-devices";


const DEBOUNCE: Duration = Duration::from_millis(300);


const NANOS_PER_MICRO: i128 = 1_000;


const ROUNDS: usize = usize::MAX;


const GRACE_STATEMENTS: u64 = 8;


const MAX_ROUNDS: usize = usize::MAX - 1;


pub const MIN_INTERVAL_SECONDS: u64 = 10;


pub const MAX_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_DEADLINE_SECONDS: u64 = 600;


pub const MAX_KNOWN_BYTES: u64 = 2_097_152;


pub const MAX_KNOWN_MACS: usize = 100_000;


const FIRST_PRINTABLE: u8 = 0x20;


const LAST_PRINTABLE: u8 = 0x7E;


const LINE_FEED: u8 = b'\n';


/// Start-only: `tenant` and every path. Live: the interval and the statement deadline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub pg_settings: PathBuf,
    pub lease_file: PathBuf,
    pub known_file: PathBuf,
    pub audit_file: PathBuf,
    pub interval_seconds: u64,
    pub statement_deadline_seconds: u64,
}


/// The MACs the CMDB knows, in the ECS form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownDevices {
    pub macs: BTreeSet<String>,
}


/// What the reader holds between two rounds: its position, its counts the leases read but not yet stored, and the leases whose unknown MAC waits for an alert.
#[derive(Debug, Default)]
pub struct Follower {
    pub state: FollowState,
    pub counts: Counts,
    pub pending: Vec<Converted>,
    pub waiting: Vec<Converted>,
    pub key: RoundKey,
}


/// What one round stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundReport {
    pub leases: usize,
    pub history: HistoryCounts,
    pub alerts: usize,
    pub loss_alerts: usize,
    pub inserted: usize,
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
    tenant_scope(&settings.tenant).map_err(|_refused| setting_error("tenant", "is not a valid tenant name"))?;
    within("interval_seconds", settings.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("statement_deadline_seconds", settings.statement_deadline_seconds, 1, MAX_DEADLINE_SECONDS)
}


/// Everything except the two live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        interval_seconds: baseline.interval_seconds,
        statement_deadline_seconds: baseline.statement_deadline_seconds,
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
        ("tenant", settings.tenant.clone()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("lease_file", settings.lease_file.display().to_string()),
        ("known_file", settings.known_file.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("statement_deadline_seconds", settings.statement_deadline_seconds.to_string()),
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
                "tenant and every path are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


fn context_for(target: &Path, request: &str) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: target.display().to_string(),
        request_id: request.to_owned(),
    }
}


/// The baseline is the one read of the settings file the caller already made.
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
        context_for(file, SETTINGS_REQUEST),
    )
}


fn known_error(file: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.to_owned(),
        reason: reason.to_owned(),
    }
}


fn printable(byte: u8) -> bool {
    byte == LINE_FEED || (FIRST_PRINTABLE..=LAST_PRINTABLE).contains(&byte)
}


/// One MAC per line in any form `normalise_mac` reads, blank lines allowed; a byte outside printable ASCII and line feed refuses the file.
pub fn parse_known(bytes: Vec<u8>, file: &str) -> Result<KnownDevices, ConfigError> {
    if bytes.iter().copied().all(printable) {
        let text: String = bytes.into_iter().map(char::from).collect();
        let macs = text
            .lines()
            .enumerate()
            .filter(|(_number, line)| !line.is_empty())
            .try_fold(BTreeSet::new(), |mut found, (number, line)| {
                let mac = normalise_mac(line).ok_or_else(|| known_error(file, &format!("line {} is not a MAC address", number + 1)))?;
                found.insert(mac);
                Ok::<BTreeSet<String>, ConfigError>(found)
            })?;
        if macs.len() > MAX_KNOWN_MACS {
            Err(known_error(file, &format!("holds more than {MAX_KNOWN_MACS} devices")))
        } else {
            Ok(KnownDevices { macs })
        }
    } else {
        Err(known_error(file, "only printable ASCII and line feeds are allowed"))
    }
}


pub fn load_known(path: &Path) -> Result<KnownDevices, ConfigError> {
    parse_known(read_bytes_capped(path, MAX_KNOWN_BYTES)?, &path.display().to_string())
}


pub fn known_state(known: &KnownDevices) -> ConfigState {
    known.macs.iter().map(|mac| (format!("mac:{mac}"), "known".to_owned())).collect()
}


pub fn open_known(path: &Path, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<KnownDevices>, ConfigError> {
    check_watched_files(&[path.display().to_string()])?;
    let file = path.to_path_buf();
    open_engine(
        Box::new(move || load_known(&file)),
        known_state,
        Vec::new(),
        audit,
        context_for(path, KNOWN_REQUEST),
    )
}


pub fn reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// Reads the lease file once; whatever it read is kept pending even when the read then fails, because its offset has moved.
pub fn collect(path: &Path, follower: &mut Follower, limits: &Limits) -> Result<(), RoundError> {
    let mut out = Vec::new();
    let polled = poll(path, &mut follower.state, limits, &mut follower.counts, &mut out);
    follower.pending.extend(out);
    match polled {
        Err(KeaError::NotRegular) => {
            follower.counts.refused += 1;
            warn!("the lease path is not a regular file, refused");
            Ok(())
        }
        other => other.map_err(RoundError::from),
    }
}


/// One round: the new leases (or the ones a failed round left pending) go to the history, then the unknown MACs to the alerts. `now` is Unix seconds.
pub async fn run_round(
    exec: alerts::types::Executor<'_, '_>,
    scope: &TenantScope,
    known: &KnownDevices,
    follower: &mut Follower,
    (path, limits, now): (&Path, &Limits, i64),
) -> Result<RoundReport, RoundError> {
    if follower.pending.is_empty() {
        collect(path, follower, limits)?;
    }
    if follower.pending.is_empty() && follower.waiting.is_empty() {
        Ok(RoundReport::default())
    } else {
        let history = store_history(exec, scope, &HistorySettings::default(), now, &follower.pending).await?;
        let batch: Vec<Converted> = follower.waiting.iter().chain(follower.pending.iter()).cloned().collect();
        let lookup = lookup_batch(exec, scope, &batch, &known.macs, !follower.waiting.is_empty()).await;
        if lookup.failed {
            Err(RoundError::LookupFailed)
        } else {
            let skipped: BTreeSet<String> = known.macs.union(&lookup.skip).cloned().collect();
            let plan = plan_alerts(
                scope,
                &batch,
                &skipped,
                micros_of(now),
                (&lookup.scan_order, &lookup.deferred),
                &follower.key,
            );
            let device_inserted = store_unknown_device_alerts(exec, scope, &plan.alerts).await?;
            let loss_stored = store_unknown_device_alerts(exec, scope, plan.loss.as_slice()).await?;
            log_unstored_loss(plan.dropped, plan.loss.is_some(), loss_stored);
            let inserted = device_inserted + loss_stored;
            advance_cursor(exec, scope, &lookup).await;
            let leases = follower.pending.len();
            follower.pending.clear();
            follower.waiting = plan.waiting;
            follower.key.round += 1;
            Ok(RoundReport {
                leases,
                history,
                alerts: plan.alerts.len(),
                loss_alerts: loss_stored,
                inserted,
            })
        }
    }
}


/// A planned loss alert the insert did not store (its id already exists) is an error naming the dropped count, never silent.
pub fn log_unstored_loss(dropped: usize, planned: bool, stored: usize) {
    if planned && stored == 0 {
        error!(dropped, "dhcp loss alert not stored, its id already exists");
    }
}


pub fn log_round(outcome: &Result<RoundReport, RoundError>) {
    match outcome {
        Ok(report) => {
            let (leases, stored, alerts, inserted) = (report.leases, report.history.inserted, report.alerts, report.inserted);
            let loss_alerts = report.loss_alerts;
            info!(leases, stored, alerts, loss_alerts, inserted, "dhcp round done");
        }
        Err(error) => warn!(%error, "dhcp round failed, the leases are retried"),
    }
}


/// What one round added to the follower's counts.
pub fn counts_delta(before: &Counts, after: &Counts) -> Counts {
    Counts {
        evicted: after.evicted.saturating_sub(before.evicted),
        restarts: after.restarts.saturating_sub(before.restarts),
        absent: after.absent.saturating_sub(before.absent),
        refused: after.refused.saturating_sub(before.refused),
        unrecovered: after.unrecovered.saturating_sub(before.unrecovered),
        beyond_seen: after.beyond_seen.saturating_sub(before.beyond_seen),
        malformed: after
            .malformed
            .iter()
            .map(|(kind, number)| (kind.clone(), number.saturating_sub(before.malformed.get(kind).copied().unwrap_or(0))))
            .filter(|(_kind, added)| *added > 0)
            .collect(),
        ..Counts::default()
    }
}


/// One fixed-text warning per round while the lease file is absent, and one warning naming every non-zero count of the round.
pub fn log_counts(delta: &Counts) {
    if delta.absent > 0 {
        warn!("the lease file is absent");
    }
    let malformed = malformed_summary(delta);
    let (refused, evicted, unrecovered, beyond_seen, restarts) = (delta.refused, delta.evicted, delta.unrecovered, delta.beyond_seen, delta.restarts);
    if refused + evicted + unrecovered + beyond_seen + restarts > 0 || !malformed.is_empty() {
        let summary = format!(
            "refused={refused} evicted={evicted} unrecovered={unrecovered} beyond_seen={beyond_seen} restarts={restarts} malformed={malformed}"
        );
        warn!(summary, "dhcp round counts");
    }
}


pub fn pause(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


#[cfg(unix)]
fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub struct NoSignals;


#[cfg(not(unix))]
fn keep_signals<Config>(_engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<NoSignals> {
    Ok(NoSignals)
}


/// Resolves on SIGINT or SIGTERM.
#[cfg(unix)]
pub fn termination() -> std::io::Result<InterruptWait> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _first = interrupt.recv() => {}
            _second = terminate.recv() => {}
        }
        Ok(())
    }))
}


pub async fn run(arguments: &[String], interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_ansi(false).with_writer(stderr).finish())?;
    start(Path::new(settings_file), ROUNDS, interrupt).await
}


pub async fn start(settings_file: &Path, rounds: usize, interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    start_with(settings_file, rounds, interrupt, pause).await
}


async fn migrate_all(pg: &PgSettings, deadline: Duration) -> Result<(), Box<dyn Error>> {
    let client = connect(pg).await?;
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, deadline).await?;
    migrate(&client, CURSOR_NAMESPACE, &CURSOR_MIGRATIONS, deadline).await?;
    Ok(())
}


/// `wait` is called between two rounds with the interval in force.
pub async fn start_with(settings_file: &Path, rounds: usize, interrupt: InterruptWait, wait: WaitFn) -> Result<(), Box<dyn Error>> {
    let baseline = load_settings(settings_file)?;
    let log = Arc::new(open_file_log(&baseline.audit_file)?);
    let settings_engine = Arc::new(open_service_settings_from(settings_file, baseline, reload_audit(&log))?);
    let start = current_config(&settings_engine);
    let known_engine = Arc::new(open_known(&start.known_file, reload_audit(&log))?);
    let _settings_watch = watch_files(Arc::clone(&settings_engine), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _known_watch = watch_files(Arc::clone(&known_engine), std::slice::from_ref(&start.known_file), DEBOUNCE)?;
    let _settings_signals = keep_signals(&settings_engine)?;
    let _known_signals = keep_signals(&known_engine)?;
    let pg = load_pg_settings(&start.pg_settings)?;
    migrate_all(&pg, Duration::from_secs(start.statement_deadline_seconds)).await?;
    let scope = tenant_scope(&start.tenant)?;
    let limits = Limits {
        started: OffsetDateTime::now_utc().unix_timestamp(),
        ..Limits::default()
    };
    info!(tenant = start.tenant, "serving");
    let stopped = serve(rounds, (&settings_engine, &known_engine), (&pg, &scope, &limits), (wait, interrupt)).await;
    let _settings_gate = settings_engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    let _known_gate = known_engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(stopped?)
}


/// Between two rounds: `Some` when the interrupt came before the interval ended.
pub async fn pause_or_stop(interrupt: &mut InterruptWait, wait: WaitFn, interval: Duration) -> Option<std::io::Result<()>> {
    tokio::select! {
        biased;
        signalled = interrupt => Some(signalled),
        () = wait(interval) => None,
    }
}


/// The key of this process: the digest of its lease file path and its start in real microseconds, the round counter at 0.
pub fn round_key(lease_file: &Path) -> RoundKey {
    let started = OffsetDateTime::now_utc().unix_timestamp_nanos() / NANOS_PER_MICRO;
    RoundKey {
        path_digest: path_digest(lease_file),
        started_micros: u64::try_from(started).unwrap_or(0),
        round: 0,
    }
}


/// A round runs to its end, whatever interrupt arrives meanwhile; only the shutdown grace (the statement deadline times `GRACE_STATEMENTS`) cuts it.
pub async fn serve(
    rounds: usize,
    engines: (&ReloadEngine<ServiceSettings>, &ReloadEngine<KnownDevices>),
    site: (&PgSettings, &TenantScope, &Limits),
    (wait, mut interrupt): (WaitFn, InterruptWait),
) -> std::io::Result<()> {
    let (settings_engine, known_engine) = engines;
    let (pg, scope, limits) = site;
    let mut follower = Follower {
        key: round_key(&current_config(settings_engine).lease_file),
        ..Follower::default()
    };
    let mut stopped: Option<std::io::Result<()>> = None;
    let mut done = 0;
    while stopped.is_none() && done < rounds.min(MAX_ROUNDS) {
        let settings = current_config(settings_engine);
        let known = current_config(known_engine);
        let before = follower.counts.clone();
        let grace = Duration::from_secs(settings.statement_deadline_seconds * GRACE_STATEMENTS);
        let (outcome, interrupted) = {
            let round = one_round(pg, scope, &settings, &known, &mut follower, limits);
            tokio::pin!(round);
            tokio::select! {
                biased;
                finished = &mut round => (Some(finished), None),
                signalled = &mut interrupt => {
                    info!("interrupt received, finishing the round in flight");
                    let finished = tokio::select! {
                        biased;
                        finished = &mut round => Some(finished),
                        () = wait(grace) => None,
                    };
                    (finished, Some(signalled))
                }
            }
        };
        match outcome {
            Some(finished) => {
                log_round(&finished);
                log_counts(&counts_delta(&before, &follower.counts));
            }
            None => warn!("dhcp round cut at the shutdown deadline"),
        }
        stopped = match interrupted {
            Some(signalled) => Some(signalled),
            None => pause_or_stop(&mut interrupt, wait, Duration::from_secs(settings.interval_seconds)).await,
        };
        done += 1;
    }
    log_waiting_at_stop(&follower);
    stopped.unwrap_or(Ok(()))
}


/// At stop the waiting list and the leases a failed round left pending are in memory only: the MACs in them are dropped, and their numbers are logged.
pub fn log_waiting_at_stop(follower: &Follower) {
    let (waiting, pending) = (follower.waiting.len(), follower.pending.len());
    if waiting + pending > 0 {
        warn!(waiting, pending, "dhcp service stopping, the waiting unknown MACs are dropped");
    }
}


async fn one_round(
    pg: &PgSettings,
    scope: &TenantScope,
    settings: &ServiceSettings,
    known: &KnownDevices,
    follower: &mut Follower,
    limits: &Limits,
) -> Result<RoundReport, RoundError> {
    let client = connect(pg).await?;
    let exec = pg_executor(&client, Duration::from_secs(settings.statement_deadline_seconds));
    let now = OffsetDateTime::now_utc().unix_timestamp();
    run_round(&exec, scope, known, follower, (&settings.lease_file, limits, now)).await
}

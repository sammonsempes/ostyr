//! The pieces of the `ostyr-backup-monitor` service: settings, declarations engine, rounds, schedule and audit entries (Unix only).

use crate::borg::{private_handle, BorgError, BORG_PROGRAM};
use crate::check::{rotated_turns, run_round_with, RoundContext, RoundControl, RoundOutcome};
use crate::declarations::load_declarations;
use crate::error::{BackupError, RestoreStoreError};
use crate::model::{CoverageStatus, Declarations, FindingKind, Limits};
use crate::restic::RESTIC_PROGRAM;
use crate::restore::{restore_plan, restore_test, RestoreOutcome, RestoreResult, RestoreTarget};
use crate::secrets::SecretsDir;
use crate::store::{
    category_label, record_restore_results_with_cap, run_error_category, test_key, RunErrorRecord, TestKey, WriteCounts, MAX_RESTORE_ROWS,
};
use crate::types::{Clock, Identity, RowFuture, SettingsReader};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_audit::tenant::AUDIT_TENANT;
use core_audit::types::ParameterMap;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::read_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use core_pg::settings::PgSettings;
use core_pg::types::SqlParameter;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const MODULE: &str = "backup-monitor";


pub const SETTINGS_REQUEST: &str = "backup-monitor-settings";


pub const DECLARATIONS_REQUEST: &str = "backup-monitor-declarations";


pub const ROUND_REQUEST: &str = "backup-monitor-round";


pub const CHECK_ACTION: &str = "backup.check_round";


pub const RESTORE_ACTION: &str = "backup.restore_round";


pub const MIN_INTERVAL_SECONDS: u64 = 3600;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_ROUND_SECONDS: u64 = 3300;


pub const COMMAND_DEADLINE_SECONDS: u64 = 120;


pub const TENANT_SWAP_REASON: &str = "the declarations tenant differs from the tenant of the service";


pub const ROUND_KEYS: [&str; 23] = [
    "skipped_invalid",
    "run_error",
    "round_error",
    "repositories",
    "failed",
    "refused",
    "not_run",
    "previous_unreadable",
    "deleted",
    "retention_below_floor",
    "repository_changed",
    "coverage_ok",
    "coverage_stale",
    "coverage_missing",
    "missed_ticks",
    "tests",
    "restored",
    "not_restored",
    "written",
    "stale_write",
    "config_changed",
    "pruned",
    "store",
];


/// Start-only: every path and the tenant. Live: the two intervals.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub declarations_file: PathBuf,
    pub state_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub interval_seconds: u64,
    pub restore_interval_seconds: u64,
}


/// The two program paths a round runs: constants in production, scripts in tests.
#[derive(Debug, Clone)]
pub struct Programs {
    pub restic: PathBuf,
    pub borg: PathBuf,
}


/// The per-command deadline and the bound of one round.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub command_deadline: Duration,
    pub max_round: Duration,
}


/// Everything a round needs that is fixed at start.
#[derive(Debug)]
pub struct Shared {
    pub programs: Programs,
    pub secrets: SecretsDir,
    pub state: PathBuf,
    pub state_identity: Identity,
    pub reports: OwnedFd,
    pub limits: Limits,
    pub timing: Timing,
    pub euid: u32,
    pub clock: Clock,
}


/// What went wrong before a round could spawn anything: fixed texts, no path.
#[derive(Debug, Error)]
pub enum RoundError {
    #[error("the state directory is refused")]
    State(#[source] BorgError),
    #[error("the state directory is not the one opened at start")]
    StateChanged,
    #[error("the state directory cannot be inspected")]
    StateIdentity(#[source] rustix::io::Errno),
}


/// Why the results of a restore round were not stored: connecting, or the store itself.
#[derive(Debug, Error)]
pub enum StoreFailure {
    #[error("cannot connect to the database")]
    Connect(#[source] PgError),
    #[error("cannot record the results")]
    Record(#[source] RestoreStoreError),
}


/// The tests run, the errors, every declared key (for the prune) and what was left out.
#[derive(Debug)]
pub struct RestoreRun {
    pub results: Vec<(TestKey, RestoreResult)>,
    pub errors: Vec<(TestKey, RunErrorRecord)>,
    pub declared: Vec<TestKey>,
    pub refused: usize,
    pub not_run: usize,
    pub next_start: usize,
}


pub fn production_programs() -> Programs {
    Programs {
        restic: PathBuf::from(RESTIC_PROGRAM),
        borg: PathBuf::from(BORG_PROGRAM),
    }
}


pub fn production_timing() -> Timing {
    Timing {
        command_deadline: Duration::from_secs(COMMAND_DEADLINE_SECONDS),
        max_round: Duration::from_secs(MAX_ROUND_SECONDS),
    }
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
    within(
        "restore_interval_seconds",
        settings.restore_interval_seconds,
        MIN_INTERVAL_SECONDS,
        MAX_INTERVAL_SECONDS,
    )
}


pub fn load_settings(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// Everything except the two intervals must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        interval_seconds: baseline.interval_seconds,
        restore_interval_seconds: baseline.restore_interval_seconds,
        ..current.clone()
    };
    same_live != *baseline
}


pub fn settings_state(settings: &ServiceSettings) -> ConfigState {
    [
        ("tenant", settings.tenant.clone()),
        ("declarations_file", settings.declarations_file.display().to_string()),
        ("state_dir", settings.state_dir.display().to_string()),
        ("secrets_dir", settings.secrets_dir.display().to_string()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("interval_seconds", settings.interval_seconds.to_string()),
        ("restore_interval_seconds", settings.restore_interval_seconds.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Reads through `read` (one read per load) and refuses a change of a start-only value.
pub fn settings_loader(file: PathBuf, baseline: ServiceSettings, read: SettingsReader) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || {
        let current = read(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "the tenant and every path are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


pub fn open_service_settings_from(
    file: &Path,
    baseline: ServiceSettings,
    read: SettingsReader,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    };
    open_engine(
        settings_loader(file.to_path_buf(), baseline, read),
        settings_state,
        Vec::new(),
        audit,
        context,
    )
}


/// A refused declarations file keeps its fixed reason; a document error is already free of document text.
pub fn declarations_refusal(error: BackupError) -> ConfigError {
    match error {
        BackupError::Declarations(refused) => refused,
        other => ConfigError::WatchedFile {
            file: "declarations".to_owned(),
            reason: other.to_string(),
        },
    }
}


/// Loads the declarations through the strict reader and refuses a tenant other than the pinned one, at start and at every reload.
pub fn declarations_loader(file: PathBuf, pinned: String) -> Box<LoaderFn<Declarations>> {
    Box::new(move || {
        let text = read_file(&file)?;
        let loaded = load_declarations(&text, &file.display().to_string()).map_err(declarations_refusal)?;
        if tenant_of(&loaded.tenant) == pinned {
            Ok(loaded)
        } else {
            Err(setting_error("tenant", TENANT_SWAP_REASON))
        }
    })
}


pub fn digest_text(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}


/// The audited state: names and digests, never a location or a secret file name.
pub fn declarations_state(declarations: &Declarations) -> ConfigState {
    let fixed = [
        ("tenant".to_owned(), tenant_of(&declarations.tenant).to_owned()),
        ("hostname_from_name".to_owned(), declarations.hostname_from_name.to_string()),
        ("critical".to_owned(), digest_text(&format!("{:?}", declarations.critical))),
    ];
    let repositories = declarations
        .repositories
        .iter()
        .map(|entry| (format!("repository.{}", entry.repository), digest_text(&format!("{entry:?}"))));
    fixed.into_iter().chain(repositories).collect()
}


pub fn open_declarations_engine(file: &Path, pinned: &str, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<Declarations>, ConfigError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: DECLARATIONS_REQUEST.to_owned(),
    };
    open_engine(
        declarations_loader(file.to_path_buf(), pinned.to_owned()),
        declarations_state,
        Vec::new(),
        audit,
        context,
    )
}


pub fn state_identity(handle: &OwnedFd) -> Result<Identity, RoundError> {
    rustix::fs::fstat(handle)
        .map(|stat| (stat.st_dev, stat.st_ino))
        .map_err(RoundError::StateIdentity)
}


/// A fresh `open_trusted_dir` plus 0700 of the state path must be the directory opened at start.
pub fn verify_state(shared: &Shared) -> Result<(), RoundError> {
    let fresh = private_handle(&shared.state, shared.euid).map_err(RoundError::State)?;
    state_identity(&fresh).and_then(|identity| {
        if identity == shared.state_identity {
            Ok(())
        } else {
            Err(RoundError::StateChanged)
        }
    })
}


/// The first command of a round always starts (a round always makes progress); later ones only before the stop and the bound.
pub fn may_start_after(stop: &AtomicBool, started: Instant, max_round: Duration, count: usize) -> bool {
    !stop.load(Ordering::SeqCst) && (count == 0 || started.elapsed() < max_round)
}


/// One check round from `start` in plan order; nothing is spawned when the state directory is not the one opened at start.
pub fn check_round(shared: &Shared, declarations: &Declarations, start: usize, stop: &AtomicBool) -> Result<RoundOutcome, RoundError> {
    verify_state(shared)?;
    let started = Instant::now();
    let context = RoundContext {
        restic_program: &shared.programs.restic,
        borg_program: &shared.programs.borg,
        secrets: &shared.secrets,
        state: Some(shared.state.as_path()),
        reports: Some(&shared.reports),
        limits: &shared.limits,
        deadline: shared.timing.command_deadline,
        euid: shared.euid,
        clock: shared.clock,
    };
    let may_start = |count: usize| may_start_after(stop, started, shared.timing.max_round, count);
    Ok(run_round_with(
        &context,
        declarations,
        &RoundControl {
            start,
            may_start: &may_start,
        },
    ))
}


/// One restore round from `start` in plan order: the results and errors of the tests that ran, every declared key and what was left out.
pub fn restore_round(shared: &Shared, declarations: &Declarations, start: usize, stop: &AtomicBool) -> Result<RestoreRun, RoundError> {
    verify_state(shared)?;
    let started = Instant::now();
    let plan = restore_plan(declarations);
    let declared: Vec<TestKey> = plan.runnable.iter().map(|(name, _, test)| test_key(name, test)).collect();
    let mut results: Vec<(TestKey, RestoreResult)> = Vec::new();
    let mut errors: Vec<(TestKey, RunErrorRecord)> = Vec::new();
    let may_start = |count: usize| may_start_after(stop, started, shared.timing.max_round, count);
    let turns = rotated_turns(
        plan.runnable.len(),
        &RoundControl {
            start,
            may_start: &may_start,
        },
        &mut |index| {
            plan.runnable.get(index).into_iter().for_each(|(name, source, test)| {
                let key = test_key(name, test);
                let target = RestoreTarget {
                    tenant: &declarations.tenant,
                    source,
                    test,
                };
                match restore_test(
                    &shared.programs.restic,
                    &shared.secrets,
                    &target,
                    &shared.limits,
                    shared.timing.command_deadline,
                    shared.clock,
                    shared.euid,
                ) {
                    Ok(result) => results.push((key, result)),
                    Err(error) => {
                        let category = run_error_category(&error);
                        let label = category_label(category);
                        warn!(repository = *name, category = label, "restore test failed");
                        errors.push((
                            key,
                            RunErrorRecord {
                                tenant: declarations.tenant.clone(),
                                tested_at: OffsetDateTime::now_utc(),
                                category,
                            },
                        ));
                    }
                }
            });
        },
    );
    let left_out: Vec<usize> = turns.iter().filter(|(_, ran)| !ran).map(|(index, _)| *index).collect();
    Ok(RestoreRun {
        results,
        errors,
        declared,
        refused: plan.refused.len(),
        not_run: left_out.len(),
        next_start: left_out.first().copied().unwrap_or(0),
    })
}


pub fn statement_deadline(settings: &PgSettings) -> Duration {
    Duration::from_secs(settings.statement_timeout_secs)
}


async fn pg_rows(
    client: &tokio_postgres::Client,
    scope: TenantScope,
    sql: &'static str,
    params: Vec<String>,
    deadline: Duration,
) -> Result<Vec<Vec<String>>, PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, deadline).await?;
    rows.iter()
        .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
        .collect()
}


/// Writes the results of one restore round for the pinned tenant through the store function (one connection per round).
pub async fn store_restore(settings: &PgSettings, scope: &TenantScope, run: &RestoreRun) -> Result<WriteCounts, StoreFailure> {
    let client = connect(settings).await.map_err(StoreFailure::Connect)?;
    let deadline = statement_deadline(settings);
    let exec =
        |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, tenant, sql, params, deadline)) };
    record_restore_results_with_cap(&exec, scope, &run.results, &run.errors, &run.declared, MAX_RESTORE_ROWS)
        .await
        .map_err(StoreFailure::Record)
}


/// The fixed category of a store failure.
pub fn failure_category(failure: &StoreFailure) -> &'static str {
    match failure {
        StoreFailure::Connect(_) => "connect",
        StoreFailure::Record(_) => "record",
    }
}


/// The next due second after a round: one interval after the due one, moved past every tick the round overran; the second value counts those ticks.
pub fn next_due(due: u64, interval: u64, now: u64) -> (u64, u64) {
    let planned = due.saturating_add(interval);
    let overrun = u64::from(now >= planned) * (now.saturating_sub(planned) / interval.max(1) + 1);
    (planned.saturating_add(overrun.saturating_mul(interval)), overrun)
}


pub fn count_text(count: usize) -> String {
    count.to_string()
}


/// Counts only: the audited summary of a check round.
pub fn check_parameters(round: &RoundOutcome, missed: u64) -> ParameterMap {
    let checks = round.repositories.iter().filter_map(|(_, result)| result.as_ref().ok());
    let findings: Vec<&FindingKind> = checks
        .clone()
        .flat_map(|check| check.findings.iter().map(|finding| &finding.kind))
        .collect();
    let by_kind = |wanted: fn(&FindingKind) -> bool| findings.iter().filter(|kind| wanted(kind)).count();
    let covered = |wanted: fn(&CoverageStatus) -> bool| round.coverage.iter().filter(|entry| wanted(&entry.status)).count();
    [
        ("repositories", count_text(round.repositories.len())),
        (
            "failed",
            count_text(round.repositories.iter().filter(|(_, result)| result.is_err()).count()),
        ),
        ("refused", count_text(round.refused_restic.len() + round.refused_borg.len())),
        ("not_run", count_text(round.not_run.len())),
        (
            "previous_unreadable",
            count_text(checks.filter(|check| check.previous_unreadable).count()),
        ),
        ("deleted", count_text(by_kind(|kind| matches!(kind, FindingKind::Deleted { .. })))),
        (
            "retention_below_floor",
            count_text(by_kind(|kind| matches!(kind, FindingKind::RetentionBelowFloor { .. }))),
        ),
        (
            "repository_changed",
            count_text(by_kind(|kind| matches!(kind, FindingKind::RepositoryChanged { .. }))),
        ),
        ("coverage_ok", count_text(covered(|status| matches!(status, CoverageStatus::Ok)))),
        (
            "coverage_stale",
            count_text(covered(|status| matches!(status, CoverageStatus::Stale { .. }))),
        ),
        (
            "coverage_missing",
            count_text(covered(|status| matches!(status, CoverageStatus::Missing))),
        ),
        ("missed_ticks", missed.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Counts only: the audited summary of a restore round and of its store step.
pub fn restore_parameters(run: &RestoreRun, stored: &Result<WriteCounts, StoreFailure>, missed: u64) -> ParameterMap {
    let restored = run
        .results
        .iter()
        .filter(|(_, result)| result.outcome == RestoreOutcome::Restored)
        .count();
    let counts = stored.as_ref().map_or_else(|_| WriteCounts::default(), Clone::clone);
    let store = stored.as_ref().map_or_else(failure_category, |_| "ok");
    [
        ("tests", count_text(run.results.len() + run.errors.len())),
        ("restored", count_text(restored)),
        ("not_restored", count_text(run.results.len() - restored + run.errors.len())),
        ("refused", count_text(run.refused)),
        ("not_run", count_text(run.not_run)),
        ("written", counts.written.to_string()),
        ("skipped_invalid", counts.skipped_invalid.to_string()),
        ("run_error", counts.run_error.to_string()),
        ("stale_write", counts.stale_write.to_string()),
        ("config_changed", counts.config_changed.to_string()),
        ("pruned", counts.pruned.to_string()),
        ("store", store.to_owned()),
        ("missed_ticks", missed.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// One audit record of a round, always under the non-customer tenant `all`.
pub fn round_entry(action: &str, target: &str, outcome: Outcome, parameters: ParameterMap) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        outcome,
        request_id: ROUND_REQUEST.to_owned(),
        justification: None,
        parameters,
    }
}


/// The audit outcome of a check round: a failed repository or a repository left out is a failure.
pub fn check_outcome(round: &RoundOutcome) -> Outcome {
    if round.not_run.is_empty() && round.repositories.iter().all(|(_, result)| result.is_ok()) {
        Outcome::Success
    } else {
        Outcome::Failure
    }
}


/// The audit outcome of a restore round.
pub fn restore_outcome(run: &RestoreRun, stored: &Result<WriteCounts, StoreFailure>) -> Outcome {
    if run.errors.is_empty() && run.not_run == 0 && stored.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    }
}


/// The log line of a check round: counts and fixed categories only.
pub fn log_check(round: &RoundOutcome, missed: u64) {
    let parameters = check_parameters(round, missed);
    let summary = format!("{parameters:?}");
    info!(summary, "check round done");
}


/// The log line of a restore round: counts and fixed categories only.
pub fn log_restore(run: &RestoreRun, stored: &Result<WriteCounts, StoreFailure>, missed: u64) {
    let parameters = restore_parameters(run, stored, missed);
    let summary = format!("{parameters:?}");
    info!(summary, "restore round done");
}

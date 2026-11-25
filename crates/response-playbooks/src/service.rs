use crate::batch::{dry_run_batch, AlertRun, DryRunLimits, DryRunReport, Line};
use crate::bundle::{Bundle, MODULE};
use crate::error::RoundError;
use crate::feed::alert_json;
use crate::render::write_dry_run;
use crate::runs::{run_rows, store_runs, RunRow, BOUND_NAME, MAX_PLAYBOOK_RUNS};
use crate::types::{ControlFn, LiveFn, NowFn, WaitFn};
use alerts::id::is_alert_id;
use alerts::model::{FeedItem, FeedRow};
use alerts::store::{ack_playbook_feed, read_playbook_feed, MAX_PAGE_SIZE};
use alerts::types::{AuditAppendFn, Executor as StoreExec};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome as AuditOutcome};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use core_pg::transaction::Boundary;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;
use tracing::{error, info, warn};


pub const ROUND_ACTION: &str = "playbooks.dry_run";


pub const FEED_TARGET: &str = "playbook_outbox";


pub const INVALID_ID: &str = "invalid";


pub const NO_RANGE_REQUEST: &str = "round-none";


pub const SETTINGS_REQUEST: &str = "settings";


pub const MAX_FEED_AGE_SECONDS: u64 = 604_800;


pub const MAX_NAME_BYTES: usize = 64;


pub const MAX_RECORD_NAMES: usize = 64;


pub const MAX_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_MATCHES: usize = 16;


pub const MAX_TRACE_EVENTS: usize = 10_000;


pub const MAX_PLAYBOOK_FILES: usize = 256;


pub const MAX_BACKOFF_SHIFT: u32 = 5;


pub const LOUD_AFTER_FAILURES: u32 = 2;


pub const MAX_REPLAYED_ROUNDS: u32 = 3;


pub const ROUND_KEYS: [&str; 16] = [
    BOUNDS_KEY,
    "acknowledged",
    "alerts",
    "seq_first",
    "seq_last",
    "simulated",
    "matches",
    "matched_alerts",
    "playbooks",
    "playbooks_omitted",
    "skipped",
    "undecodable",
    "expired_unprocessed",
    "runs_written",
    "runs_replayed",
    "runs_pruned",
];


pub const BOUNDS_KEY: &str = "bounds";


/// Start-only: `tenant`, `pg_settings` and every path. Live: the interval, the page size and the dry-run limits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub pg_settings: PathBuf,
    pub catalogue: PathBuf,
    pub inventory: PathBuf,
    pub playbooks: Vec<PathBuf>,
    pub limits_file: PathBuf,
    pub scratch_dir: PathBuf,
    pub audit_file: PathBuf,
    pub poll_interval_seconds: u64,
    pub page_size: usize,
    pub max_matches_per_alert: usize,
    pub max_trace_events: usize,
}


/// One round's snapshot: the bundle and the settings in force when it starts.
#[derive(Debug, Clone)]
pub struct Live {
    pub bundle: Arc<Bundle>,
    pub settings: Arc<ServiceSettings>,
}


/// The feed page sorted: rows to simulate, ids of rows too old, ids of rows that do not decode, and the `seq` range of every row of the page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sorted<'a> {
    pub runnable: Vec<&'a FeedRow>,
    pub expired: Vec<String>,
    pub undecodable: Vec<String>,
    pub range: Option<(u64, u64)>,
}


/// The row ids of the last recorded page whose delete failed, and how many records that page already has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Replays {
    pub ids: BTreeSet<String>,
    pub records: u32,
}


/// What one round did, in fixed-size data: counts, ids, names and the bounds hit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub read: usize,
    pub simulated: usize,
    pub range: Option<(u64, u64)>,
    pub matches: usize,
    pub matched_alerts: Vec<String>,
    pub playbooks: Vec<String>,
    pub playbooks_omitted: usize,
    pub skipped: Vec<String>,
    pub undecodable: Vec<String>,
    pub expired: Vec<String>,
    pub acknowledged: Vec<String>,
    pub bounds: Vec<&'static str>,
    pub runs_written: usize,
    pub runs_replayed: usize,
    pub runs_pruned: usize,
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
    within("playbooks", settings.playbooks.len() as u64, 1, MAX_PLAYBOOK_FILES as u64)?;
    within("poll_interval_seconds", settings.poll_interval_seconds, 1, MAX_INTERVAL_SECONDS)?;
    within("page_size", settings.page_size as u64, 1, MAX_PAGE_SIZE as u64)?;
    within("max_matches_per_alert", settings.max_matches_per_alert as u64, 1, MAX_MATCHES as u64)?;
    within("max_trace_events", settings.max_trace_events as u64, 1, MAX_TRACE_EVENTS as u64)
}


/// Everything except the four live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    let same_live = ServiceSettings {
        poll_interval_seconds: baseline.poll_interval_seconds,
        page_size: baseline.page_size,
        max_matches_per_alert: baseline.max_matches_per_alert,
        max_trace_events: baseline.max_trace_events,
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
        ("catalogue", settings.catalogue.display().to_string()),
        ("inventory", settings.inventory.display().to_string()),
        ("playbooks", format!("{:?}", settings.playbooks)),
        ("limits_file", settings.limits_file.display().to_string()),
        ("scratch_dir", settings.scratch_dir.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("poll_interval_seconds", settings.poll_interval_seconds.to_string()),
        ("page_size", settings.page_size.to_string()),
        ("max_matches_per_alert", settings.max_matches_per_alert.to_string()),
        ("max_trace_events", settings.max_trace_events.to_string()),
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
                "tenant, pg_settings and every path are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


/// The first read is the baseline; a later reload may change only the four live values, any other change is refused and audited `denied`.
pub fn open_service_settings(file: &Path, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    open_service_settings_from(file, load_settings(file)?, audit)
}


/// Same as `open_service_settings` over a baseline the caller already parsed, so one read of the file serves both.
pub fn open_service_settings_from(
    file: &Path,
    baseline: ServiceSettings,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: baseline.tenant.clone(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    };
    open_engine(settings_loader(file.to_path_buf(), baseline), settings_state, Vec::new(), audit, context)
}


/// An id of a row that did not decode may be anything the table holds: only an alert id is shown.
pub fn shown_id(id: &str) -> String {
    if is_alert_id(id) {
        id.to_owned()
    } else {
        INVALID_ID.to_owned()
    }
}


pub fn decoded(item: &FeedItem) -> Option<&FeedRow> {
    item.row.as_ref().ok()
}


pub fn sort_page(items: &[FeedItem]) -> Sorted<'_> {
    let rows: Vec<&FeedRow> = items.iter().filter_map(decoded).collect();
    let seqs: Vec<u64> = items.iter().filter_map(|item| item.seq).collect();
    Sorted {
        runnable: rows.iter().copied().filter(|row| row.age_seconds <= MAX_FEED_AGE_SECONDS).collect(),
        expired: rows
            .iter()
            .filter(|row| row.age_seconds > MAX_FEED_AGE_SECONDS)
            .map(|row| row.alert.id.clone())
            .collect(),
        undecodable: items
            .iter()
            .filter(|item| decoded(item).is_none())
            .map(|item| shown_id(&item.id))
            .collect(),
        range: seqs.iter().min().zip(seqs.iter().max()).map(|(first, last)| (*first, *last)),
    }
}


/// A name cut at `MAX_NAME_BYTES` on a character boundary.
pub fn bounded_name(name: &str) -> String {
    name.chars()
        .scan(0, |bytes, character| {
            *bytes += character.len_utf8();
            (*bytes <= MAX_NAME_BYTES).then_some(character)
        })
        .collect()
}


pub fn run_id(sorted: &Sorted<'_>, run: &AlertRun) -> String {
    sorted
        .runnable
        .get(run.position)
        .map_or_else(|| INVALID_ID.to_owned(), |row| row.alert.id.clone())
}


/// The record data of one round; the trace text never enters it.
pub fn outcome_of(items: &[FeedItem], sorted: &Sorted<'_>, report: Option<&DryRunReport>, page_size: usize) -> Outcome {
    let runs: &[AlertRun] = report.map_or(&[], |found| found.alerts.as_slice());
    let names: BTreeSet<String> = runs
        .iter()
        .flat_map(|run| run.traces.iter().map(|trace| bounded_name(&trace.playbook)))
        .collect();
    let bounds = [
        (items.len() >= page_size, "backlog"),
        (runs.iter().any(|run| run.matches_over_bound > 0), "max_matches_per_alert"),
        (
            runs.iter().any(|run| run.matches_over_budget > 0 || run.events_omitted > 0),
            "max_trace_events",
        ),
    ];
    Outcome {
        read: items.len(),
        simulated: runs.iter().filter(|run| run.skipped.is_none()).count(),
        range: sorted.range,
        matches: runs.iter().map(|run| run.traces.len()).sum(),
        matched_alerts: runs.iter().filter(|run| !run.traces.is_empty()).map(|run| run_id(sorted, run)).collect(),
        playbooks_omitted: names.len().saturating_sub(MAX_RECORD_NAMES),
        playbooks: names.into_iter().take(MAX_RECORD_NAMES).collect(),
        skipped: runs
            .iter()
            .filter_map(|run| run.skipped.map(|reason| format!("{}={reason}", run_id(sorted, run))))
            .collect(),
        undecodable: sorted.undecodable.clone(),
        expired: sorted.expired.clone(),
        acknowledged: items.iter().map(|item| shown_id(&item.id)).collect(),
        bounds: bounds.into_iter().filter(|(hit, _name)| *hit).map(|(_hit, name)| name).collect(),
        ..Outcome::default()
    }
}


pub fn list(items: &[String]) -> String {
    json!(items).to_string()
}


pub fn round_entry(tenant: &str, outcome: &Outcome, now: OffsetDateTime) -> NewEntry {
    let range_text = |pick: fn(&(u64, u64)) -> u64| outcome.range.as_ref().map_or_else(String::new, |range| pick(range).to_string());
    let parameters: BTreeMap<String, String> = [
        ("alerts", outcome.read.to_string()),
        ("seq_first", range_text(|range| range.0)),
        ("seq_last", range_text(|range| range.1)),
        ("simulated", outcome.simulated.to_string()),
        ("matches", outcome.matches.to_string()),
        ("matched_alerts", list(&outcome.matched_alerts)),
        ("playbooks", list(&outcome.playbooks)),
        ("playbooks_omitted", outcome.playbooks_omitted.to_string()),
        ("skipped", list(&outcome.skipped)),
        ("undecodable", list(&outcome.undecodable)),
        ("expired_unprocessed", list(&outcome.expired)),
        ("acknowledged", list(&outcome.acknowledged)),
        ("runs_written", outcome.runs_written.to_string()),
        ("runs_replayed", outcome.runs_replayed.to_string()),
        ("runs_pruned", outcome.runs_pruned.to_string()),
        (BOUNDS_KEY, json!(outcome.bounds).to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    NewEntry {
        timestamp: now,
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: MODULE.to_owned(),
        action: ROUND_ACTION.to_owned(),
        target: FEED_TARGET.to_owned(),
        outcome: AuditOutcome::Success,
        request_id: outcome
            .range
            .map_or_else(|| NO_RANGE_REQUEST.to_owned(), |(first, last)| format!("round-{first}-{last}")),
        justification: None,
        parameters,
    }
}


/// The dry run on a blocking thread: scratch breakers of its own, nothing executed.
pub async fn simulate_page(live: &Live, lines: Vec<Line>) -> Result<Option<DryRunReport>, RoundError> {
    if lines.is_empty() {
        Ok(None)
    } else {
        let bundle = Arc::clone(&live.bundle);
        let settings = Arc::clone(&live.settings);
        let report = spawn_blocking(move || {
            let limits = DryRunLimits {
                max_alerts: settings.page_size,
                max_matches_per_alert: settings.max_matches_per_alert,
                max_trace_events: settings.max_trace_events,
            };
            dry_run_batch(&bundle, &settings.limits_file, &settings.scratch_dir, &settings.tenant, &lines, limits)
        })
        .await??;
        Ok(Some(report))
    }
}


/// A page is a replay when its ids were all recorded and the cap is reached: one id outside the recorded set always gets a record.
pub fn is_replay(replays: &Replays, ids: &BTreeSet<String>) -> bool {
    ids.is_subset(&replays.ids) && replays.records >= MAX_REPLAYED_ROUNDS
}


/// The state after a record was appended for the page `ids`: the count grows only while the page holds ids already recorded.
pub fn next_replays(replays: &Replays, ids: &BTreeSet<String>) -> Replays {
    Replays {
        ids: ids.clone(),
        records: if ids.is_subset(&replays.ids) {
            replays.records.saturating_add(1)
        } else {
            1
        },
    }
}


pub fn log_replay(range: Option<(u64, u64)>, records: u32) {
    let text = format!("playbooks round replays range {range:?} after {records} records, no new record until its rows are deleted");
    error!("{text}");
}


pub fn log_partial_ack(range: Option<(u64, u64)>, deleted: usize, expected: usize) {
    let text = format!("playbooks round partial ack range {range:?}: {deleted} of {expected} rows deleted, the rest replays");
    warn!("{text}");
}


/// The database as a round sees it: the statement executor and the transaction boundaries, both on one connection.
pub struct Db<'a, 'b> {
    pub exec: StoreExec<'a, 'b>,
    pub control: ControlFn<'a>,
}


/// What the transaction needs besides the executor: the page, the rows to store, the record data and the replay state in force.
pub struct Atomic<'a> {
    pub items: &'a [FeedItem],
    pub rows: &'a [RunRow],
    pub outcome: &'a Outcome,
    pub replays: &'a Replays,
}


/// The round's result before the commit: its record data and the replay state to keep when the commit succeeds (`committed`) or fails after the record was appended (`recorded`).
#[derive(Debug, Clone)]
pub struct Done {
    pub outcome: Outcome,
    pub recorded: Replays,
    pub committed: Replays,
}


pub fn log_pruned(pruned: usize) {
    let text = format!("playbooks run store over {MAX_PLAYBOOK_RUNS} rows: {pruned} oldest runs deleted");
    warn!("{text}");
}


/// The statements of one round, in order: runs (lock, insert, count, prune), delete of the page, record. The caller ends the transaction.
pub async fn atomic_round(
    exec: StoreExec<'_, '_>,
    scope: &TenantScope,
    audit: AuditAppendFn<'_>,
    now: NowFn,
    input: &Atomic<'_>,
) -> Result<Done, RoundError> {
    let counts = store_runs(exec, scope, input.rows, now().unix_timestamp()).await?;
    let deleted = ack_playbook_feed(exec, scope, input.items).await?;
    if deleted > input.items.len() {
        Err(RoundError::AckCount {
            deleted,
            expected: input.items.len(),
        })
    } else {
        let pruned_bound = (counts.pruned > 0).then_some(BOUND_NAME);
        let outcome = Outcome {
            runs_written: counts.written,
            runs_replayed: counts.replayed,
            runs_pruned: counts.pruned,
            bounds: input.outcome.bounds.iter().copied().chain(pruned_bound).collect(),
            ..input.outcome.clone()
        };
        if counts.pruned > 0 {
            log_pruned(counts.pruned);
        }
        let page_ids: BTreeSet<String> = input.items.iter().map(|item| item.id.clone()).collect();
        let replay = is_replay(input.replays, &page_ids);
        if replay {
            log_replay(outcome.range, input.replays.records);
        } else {
            audit(round_entry(tenant_of(scope), &outcome, now()))?;
        }
        if deleted < input.items.len() {
            log_partial_ack(outcome.range, deleted, input.items.len());
        }
        let recorded = if replay {
            input.replays.clone()
        } else {
            next_replays(input.replays, &page_ids)
        };
        let committed = if deleted == input.items.len() {
            Replays::default()
        } else {
            recorded.clone()
        };
        Ok(Done {
            outcome,
            recorded,
            committed,
        })
    }
}


/// Ends the transaction: a finished round is committed, a failed one rolled back with its error kept; a failed rollback is logged.
pub async fn finish_round(control: ControlFn<'_>, result: Result<Done, RoundError>, replays: &mut Replays) -> Result<Outcome, RoundError> {
    match result {
        Ok(done) => {
            let ended = control(Boundary::Commit).await;
            *replays = if ended.is_ok() { done.committed } else { done.recorded };
            ended?;
            Ok(done.outcome)
        }
        Err(failed) => {
            if let Err(refused) = control(Boundary::Rollback).await {
                let text = format!("playbooks round rollback failed: {refused}");
                warn!("{text}");
            }
            Err(failed)
        }
    }
}


/// One round: read the oldest page of the tenant's feed, simulate, write the trace, then in one transaction store the runs, delete the rows and append one record.
pub async fn run_round<Out: Write>(
    db: &Db<'_, '_>,
    scope: &TenantScope,
    live: &Live,
    audit: AuditAppendFn<'_>,
    now: NowFn,
    trace_out: &mut Out,
    replays: &mut Replays,
) -> Result<Outcome, RoundError> {
    let items = read_playbook_feed(db.exec, scope, live.settings.page_size).await?;
    if items.is_empty() {
        Ok(Outcome::default())
    } else {
        let sorted = sort_page(&items);
        let lines: Vec<Line> = sorted
            .runnable
            .iter()
            .map(|row| Line::Alert(alert_json(tenant_of(scope), &row.alert)))
            .collect();
        let report = simulate_page(live, lines).await?;
        if let Some(found) = &report {
            write_dry_run(trace_out, found).map_err(RoundError::Trace)?;
        }
        let outcome = outcome_of(&items, &sorted, report.as_ref(), live.settings.page_size);
        let rows = run_rows(tenant_of(scope), &sorted.runnable, report.as_ref(), &live.bundle.catalogue);
        (db.control)(Boundary::Begin).await?;
        let input = Atomic {
            items: &items,
            rows: &rows,
            outcome: &outcome,
            replays,
        };
        let result = atomic_round(db.exec, scope, audit, now, &input).await;
        finish_round(db.control, result, replays).await
    }
}


pub fn next_failures(failures: u32, outcome: &Result<Outcome, RoundError>) -> u32 {
    match outcome {
        Ok(_done) => 0,
        Err(_failed) => failures.saturating_add(1),
    }
}


pub fn backoff(interval_seconds: u64, failures: u32) -> Duration {
    Duration::from_secs(interval_seconds).saturating_mul(1 << failures.min(MAX_BACKOFF_SHIFT))
}


/// A failure streak is loud at its second failure and again at each power of two.
pub fn is_loud(failures: u32) -> bool {
    failures >= LOUD_AFTER_FAILURES && failures.is_power_of_two()
}


pub fn log_round(outcome: &Result<Outcome, RoundError>, failures: u32) {
    match outcome {
        Ok(done) if done.read > 0 => {
            let text = format!(
                "playbooks round: {} read, {} simulated, {} matches, {} skipped, {} undecodable, {} expired, bounds {:?}",
                done.read,
                done.simulated,
                done.matches,
                done.skipped.len(),
                done.undecodable.len(),
                done.expired.len(),
                done.bounds
            );
            info!("{text}");
        }
        Ok(_empty) => {}
        Err(failed) => {
            let text = format!("playbooks round failed ({failures} in a row), rows kept: {failed}");
            if is_loud(failures) {
                error!("{text}");
            } else {
                warn!("{text}");
            }
        }
    }
}


/// `rounds` rounds, each on the snapshot `live()` returns at its start; a failed round keeps its rows and the wait doubles up to a cap.
pub async fn serve<Round, Pending>(rounds: usize, live: LiveFn<'_>, round: &mut Round, wait: WaitFn)
where
    Round: FnMut(Live) -> Pending,
    Pending: Future<Output = Result<Outcome, RoundError>>,
{
    let mut failures: u32 = 0;
    for _round in 0..rounds {
        let snapshot = live();
        let interval = snapshot.settings.poll_interval_seconds;
        let outcome = round(snapshot).await;
        failures = next_failures(failures, &outcome);
        log_round(&outcome, failures);
        wait(backoff(interval, failures)).await;
    }
}

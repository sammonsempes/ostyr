use crate::error::shown_id;
use crate::model::{HuntPack, Source};
use crate::schedule::{RunWindow, ScheduleError};
use crate::store::{last_done, record_done, Param, StateError};
use crate::types::{DueFn, RunFn};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use std::future::Future;
use thiserror::Error;
use tracing::{info, warn};


/// A stored end later than `now` by more than this is a poisoned state, not a clock difference.
pub const MAX_CLOCK_SKEW: i64 = 300;


pub const DEFAULT_MAX_TENANTS: usize = 100;


pub const MAX_TENANTS_CEILING: usize = 10_000;


pub const DEFAULT_MAX_RUNS_PER_TICK: usize = 500;


pub const MAX_RUNS_PER_TICK_CEILING: usize = 10_000;


pub const DEFAULT_MAX_RUNS: u32 = 24;


pub struct TickLimits {
    pub grace_seconds: i64,
    pub max_runs: u32,
    pub max_tenants: usize,
    pub max_runs_per_tick: usize,
}


impl Default for TickLimits {
    fn default() -> Self {
        Self {
            grace_seconds: 0,
            max_runs: DEFAULT_MAX_RUNS,
            max_tenants: DEFAULT_MAX_TENANTS,
            max_runs_per_tick: DEFAULT_MAX_RUNS_PER_TICK,
        }
    }
}


/// The two injected steps: production binds `run_pack` and `schedule::due_runs`; `run` is a trait object so a test can record its calls.
pub struct Hooks<'run> {
    pub run: &'run mut RunFn<'run>,
    pub due: DueFn,
}


#[derive(Debug, Error)]
pub enum TickError {
    #[error("max_tenants must be 1 to {MAX_TENANTS_CEILING} and max_runs_per_tick at most {MAX_RUNS_PER_TICK_CEILING}")]
    InvalidLimits,
    #[error("{count} tenants, at most {max} per tick")]
    TooManyTenants { count: usize, max: usize },
}


/// Fixed texts only: the error kinds of `RunError`, `StateError` and `ScheduleError` carry no query, key or server message.
#[derive(Debug, PartialEq, Eq)]
pub enum PackStatus {
    Done,
    Deferred,
    StateInFuture,
    FutureEnd,
    RunFailed(String),
    StoreFailed(String),
    ScheduleFailed(String),
}


#[derive(Debug, PartialEq, Eq)]
pub struct RunRecord {
    pub end: i64,
    pub finding: bool,
}


pub struct PackReport {
    pub tenant: String,
    pub pack_id: String,
    pub attempted: usize,
    pub runs: Vec<RunRecord>,
    pub last_end: Option<i64>,
    pub status: PackStatus,
}


#[derive(Default)]
pub struct TickReport {
    pub packs: Vec<PackReport>,
    pub deferred: usize,
    pub skipped_osquery: usize,
    pub refused_tenants: usize,
}


/// The tenant ceiling and the tenant count are checked before any statement.
pub fn check_limits(limits: &TickLimits, tenants: usize) -> Result<(), TickError> {
    ((1..=MAX_TENANTS_CEILING).contains(&limits.max_tenants) && limits.max_runs_per_tick <= MAX_RUNS_PER_TICK_CEILING)
        .then_some(())
        .ok_or(TickError::InvalidLimits)?;
    (tenants <= limits.max_tenants).then_some(()).ok_or(TickError::TooManyTenants {
        count: tenants,
        max: limits.max_tenants,
    })
}


fn store_failure(tenant: &str, pack_id: &str, error: &StateError) -> PackStatus {
    let id = shown_id(pack_id);
    let text = error.to_string();
    warn!("hunt store failed: tenant {tenant} pack {id}: {text}");
    PackStatus::StoreFailed(text)
}


fn schedule_failure(tenant: &str, pack_id: &str, error: &ScheduleError) -> PackStatus {
    let id = shown_id(pack_id);
    let text = error.to_string();
    warn!("hunt schedule failed: tenant {tenant} pack {id}: {text}");
    PackStatus::ScheduleFailed(text)
}


/// The windows due for the pack, or the status that stops it: a stored end far in the future runs nothing.
pub async fn due_windows<Executor, Pending>(
    exec: &mut Executor,
    tenant: &str,
    pack: &HuntPack,
    now: i64,
    limits: &TickLimits,
    due: DueFn,
) -> Result<Vec<RunWindow>, PackStatus>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let stored = last_done(exec, tenant, &pack.id)
        .await
        .map_err(|error| store_failure(tenant, &pack.id, &error))?;
    let latest_allowed = now.saturating_add(MAX_CLOCK_SKEW);
    if stored.is_some_and(|end| end > latest_allowed) {
        let id = shown_id(&pack.id);
        warn!("hunt state in the future: tenant {tenant} pack {id}");
        Err(PackStatus::StateInFuture)
    } else {
        due(pack, stored, now, limits.grace_seconds, limits.max_runs).map_err(|error| schedule_failure(tenant, &pack.id, &error))
    }
}


/// One window: refuse an end after `now`, run, then record; a failed run records nothing.
pub async fn run_window<Executor, Pending>(
    exec: &mut Executor,
    report: &mut PackReport,
    pack: &HuntPack,
    window: &RunWindow,
    now: i64,
    run: &mut RunFn<'_>,
) where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    if window.end > now {
        report.status = PackStatus::FutureEnd;
    } else {
        report.attempted += 1;
        match run(pack, &report.tenant, window.end) {
            Ok(outcome) => match record_done(exec, &report.tenant, &pack.id, window.end).await {
                Ok(stored) => {
                    report.runs.push(RunRecord {
                        end: window.end,
                        finding: outcome.finding,
                    });
                    report.last_end = Some(stored);
                }
                Err(error) => report.status = store_failure(&report.tenant, &pack.id, &error),
            },
            Err(error) => report.status = PackStatus::RunFailed(error.to_string()),
        }
    }
}


/// One pack for one tenant with `budget` runs left in the tick; the windows run oldest first and the first failure stops the pack.
pub async fn tick_pack<Executor, Pending>(
    exec: &mut Executor,
    tenant: &str,
    pack: &HuntPack,
    now: i64,
    limits: &TickLimits,
    budget: usize,
    hooks: &mut Hooks<'_>,
) -> PackReport
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let mut report = PackReport {
        tenant: tenant.to_owned(),
        pack_id: pack.id.clone(),
        attempted: 0,
        runs: Vec::new(),
        last_end: None,
        status: PackStatus::Done,
    };
    if budget == 0 {
        report.status = PackStatus::Deferred;
    } else {
        match due_windows(exec, tenant, pack, now, limits, hooks.due).await {
            Ok(windows) => {
                if windows.len() > budget {
                    report.status = PackStatus::Deferred;
                }
                for window in windows.iter().take(budget) {
                    if matches!(report.status, PackStatus::Done | PackStatus::Deferred) {
                        run_window(exec, &mut report, pack, window, now, &mut *hooks.run).await;
                    }
                }
            }
            Err(status) => report.status = status,
        }
    }
    report
}


/// One scheduler tick: every clickhouse pack in id order for every tenant. At most `max_runs_per_tick` runs; the rest is `deferred`.
pub async fn tick<Executor, Pending>(
    tenants: &[String],
    packs: &[HuntPack],
    now: i64,
    limits: &TickLimits,
    exec: &mut Executor,
    hooks: &mut Hooks<'_>,
) -> Result<TickReport, TickError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    check_limits(limits, tenants.len())?;
    let mut ordered: Vec<&HuntPack> = packs.iter().collect();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));
    let (valid, refused): (Vec<&String>, Vec<&String>) = tenants.iter().partition(|tenant| tenant_scope(tenant).is_ok());
    let refused_count = refused.len();
    if refused_count > 0 {
        warn!("hunt tick: {refused_count} tenants refused as invalid");
    }
    let mut report = TickReport {
        refused_tenants: refused_count,
        ..TickReport::default()
    };
    let mut budget = limits.max_runs_per_tick;
    for tenant in valid {
        for pack in &ordered {
            if pack.source == Source::Clickhouse {
                let entry = tick_pack(exec, tenant, pack, now, limits, budget, &mut *hooks).await;
                budget = budget.saturating_sub(entry.attempted);
                report.deferred += usize::from(entry.status == PackStatus::Deferred);
                report.packs.push(entry);
            } else {
                report.skipped_osquery += 1;
            }
        }
    }
    let (packs_seen, deferred, skipped) = (report.packs.len(), report.deferred, report.skipped_osquery);
    let runs: usize = report.packs.iter().map(|entry| entry.runs.len()).sum();
    info!("hunt tick: {packs_seen} packs, {runs} runs, {deferred} deferred, {skipped} osquery skipped");
    Ok(report)
}

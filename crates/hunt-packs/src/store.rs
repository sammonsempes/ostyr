use crate::packs::is_pack_id;
use crate::schedule::{checked_time, RunWindow, ScheduleError};
use crate::types::ListResult;
use core_pg::error::PgError;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_scope, TenantScope};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;


pub const MIGRATION_NAMESPACE: &str = "hunt_packs";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "hunt_packs_0001",
        sql: include_str!("../migrations/hunt_packs_0001.sql"),
    },
    Migration {
        version: "hunt_packs_0002",
        sql: include_str!("../migrations/hunt_packs_0002.sql"),
    },
];


/// Server and client deadline of every statement (`core_pg::query::scoped_query` sends `SET statement_timeout` first).
pub const STATEMENT_DEADLINE: Duration = Duration::from_secs(10);


/// Params: `$2` pack id. At most one row, the last completed run end.
pub const GET_SQL: &str = "SELECT last_done_end FROM hunt_pack_runs WHERE tenant = $1 AND pack_id = $2";


/// Params: `$2` pack id, `$3` run end. The stored end never moves back; the stored value is returned.
pub const SET_SQL: &str = "INSERT INTO hunt_pack_runs (tenant, pack_id, last_done_end, updated_at) VALUES ($1, $2, $3, now()) \
    ON CONFLICT (tenant, pack_id) DO UPDATE SET last_done_end = GREATEST(hunt_pack_runs.last_done_end, EXCLUDED.last_done_end), updated_at = now() \
    RETURNING last_done_end";


/// Params: `$2` pack id, `$3` window start, `$4` window end, `$5` matches, `$6` baseline. One row when inserted, none for a replayed window.
pub const FINDING_SQL: &str = "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) \
    VALUES ($1, $2, $3, $4, $5, $6, now()) ON CONFLICT (tenant, pack_id, window_end) DO NOTHING RETURNING window_end";


/// Params: `$2` cursor window end, `$3` cursor pack id, `$4` limit. Rows after the cursor in `(window_end, pack_id)` order, the limit applied here.
pub const LIST_SQL: &str = "SELECT pack_id, window_start, window_end, matches, max_matches FROM hunt_pack_findings \
    WHERE tenant = $1 AND (window_end, pack_id) > ($2, $3) ORDER BY window_end, pack_id LIMIT $4";


/// The largest page `list_findings` asks for, whatever the caller passes.
pub const MAX_FINDINGS_PAGE: i64 = 500;


/// A bound statement parameter; the tenant is `$1` and is added by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Int(i64),
}


#[derive(Debug, Error)]
pub enum StateError {
    #[error(transparent)]
    Pg(#[from] PgError),
    #[error("invalid pack id")]
    InvalidPackId,
    #[error("a run end is outside years 0 to 9999")]
    OutOfRange(#[source] ScheduleError),
    #[error("a match count does not fit the store")]
    CountOutOfRange,
    #[error("the store answered with an unexpected number of rows")]
    BadReply,
}


/// Validates the tenant and the pack id before any statement is built.
pub fn checked_key(tenant: &str, pack_id: &str) -> Result<TenantScope, StateError> {
    let scope = tenant_scope(tenant)?;
    is_pack_id(pack_id).then_some(scope).ok_or(StateError::InvalidPackId)
}


/// One stored end, or none; a value outside years 0 to 9999 is refused, never clamped.
pub fn single_end(rows: &[i64]) -> Result<Option<i64>, StateError> {
    match rows {
        [] => Ok(None),
        [end] => checked_time(*end).map(Some).map_err(StateError::OutOfRange),
        _ => Err(StateError::BadReply),
    }
}


/// The last completed run end of the pack for the tenant; `None` when there is no row.
pub async fn last_done<Executor, Pending>(exec: &mut Executor, tenant: &str, pack_id: &str) -> Result<Option<i64>, StateError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let scope = checked_key(tenant, pack_id)?;
    let rows = exec(&scope, GET_SQL, vec![Param::Text(pack_id.to_owned())]).await?;
    single_end(&rows)
}


/// Records a completed run end and returns the stored end, which is the newer of the old and the new one.
pub async fn record_done<Executor, Pending>(exec: &mut Executor, tenant: &str, pack_id: &str, end: i64) -> Result<i64, StateError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let scope = checked_key(tenant, pack_id)?;
    checked_time(end).map_err(StateError::OutOfRange)?;
    let rows = exec(&scope, SET_SQL, vec![Param::Text(pack_id.to_owned()), Param::Int(end)]).await?;
    single_end(&rows)?.ok_or(StateError::BadReply)
}


/// One stored finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub pack_id: String,
    pub window_start: i64,
    pub window_end: i64,
    pub matches: i64,
    pub max_matches: i64,
}


/// Rows after the cursor; a stored row with an invalid pack id is left out and counted in `skipped`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FindingPage {
    pub rows: Vec<FindingRow>,
    pub skipped: usize,
}


/// Records the finding of a window and tells whether a row was inserted (`false`: the window was already recorded).
pub async fn record_finding<Executor, Pending>(
    exec: &mut Executor,
    tenant: &str,
    pack_id: &str,
    window: &RunWindow,
    matches: u64,
    max_matches: u64,
) -> Result<bool, StateError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let scope = checked_key(tenant, pack_id)?;
    checked_time(window.start).map_err(StateError::OutOfRange)?;
    checked_time(window.end).map_err(StateError::OutOfRange)?;
    let matches_stored = i64::try_from(matches).map_err(|_| StateError::CountOutOfRange)?;
    let baseline_stored = i64::try_from(max_matches).map_err(|_| StateError::CountOutOfRange)?;
    let params = vec![
        Param::Text(pack_id.to_owned()),
        Param::Int(window.start),
        Param::Int(window.end),
        Param::Int(matches_stored),
        Param::Int(baseline_stored),
    ];
    let rows = exec(&scope, FINDING_SQL, params).await?;
    single_end(&rows).map(|inserted| inserted.is_some())
}


/// Findings of the tenant strictly after the cursor `(end, pack_id)`, in `(window_end, pack_id)` order; the limit is capped at `MAX_FINDINGS_PAGE`.
pub async fn list_findings<Executor, Pending>(
    exec: &mut Executor,
    tenant: &str,
    since_end: i64,
    since_pack: &str,
    limit: i64,
) -> Result<FindingPage, StateError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = ListResult>,
{
    let scope = tenant_scope(tenant)?;
    checked_time(since_end).map_err(StateError::OutOfRange)?;
    let capped = limit.clamp(1, MAX_FINDINGS_PAGE);
    let params = vec![Param::Int(since_end), Param::Text(since_pack.to_owned()), Param::Int(capped)];
    let rows = exec(&scope, LIST_SQL, params).await?;
    let (valid, refused): (Vec<FindingRow>, Vec<FindingRow>) = rows.into_iter().partition(|row| is_pack_id(&row.pack_id));
    Ok(FindingPage {
        rows: valid,
        skipped: refused.len(),
    })
}

use crate::packs::is_pack_id;
use crate::schedule::{checked_time, ScheduleError};
use core_pg::error::PgError;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_scope, TenantScope};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;


pub const MIGRATION_NAMESPACE: &str = "hunt_packs";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "hunt_packs_0001",
    sql: include_str!("../migrations/hunt_packs_0001.sql"),
}];


/// Server and client deadline of every statement (`core_pg::query::scoped_query` sends `SET statement_timeout` first).
pub const STATEMENT_DEADLINE: Duration = Duration::from_secs(10);


/// Params: `$2` pack id. At most one row, the last completed run end.
pub const GET_SQL: &str = "SELECT last_done_end FROM hunt_pack_runs WHERE tenant = $1 AND pack_id = $2";


/// Params: `$2` pack id, `$3` run end. The stored end never moves back; the stored value is returned.
pub const SET_SQL: &str = "INSERT INTO hunt_pack_runs (tenant, pack_id, last_done_end, updated_at) VALUES ($1, $2, $3, now()) \
    ON CONFLICT (tenant, pack_id) DO UPDATE SET last_done_end = GREATEST(hunt_pack_runs.last_done_end, EXCLUDED.last_done_end), updated_at = now() \
    RETURNING last_done_end";


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

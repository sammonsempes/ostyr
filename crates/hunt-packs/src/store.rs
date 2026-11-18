use crate::packs::{is_pack_id, MAX_ID_CHARS};
use crate::schedule::{checked_time, RunWindow, ScheduleError};
use crate::types::ListResult;
use core_pg::error::PgError;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_scope, TenantScope};
use std::future::Future;
use std::num::TryFromIntError;
use std::time::Duration;
use thiserror::Error;


pub const MIGRATION_NAMESPACE: &str = "hunt_packs";


pub const MIGRATIONS: [Migration; 5] = [
    Migration {
        version: "hunt_packs_0001",
        sql: include_str!("../migrations/hunt_packs_0001.sql"),
    },
    Migration {
        version: "hunt_packs_0002",
        sql: include_str!("../migrations/hunt_packs_0002.sql"),
    },
    Migration {
        version: "hunt_packs_0003",
        sql: include_str!("../migrations/hunt_packs_0003.sql"),
    },
    Migration {
        version: "hunt_packs_0004",
        sql: include_str!("../migrations/hunt_packs_0004.sql"),
    },
    Migration {
        version: "hunt_packs_0005",
        sql: include_str!("../migrations/hunt_packs_0005.sql"),
    },
];


/// Server and client deadline of every statement (`core_pg::query::scoped_query` sends `SET statement_timeout` first).
pub const STATEMENT_DEADLINE: Duration = Duration::from_secs(10);


/// Deadline of the migrations, which may build an index on a cold database.
pub const MIGRATION_DEADLINE: Duration = Duration::from_secs(120);


/// Params: `$2` pack id. At most one row, the last completed run end.
pub const GET_SQL: &str = "SELECT last_done_end FROM hunt_pack_runs WHERE tenant = $1 AND pack_id = $2";


/// Params: `$2` pack id, `$3` run end. The stored end never moves back; the stored value is returned.
pub const SET_SQL: &str = "INSERT INTO hunt_pack_runs (tenant, pack_id, last_done_end, updated_at) VALUES ($1, $2, $3, now()) \
    ON CONFLICT (tenant, pack_id) DO UPDATE SET last_done_end = GREATEST(hunt_pack_runs.last_done_end, EXCLUDED.last_done_end), updated_at = now() \
    RETURNING last_done_end";


/// Params: `$2` pack id, `$3` window start, `$4` window end, `$5` matches, `$6` baseline. One row when inserted, none for a replayed window.
pub const FINDING_SQL: &str = "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) \
    VALUES ($1, $2, $3, $4, $5, $6, now()) ON CONFLICT (tenant, pack_id, window_end) DO NOTHING RETURNING window_end";


/// The longest stored pack id in bytes (the `hunt_packs_0003` constraint); a longer stored id is never read, so a cursor always parses back.
pub const ID_BYTE_CAP: i64 = MAX_ID_CHARS as i64;


/// Most oversized rows counted for the report; one more is fetched to tell "more than".
pub const OVERSIZED_REPORT_CAP: i64 = 1000;


/// Params: `$2` cursor window end, `$3` cursor pack id, `$4` limit. Rows after the cursor in `(window_end, pack_id)` order; the literal 64 is the `hunt_packs_0005` partial index predicate.
pub const LIST_SQL: &str = "SELECT pack_id, window_start, window_end, matches, max_matches FROM hunt_pack_findings \
    WHERE tenant = $1 AND (window_end, pack_id) > ($2, $3) AND octet_length(pack_id) <= 64 ORDER BY window_end, pack_id LIMIT $4";


/// Params: `$2` count limit. One row: the tenant's rows with a pack id over 64 bytes (the literal of the `hunt_packs_0004` partial index).
pub const OVERSIZED_SQL: &str =
    "SELECT count(*) FROM (SELECT 1 FROM hunt_pack_findings WHERE tenant = $1 AND octet_length(pack_id) > 64 LIMIT $2::bigint) oversized";


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
    CountOutOfRange(#[source] TryFromIntError),
    #[error("the store answered with an unexpected number of rows")]
    BadReply,
}


/// A refusal no retry can fix (the value itself is wrong), as opposed to a store failure that may pass on the next tick.
pub fn is_permanent(error: &StateError) -> bool {
    matches!(error, StateError::CountOutOfRange(_) | StateError::InvalidPackId)
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


/// Rows after the cursor, bad pack ids counted in `skipped`; `next` is the last row READ (skipped included), set only on a full page.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FindingPage {
    pub rows: Vec<FindingRow>,
    pub skipped: usize,
    pub next: Option<(i64, String)>,
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
    let matches_stored = i64::try_from(matches).map_err(StateError::CountOutOfRange)?;
    let baseline_stored = i64::try_from(max_matches).map_err(StateError::CountOutOfRange)?;
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
    let cursor = (Param::Int(since_end), Param::Text(since_pack.to_owned()));
    let rows = exec(&scope, LIST_SQL, vec![cursor.0, cursor.1, Param::Int(capped)]).await?;
    let full = i64::try_from(rows.len()).is_ok_and(|read| read >= capped);
    let next = rows.last().filter(|_| full).map(|row| (row.window_end, row.pack_id.clone()));
    let (valid, refused): (Vec<FindingRow>, Vec<FindingRow>) = rows.into_iter().partition(|row| is_pack_id(&row.pack_id));
    Ok(FindingPage {
        rows: valid,
        skipped: refused.len(),
        next,
    })
}


/// How many of the tenant's stored rows have a pack id over `ID_BYTE_CAP` (never listed), counted up to `OVERSIZED_REPORT_CAP + 1`.
pub async fn count_oversized<Executor, Pending>(exec: &mut Executor, tenant: &str) -> Result<i64, StateError>
where
    Executor: FnMut(&TenantScope, &'static str, Vec<Param>) -> Pending,
    Pending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let scope = tenant_scope(tenant)?;
    let rows = exec(&scope, OVERSIZED_SQL, vec![Param::Int(OVERSIZED_REPORT_CAP + 1)]).await?;
    match rows.as_slice() {
        [count] => Ok(*count),
        _ => Err(StateError::BadReply),
    }
}


const HEX_RADIX: u32 = 16;


const HEX_DIGITS_PER_BYTE: usize = 2;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum CursorError {
    #[error("the cursor is not `<end>` or `<end>:<lowercase hex of the pack id>`")]
    Malformed,
}


/// `<end>:<lowercase hex of the pack id bytes>`: any stored id, control characters included, prints and parses back unchanged.
pub fn format_cursor(end: i64, pack_id: &str) -> String {
    let hex: String = pack_id.bytes().map(|byte| format!("{byte:02x}")).collect();
    format!("{end}:{hex}")
}


fn unhex(hex: &str) -> Option<Vec<u8>> {
    let lowercase = hex.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    let bounded = hex.len() <= MAX_ID_CHARS * HEX_DIGITS_PER_BYTE && hex.len().is_multiple_of(HEX_DIGITS_PER_BYTE);
    let valid = lowercase && bounded;
    valid.then_some(hex).and_then(|digits| {
        (0..digits.len())
            .step_by(HEX_DIGITS_PER_BYTE)
            .map(|start| hex_byte(digits, start))
            .collect()
    })
}


fn hex_byte(digits: &str, start: usize) -> Option<u8> {
    digits
        .get(start..start + HEX_DIGITS_PER_BYTE)
        .and_then(|pair| u8::from_str_radix(pair, HEX_RADIX).ok())
}


/// Reads `<end>` (the pack part empty) or the form `format_cursor` prints; anything else is refused.
pub fn parse_cursor(text: &str) -> Result<(i64, String), CursorError> {
    let (end, hex) = text.split_once(':').unwrap_or((text, ""));
    let end_value: i64 = end.parse().map_err(|_| CursorError::Malformed)?;
    let bytes = unhex(hex).ok_or(CursorError::Malformed)?;
    String::from_utf8(bytes).map(|pack| (end_value, pack)).map_err(|_| CursorError::Malformed)
}

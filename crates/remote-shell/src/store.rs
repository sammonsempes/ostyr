use crate::audit::escape_cut;
use crate::error::StoreError;
use crate::grammar::{valid_reference, valid_subject};
use crate::recording::{Header, Recording};
use crate::session::CloseReason;
use crate::store_model::{Cell, CloseRecord, Cursor, ListFilter, Param, SessionRow, Statement};
use crate::types::Row;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use std::future::Future;


pub const MIGRATION_NAMESPACE: &str = "remote_shell";


pub const MIGRATIONS: [Migration; 5] = [
    Migration {
        version: "rshell_0001",
        sql: include_str!("../migrations/rshell_0001.sql"),
    },
    Migration {
        version: "rshell_0002",
        sql: include_str!("../migrations/rshell_0002.sql"),
    },
    Migration {
        version: "rshell_0003",
        sql: include_str!("../migrations/rshell_0003.sql"),
    },
    Migration {
        version: "rshell_0004",
        sql: include_str!("../migrations/rshell_0004.sql"),
    },
    Migration {
        version: "rshell_0005",
        sql: include_str!("../migrations/rshell_0005.sql"),
    },
];


pub const MAX_PAGE: u32 = 200;


pub const HEADER_AND_TRAILER_FRAMES: u64 = 2;


pub const COL_SESSION: usize = 0;


pub const COL_REQUESTER: usize = 1;


pub const COL_ASSET: usize = 2;


pub const COL_TICKET: usize = 3;


pub const COL_OPENED_AT: usize = 4;


pub const COL_CLOSED_AT: usize = 5;


pub const COL_REASON: usize = 6;


pub const COL_FRAMES: usize = 7;


pub const COL_HASH: usize = 8;


pub const COL_BYTES: usize = 9;


pub const COL_STATE_CLOSED_AT: usize = 0;


pub const COL_STATE_OPENED_AT: usize = 1;


pub const COL_STATE_REQUESTER: usize = 2;


pub const COL_STATE_ASSET: usize = 3;


pub const COL_STATE_TICKET: usize = 4;


pub const NO_FILTER: &str = "";


/// Params: `$2` session id, `$3` requester, `$4` asset, `$5` ticket, `$6` opened_at; no row on a repeated session id of the tenant.
pub const OPEN_SQL: &str = "INSERT INTO remote_shell_sessions (tenant, session_id, requester, asset, ticket, opened_at) \
    VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant, session_id) DO NOTHING RETURNING session_id";


/// Params `$2` to `$7`: id, closed_at, reason, frames, hash, bytes; `$8` to `$11`: the header's requester, asset, ticket, opened_at.
pub const CLOSE_SQL: &str = "UPDATE remote_shell_sessions SET closed_at = $3, close_reason = $4, recording_frames = $5, recording_hash = $6, \
    recording_bytes = $7 WHERE tenant = $1 AND session_id = $2 AND closed_at IS NULL AND opened_at <= $3 \
    AND requester = $8 AND asset = $9 AND ticket = $10 AND opened_at = $11 RETURNING session_id";


/// Params: `$2` session id; read only after a refused close, to name the refusal.
pub const STATE_SQL: &str = "SELECT closed_at, opened_at, requester, asset, ticket FROM remote_shell_sessions WHERE tenant = $1 AND session_id = $2";


/// Params: `$2` asset or empty, `$3` requester or empty, `$4` open only, `$5` limit.
pub const LIST_SQL: &str = "SELECT session_id, requester, asset, ticket, opened_at, closed_at, close_reason, recording_frames, recording_hash, \
    recording_bytes FROM remote_shell_sessions WHERE tenant = $1 AND ($2 = '' OR asset = $2) AND ($3 = '' OR requester = $3) \
    AND (NOT $4 OR closed_at IS NULL) ORDER BY opened_at DESC, session_id DESC LIMIT $5";


/// Params: `$2` session id; one session of the tenant, in the columns of `LIST_SQL`.
pub const SESSION_SQL: &str = "SELECT session_id, requester, asset, ticket, opened_at, closed_at, close_reason, recording_frames, recording_hash, \
    recording_bytes FROM remote_shell_sessions WHERE tenant = $1 AND session_id = $2";


/// As `LIST_SQL` plus `$6` and `$7`, the opened_at and session id the page starts strictly after.
pub const LIST_AFTER_SQL: &str =
    "SELECT session_id, requester, asset, ticket, opened_at, closed_at, close_reason, recording_frames, recording_hash, \
    recording_bytes FROM remote_shell_sessions WHERE tenant = $1 AND ($2 = '' OR asset = $2) AND ($3 = '' OR requester = $3) \
    AND (NOT $4 OR closed_at IS NULL) AND (opened_at, session_id) < ($6, $7) ORDER BY opened_at DESC, session_id DESC LIMIT $5";


pub fn reason_token(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::IdleTimeout => "idle_timeout",
        CloseReason::MaxDuration => "max_duration",
        CloseReason::RecordingFailed => "recording_failed",
        CloseReason::ChannelDead => "channel_dead",
        CloseReason::UserClose => "user_close",
        CloseReason::ClockSkew => "clock_skew",
    }
}


pub fn check_reference(field: &'static str, text: &str) -> Result<(), StoreError> {
    if valid_reference(text) {
        Ok(())
    } else {
        Err(StoreError::Invalid { field })
    }
}


pub fn check_requester(text: &str) -> Result<(), StoreError> {
    if valid_subject(text) {
        Ok(())
    } else {
        Err(StoreError::Invalid { field: "requester" })
    }
}


/// A requester stored in the register never starts with `-`, so a later signer or command line never reads it as an option.
pub fn check_registered_requester(text: &str) -> Result<(), StoreError> {
    check_requester(text)?;
    if text.starts_with('-') {
        Err(StoreError::Invalid { field: "requester" })
    } else {
        Ok(())
    }
}


pub fn to_i64(field: &'static str, value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_overflow| StoreError::OutOfRange { field })
}


pub fn check_asset(text: &str) -> Result<(), StoreError> {
    check_reference("asset", text)
}


pub fn filter_text(value: Option<&String>, check: fn(&str) -> Result<(), StoreError>) -> Result<String, StoreError> {
    match value {
        Some(text) => check(text).map(|()| text.clone()),
        None => Ok(NO_FILTER.to_owned()),
    }
}


pub async fn run<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    exec(scope, Statement { sql, params }).await
}


/// A header of another tenant or session is refused, so a row never points at foreign evidence.
pub fn check_recording(scope: &TenantScope, session_id: &str, header: &Header) -> Result<(), StoreError> {
    if header.tenant != tenant_of(scope) {
        Err(StoreError::TenantMismatch)
    } else if header.session_id != session_id {
        Err(StoreError::RecordingMismatch {
            session_id: escape_cut(session_id),
        })
    } else {
        Ok(())
    }
}


/// The recording's identity for the close, with its whole header so the store compares it with the row.
pub fn close_of(
    scope: &TenantScope,
    session_id: &str,
    recording: &Recording,
    reason: CloseReason,
    byte_length: u64,
) -> Result<CloseRecord, StoreError> {
    check_recording(scope, session_id, &recording.header)?;
    let data_frames = recording.frames.len() as u64;
    Ok(CloseRecord {
        header: recording.header.clone(),
        reason,
        trailer: recording.trailer.clone(),
        final_hash: recording.final_hash,
        frames: data_frames.saturating_add(HEADER_AND_TRAILER_FRAMES),
        bytes: byte_length,
    })
}


/// Inserts the open row; a repeated session id of the tenant is `Duplicate`, never an overwrite.
pub async fn register_open<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, header: &Header) -> Result<(), StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    if header.tenant != tenant_of(scope) {
        Err(StoreError::TenantMismatch)
    } else {
        check_reference("session_id", &header.session_id)?;
        check_registered_requester(&header.requester)?;
        check_asset(&header.asset)?;
        check_reference("ticket", &header.ticket)?;
        let params = vec![
            Param::Text(header.session_id.clone()),
            Param::Text(header.requester.clone()),
            Param::Text(header.asset.clone()),
            Param::Text(header.ticket.clone()),
            Param::Int(header.opened_at),
        ];
        let rows = run(exec, scope, OPEN_SQL, params).await?;
        if rows.is_empty() {
            Err(StoreError::Duplicate {
                session_id: escape_cut(&header.session_id),
            })
        } else {
            Ok(())
        }
    }
}


pub fn state_refusal(row: &Row, header: &Header, session_id: &str) -> Result<StoreError, StoreError> {
    let escaped = escape_cut(session_id);
    let closed_at = optional_int(row, COL_STATE_CLOSED_AT, "closed_at")?;
    let opened_at = int_of(required(cell(row, COL_STATE_OPENED_AT, "opened_at")?, "opened_at")?, "opened_at")?;
    let requester = text_of(required(cell(row, COL_STATE_REQUESTER, "requester")?, "requester")?, "requester")?;
    let asset = text_of(required(cell(row, COL_STATE_ASSET, "asset")?, "asset")?, "asset")?;
    let ticket = text_of(required(cell(row, COL_STATE_TICKET, "ticket")?, "ticket")?, "ticket")?;
    let same_header = opened_at == header.opened_at && requester == header.requester && asset == header.asset && ticket == header.ticket;
    Ok(if !same_header {
        StoreError::RecordingMismatch { session_id: escaped }
    } else if closed_at.is_some() {
        StoreError::AlreadyClosed { session_id: escaped }
    } else {
        StoreError::CloseBeforeOpen { session_id: escaped }
    })
}


pub async fn refusal_of_close<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    session_id: &str,
    header: &Header,
) -> Result<StoreError, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let rows = run(exec, scope, STATE_SQL, vec![Param::Text(session_id.to_owned())]).await?;
    match rows.first() {
        None => Ok(StoreError::Unknown {
            session_id: escape_cut(session_id),
        }),
        Some(row) => state_refusal(row, header, session_id),
    }
}


/// Sets the close columns once, in one guarded statement; any other close is a typed refusal.
pub async fn register_close<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    session_id: &str,
    close: &CloseRecord,
) -> Result<(), StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    check_reference("session_id", session_id)?;
    check_recording(scope, session_id, &close.header)?;
    let params = vec![
        Param::Text(session_id.to_owned()),
        Param::Int(close.trailer.at),
        Param::Text(reason_token(close.reason).to_owned()),
        Param::Int(to_i64("frames", close.frames)?),
        Param::Bytes(close.final_hash.to_vec()),
        Param::Int(to_i64("bytes", close.bytes)?),
        Param::Text(close.header.requester.clone()),
        Param::Text(close.header.asset.clone()),
        Param::Text(close.header.ticket.clone()),
        Param::Int(close.header.opened_at),
    ];
    let rows = run(exec, scope, CLOSE_SQL, params).await?;
    if rows.is_empty() {
        Err(refusal_of_close(exec, scope, session_id, &close.header).await?)
    } else {
        Ok(())
    }
}


pub fn cell(row: &Row, index: usize, column: &'static str) -> Result<Option<Cell>, StoreError> {
    let found = row.get(index).ok_or(StoreError::BadRow { column })?;
    Ok((*found != Cell::Null).then(|| found.clone()))
}


pub fn int_of(found: Cell, column: &'static str) -> Result<i64, StoreError> {
    match found {
        Cell::Int(value) => Ok(value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn text_of(found: Cell, column: &'static str) -> Result<String, StoreError> {
    match found {
        Cell::Text(value) => Ok(value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn bytes_of(found: Cell, column: &'static str) -> Result<Vec<u8>, StoreError> {
    match found {
        Cell::Bytes(value) => Ok(value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn optional_int(row: &Row, index: usize, column: &'static str) -> Result<Option<i64>, StoreError> {
    cell(row, index, column)?.map(|found| int_of(found, column)).transpose()
}


pub fn required<Value>(found: Option<Value>, column: &'static str) -> Result<Value, StoreError> {
    found.ok_or(StoreError::BadRow { column })
}


pub fn decode_session(row: &Row) -> Result<SessionRow, StoreError> {
    Ok(SessionRow {
        session_id: text_of(required(cell(row, COL_SESSION, "session_id")?, "session_id")?, "session_id")?,
        requester: text_of(required(cell(row, COL_REQUESTER, "requester")?, "requester")?, "requester")?,
        asset: text_of(required(cell(row, COL_ASSET, "asset")?, "asset")?, "asset")?,
        ticket: text_of(required(cell(row, COL_TICKET, "ticket")?, "ticket")?, "ticket")?,
        opened_at: int_of(required(cell(row, COL_OPENED_AT, "opened_at")?, "opened_at")?, "opened_at")?,
        closed_at: optional_int(row, COL_CLOSED_AT, "closed_at")?,
        close_reason: cell(row, COL_REASON, "close_reason")?
            .map(|found| text_of(found, "close_reason"))
            .transpose()?,
        recording_frames: optional_int(row, COL_FRAMES, "recording_frames")?,
        recording_hash: cell(row, COL_HASH, "recording_hash")?
            .map(|found| bytes_of(found, "recording_hash"))
            .transpose()?,
        recording_bytes: optional_int(row, COL_BYTES, "recording_bytes")?,
    })
}


pub fn check_limit(limit: u32) -> Result<(), StoreError> {
    if limit == 0 || limit > MAX_PAGE {
        Err(StoreError::LimitOutOfRange { limit, max: MAX_PAGE })
    } else {
        Ok(())
    }
}


/// The list statement and its params (from `$2`); `rows` is the SQL `LIMIT`.
pub fn list_statement(filter: &ListFilter, after: Option<&Cursor>, rows: u32) -> Result<(&'static str, Vec<Param>), StoreError> {
    let mut params = vec![
        Param::Text(filter_text(filter.asset.as_ref(), check_asset)?),
        Param::Text(filter_text(filter.requester.as_ref(), check_requester)?),
        Param::Bool(filter.open_only),
        Param::Int(i64::from(rows)),
    ];
    let sql = match after {
        Some(cursor) => {
            check_reference("cursor", &cursor.session_id)?;
            params.push(Param::Int(cursor.opened_at));
            params.push(Param::Text(cursor.session_id.clone()));
            LIST_AFTER_SQL
        }
        None => LIST_SQL,
    };
    Ok((sql, params))
}

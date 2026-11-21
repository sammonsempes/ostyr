use crate::error::StoreError;
use crate::grammar::{valid_reference, valid_subject, MAX_REFERENCE_BYTES};
use crate::session::CloseReason;
use crate::store::{
    cell, check_limit, check_reference, decode_session, int_of, list_statement, reason_token, required, run, text_of, COL_OPENED_AT, COL_SESSION,
    HEADER_AND_TRAILER_FRAMES, SESSION_SQL,
};
use crate::store_model::{Cursor, ListFilter, Page, Param, SessionRow, Statement};
use crate::types::{Row, HASH_LEN};
use core_pg::scope::TenantScope;
use std::future::Future;
use time::OffsetDateTime;


pub const MAX_I64_CHARS: usize = 20;


pub const MAX_CURSOR_BYTES: usize = MAX_I64_CHARS + 1 + MAX_REFERENCE_BYTES;


pub const CURSOR_SEPARATOR: char = '.';


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9999;


pub const MIN_FRAMES: i64 = HEADER_AND_TRAILER_FRAMES as i64;


pub const CLOSE_REASONS: [CloseReason; 6] = [
    CloseReason::IdleTimeout,
    CloseReason::MaxDuration,
    CloseReason::RecordingFailed,
    CloseReason::ChannelDead,
    CloseReason::UserClose,
    CloseReason::ClockSkew,
];


pub fn refuse_unless(field: &'static str, holds: bool) -> Result<(), StoreError> {
    if holds {
        Ok(())
    } else {
        Err(StoreError::StoredValue { field })
    }
}


/// A time RFC 3339 can write: a UTC year 0 to 9999.
pub fn writable_time(seconds: i64) -> bool {
    OffsetDateTime::from_unix_timestamp(seconds).is_ok_and(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
}


/// The serving check: a decoded row is served only if it still holds the grammar and the table CHECKs, so a dropped constraint never reaches a reader.
pub fn check_served(row: &SessionRow) -> Result<(), StoreError> {
    refuse_unless("session_id", valid_reference(&row.session_id))?;
    refuse_unless("requester", valid_subject(&row.requester))?;
    refuse_unless("asset", valid_reference(&row.asset))?;
    refuse_unless("ticket", valid_reference(&row.ticket))?;
    let known_reason = row
        .close_reason
        .as_deref()
        .is_none_or(|token| CLOSE_REASONS.iter().any(|reason| reason_token(*reason) == token));
    refuse_unless("close_reason", known_reason)?;
    refuse_unless("close_reason", row.closed_at.is_some() == row.close_reason.is_some())?;
    refuse_unless("recording_hash", row.recording_frames.is_some() == row.recording_hash.is_some())?;
    refuse_unless("recording_bytes", row.recording_hash.is_some() == row.recording_bytes.is_some())?;
    refuse_unless("recording_hash", row.closed_at.is_some() || row.recording_hash.is_none())?;
    refuse_unless("recording_hash", row.recording_hash.as_ref().is_none_or(|hash| hash.len() == HASH_LEN))?;
    refuse_unless("recording_frames", row.recording_frames.is_none_or(|frames| frames >= MIN_FRAMES))?;
    refuse_unless("recording_bytes", row.recording_bytes.is_none_or(|bytes| bytes >= 0))?;
    refuse_unless("closed_at", row.closed_at.is_none_or(|closed| closed >= row.opened_at))?;
    refuse_unless("opened_at", writable_time(row.opened_at))?;
    refuse_unless("closed_at", row.closed_at.is_none_or(writable_time))
}


/// Decodes one row and serves it only if `check_served` holds.
pub fn serve_row(row: &Row) -> Result<SessionRow, StoreError> {
    let decoded = decode_session(row)?;
    check_served(&decoded).map(|()| decoded)
}


/// The cursor text of a key: `<opened_at>.<session id>`.
pub fn cursor_text(cursor: &Cursor) -> String {
    format!("{}{CURSOR_SEPARATOR}{}", cursor.opened_at, cursor.session_id)
}


pub fn refuse_cursor(holds: bool) -> Result<(), StoreError> {
    if holds {
        Ok(())
    } else {
        Err(StoreError::BadCursor)
    }
}


/// Length cap first, then the split, then the canonical `i64` and the reference grammar.
pub fn parse_cursor(text: &str) -> Result<Cursor, StoreError> {
    refuse_cursor(text.len() <= MAX_CURSOR_BYTES)?;
    let (at_text, session_id) = text.split_once(CURSOR_SEPARATOR).ok_or(StoreError::BadCursor)?;
    let opened_at: i64 = at_text.parse().map_err(|_malformed| StoreError::BadCursor)?;
    refuse_cursor(opened_at.to_string() == at_text)?;
    refuse_cursor(valid_reference(session_id))?;
    Ok(Cursor {
        opened_at,
        session_id: session_id.to_owned(),
    })
}


/// The cursor of a row read from the store, served or not; a key outside the grammar is `StoredValue`, never printed.
pub fn raw_cursor(row: &Row) -> Result<String, StoreError> {
    let session_id = text_of(required(cell(row, COL_SESSION, "session_id")?, "session_id")?, "session_id")?;
    let opened_at = int_of(required(cell(row, COL_OPENED_AT, "opened_at")?, "opened_at")?, "opened_at")?;
    refuse_unless("session_id", valid_reference(&session_id))?;
    Ok(cursor_text(&Cursor { opened_at, session_id }))
}


/// One session of the tenant: `None` when absent, `StoredValue` when present but unservable.
pub async fn get_session<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, session_id: &str) -> Result<Option<SessionRow>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    check_reference("session_id", session_id)?;
    let rows = run(exec, scope, SESSION_SQL, vec![Param::Text(session_id.to_owned())]).await?;
    rows.first().map(serve_row).transpose()
}


/// A page of 1 to `MAX_PAGE` rows: `limit + 1` are read, the first `limit` are served or counted in `skipped`, and the cursor is the raw key of the last of them.
pub async fn list_page<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    filter: &ListFilter,
    after: Option<&str>,
    limit: u32,
) -> Result<Page, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    check_limit(limit)?;
    let cursor = after.map(parse_cursor).transpose()?;
    let (sql, params) = list_statement(filter, cursor.as_ref(), limit + 1)?;
    let fetched = run(exec, scope, sql, params).await?;
    let wanted = limit as usize;
    let shown: Vec<&Row> = fetched.iter().take(wanted).collect();
    let next_cursor = if fetched.len() > wanted {
        shown.last().map(|row| raw_cursor(row)).transpose()?
    } else {
        None
    };
    let served: Vec<Result<SessionRow, StoreError>> = shown.iter().map(|row| serve_row(row)).collect();
    let skipped = served.iter().filter(|outcome| outcome.is_err()).count();
    Ok(Page {
        rows: served.into_iter().flatten().collect(),
        skipped,
        next_cursor,
    })
}

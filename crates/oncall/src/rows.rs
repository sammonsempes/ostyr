use crate::alert::{Alert, Cell, LifecycleState, Phase};
use crate::error::StoreError;
use crate::types::Row;
use chrono::{DateTime, Utc};


pub const COL_ID: usize = 0;


pub const COL_FINGERPRINT: usize = 1;


pub const COL_STATE: usize = 2;


pub const COL_LEVEL: usize = 3;


pub const COL_OCCURRENCES: usize = 4;


pub const COL_VERSION: usize = 5;


pub const COL_OPENED_AT: usize = 6;


pub const COL_ACKNOWLEDGED_AT: usize = 7;


pub const COL_RESOLVED_AT: usize = 8;


pub const COL_CREATED: usize = 9;


pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Open => "open",
        Phase::Acknowledged => "acknowledged",
        Phase::Escalated => "escalated",
        Phase::Resolved => "resolved",
    }
}


pub fn parse_phase(text: &str) -> Option<Phase> {
    [Phase::Open, Phase::Acknowledged, Phase::Escalated, Phase::Resolved]
        .into_iter()
        .find(|phase| phase_name(*phase) == text)
}


pub fn cell<'row>(row: &'row Row, index: usize, column: &'static str) -> Result<&'row Cell, StoreError> {
    row.get(index).ok_or(StoreError::BadRow { column })
}


pub fn cell_int(row: &Row, index: usize, column: &'static str) -> Result<i64, StoreError> {
    match cell(row, index, column)? {
        Cell::Int(value) => Ok(*value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn cell_text<'row>(row: &'row Row, index: usize, column: &'static str) -> Result<&'row str, StoreError> {
    match cell(row, index, column)? {
        Cell::Text(value) => Ok(value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn cell_time(row: &Row, index: usize, column: &'static str) -> Result<Option<DateTime<Utc>>, StoreError> {
    match cell(row, index, column)? {
        Cell::Time(value) => Ok(*value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn cell_bool(row: &Row, index: usize, column: &'static str) -> Result<bool, StoreError> {
    match cell(row, index, column)? {
        Cell::Bool(value) => Ok(*value),
        _ => Err(StoreError::BadRow { column }),
    }
}


/// Columns: id, fingerprint, state, level, occurrences, version, opened_at, acknowledged_at, resolved_at.
pub fn decode_alert(row: &Row) -> Result<Alert, StoreError> {
    let phase = parse_phase(cell_text(row, COL_STATE, "state")?).ok_or(StoreError::BadRow { column: "state" })?;
    let level = u32::try_from(cell_int(row, COL_LEVEL, "level")?).map_err(|_overflow| StoreError::BadRow { column: "level" })?;
    Ok(Alert {
        id: cell_int(row, COL_ID, "id")?,
        fingerprint: cell_text(row, COL_FINGERPRINT, "fingerprint")?.to_owned(),
        state: LifecycleState { phase, level },
        occurrences: cell_int(row, COL_OCCURRENCES, "occurrences")?,
        version: cell_int(row, COL_VERSION, "version")?,
        opened_at: cell_time(row, COL_OPENED_AT, "opened_at")?.ok_or(StoreError::BadRow { column: "opened_at" })?,
        acknowledged_at: cell_time(row, COL_ACKNOWLEDGED_AT, "acknowledged_at")?,
        resolved_at: cell_time(row, COL_RESOLVED_AT, "resolved_at")?,
    })
}

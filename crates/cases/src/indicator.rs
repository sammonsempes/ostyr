//! GRC indicator `incident.mean_hours_to_close`, computed from the cases of one tenant in one statement.

use crate::error::IndicatorError;
use alerts::types::{Executor, Row};
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const INCIDENT_INDICATOR: &str = "incident.mean_hours_to_close";


pub const WINDOW_DAYS: i64 = 90;


const SECONDS_PER_DAY: i64 = 86_400;


/// The window in seconds; a case worth the worst value counts at least this many.
pub const WINDOW_SECONDS: i64 = WINDOW_DAYS * SECONDS_PER_DAY;


const MAX_YEAR: i32 = 9_999;


const MIN_VALUE: f64 = 0.0;


/// The largest gap between the caller's clock and the database clock, in seconds.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


/// Params: `$2` now and `$3` window, both unix seconds as text; answers value, open, closed, bad, excluded, any case, database seconds (all text).
pub const INDICATOR_SQL: &str = include_str!("../migrations/indicator.sql");


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndicatorCounts {
    pub open: u64,
    pub closed: u64,
    pub bad: u64,
    pub excluded: u64,
    pub any_case: bool,
}


#[derive(Debug, Clone, PartialEq)]
pub struct IndicatorRow {
    pub tenant: String,
    pub name: String,
    pub value: f64,
    pub observed_at: OffsetDateTime,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq)]
pub struct IndicatorOutcome {
    pub row: Option<IndicatorRow>,
    pub counts: IndicatorCounts,
}


pub fn parse_count(text: &str) -> Result<u64, IndicatorError> {
    text.parse::<u64>().map_err(|_error| IndicatorError::BadRow)
}


pub fn parse_flag(text: &str) -> Result<bool, IndicatorError> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(IndicatorError::BadRow),
    }
}


pub fn check_clock(now: i64, database_seconds: &str) -> Result<(), IndicatorError> {
    let database = database_seconds.parse::<i64>().map_err(|_error| IndicatorError::BadRow)?;
    (now.abs_diff(database) <= MAX_CLOCK_SKEW_SECONDS)
        .then_some(())
        .ok_or(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
}


pub fn value_of(text: &str) -> Result<f64, IndicatorError> {
    let value = text.parse::<f64>().map_err(|_error| IndicatorError::BadRow)?;
    (value.is_finite() && value >= MIN_VALUE)
        .then_some(value + MIN_VALUE)
        .ok_or(IndicatorError::ValueOutOfRange)
}


/// The time as an RFC 3339 date-time; a year the format cannot write is refused.
pub fn observed_at_of(now: i64) -> Result<OffsetDateTime, IndicatorError> {
    let observed = OffsetDateTime::from_unix_timestamp(now).map_err(|_error| IndicatorError::TimeOutOfRange)?;
    (0..=MAX_YEAR)
        .contains(&observed.year())
        .then_some(observed)
        .ok_or(IndicatorError::TimeOutOfRange)
}


pub fn counts_text(counts: &IndicatorCounts) -> String {
    format!(
        "open={};closed={};bad={};excluded={}",
        counts.open, counts.closed, counts.bad, counts.excluded
    )
}


pub fn source_text(now: i64, counts: &IndicatorCounts) -> String {
    format!("cases:computed={now};{};window_days={WINDOW_DAYS}", counts_text(counts))
}


/// The counts line written when no value is emitted: integers only, naming which case applies.
pub fn warning_line(counts: &IndicatorCounts) -> String {
    let reason = if counts.any_case {
        "no incident case in the window"
    } else {
        "no case at all"
    };
    format!("no incident indicator emitted ({reason}): {}", counts_text(counts))
}


/// One answer row; an empty value is `row: None` with the counts.
pub fn decode_row(scope: &TenantScope, now: i64, row: &Row) -> Result<IndicatorOutcome, IndicatorError> {
    match row.as_slice() {
        [value, open, closed, bad, excluded, any_case, database_seconds] => {
            check_clock(now, database_seconds)?;
            let counts = IndicatorCounts {
                open: parse_count(open)?,
                closed: parse_count(closed)?,
                bad: parse_count(bad)?,
                excluded: parse_count(excluded)?,
                any_case: parse_flag(any_case)?,
            };
            let indicator = if value.is_empty() {
                None
            } else {
                Some(IndicatorRow {
                    tenant: tenant_of(scope).to_owned(),
                    name: INCIDENT_INDICATOR.to_owned(),
                    value: value_of(value)?,
                    observed_at: observed_at_of(now)?,
                    source: source_text(now, &counts),
                })
            };
            Ok(IndicatorOutcome { row: indicator, counts })
        }
        _ => Err(IndicatorError::BadRow),
    }
}


pub fn indicator_json(rows: &[IndicatorRow]) -> Result<String, IndicatorError> {
    let items = rows
        .iter()
        .map(|row| {
            row.observed_at
                .format(&Rfc3339)
                .map(|observed| json!({ "tenant": row.tenant, "name": row.name, "value": row.value, "observed_at": observed, "source": row.source }))
                .map_err(|_error| IndicatorError::TimeOutOfRange)
        })
        .collect::<Result<Vec<Value>, IndicatorError>>()?;
    Ok(Value::Array(items).to_string())
}


/// Computes the figure for the scope's tenant; `now` is unix seconds and must lie within `MAX_CLOCK_SKEW_SECONDS` of the database clock.
pub async fn incident_indicator(exec: Executor<'_, '_>, scope: &TenantScope, now: i64) -> Result<IndicatorOutcome, IndicatorError> {
    observed_at_of(now)?;
    let params = vec![now.to_string(), WINDOW_SECONDS.to_string()];
    let rows = exec(scope.clone(), INDICATOR_SQL, params).await.map_err(IndicatorError::Store)?;
    match rows.as_slice() {
        [row] => decode_row(scope, now, row),
        _ => Err(IndicatorError::BadRow),
    }
}

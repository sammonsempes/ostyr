//! GRC indicator `vuln.kev_mean_days_to_fix`, computed from the findings store of one tenant.

use crate::error::IndicatorError;
use crate::model::{IndicatorCounts, IndicatorOutcome, IndicatorRow};
use alerts::types::{Executor, Row};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const KEV_INDICATOR: &str = "vuln.kev_mean_days_to_fix";


/// Days a resolved finding stays in the figure after its resolution; the SQL carries the same span in microseconds.
pub const WINDOW_DAYS: u64 = 90;


/// The largest gap between the caller's clock and the database clock, in seconds.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


pub const ANSWER_COLUMNS: usize = 9;


const MICROS_PER_SECOND: u64 = 1_000_000;


const NANOS_PER_MICRO: i128 = 1_000;


const MAX_YEAR: i32 = 9_999;


const MIN_VALUE: f64 = 0.0;


/// `$1` tenant, `$2` now: the pinned function `vuln_kev_indicator`, one answer row of text columns; the rule is in the crate notes.
pub const INDICATOR_SQL: &str =
    "SELECT figure, n_open::text, n_resolved::text, n_cleared::text, n_bad::text, n_over_30::text, oldest_open_days::text, \
                                 observed_micros, database_seconds FROM vuln_kev_indicator($1, $2::text::bigint)";


pub fn parse_count(text: &str) -> Result<u64, IndicatorError> {
    text.parse::<u64>().map_err(|_error| IndicatorError::BadRow)
}


pub fn counts_text(counts: &IndicatorCounts) -> String {
    format!(
        "kev_open={};kev_resolved={};kev_cleared={};bad_time_rows={};open_over_30={};oldest_open_days={};window_days={}",
        counts.kev_open, counts.kev_resolved, counts.kev_cleared, counts.bad_time_rows, counts.open_over_30, counts.oldest_open_days, WINDOW_DAYS
    )
}


pub fn source_text(now_micros: u64, counts: &IndicatorCounts) -> String {
    format!("vuln:computed={};{}", now_micros / MICROS_PER_SECOND, counts_text(counts))
}


/// The counts line written when no value is emitted: integers only.
pub fn warning_line(counts: &IndicatorCounts) -> String {
    format!("no vulnerability indicator emitted: {}", counts_text(counts))
}


pub fn observed_at_of(oldest: &str) -> Result<OffsetDateTime, IndicatorError> {
    let micros = oldest.parse::<i64>().map_err(|_error| IndicatorError::BadRow)?;
    let observed =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * NANOS_PER_MICRO).map_err(|_error| IndicatorError::TimeOutOfRange)?;
    (0..=MAX_YEAR)
        .contains(&observed.year())
        .then_some(observed)
        .ok_or(IndicatorError::TimeOutOfRange)
}


pub fn check_clock(now_micros: u64, database_seconds: &str) -> Result<(), IndicatorError> {
    let database = database_seconds.parse::<u64>().map_err(|_error| IndicatorError::BadRow)?;
    let skew = (now_micros / MICROS_PER_SECOND).abs_diff(database);
    (skew <= MAX_CLOCK_SKEW_SECONDS)
        .then_some(())
        .ok_or(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
}


pub fn value_of(text: &str) -> Result<f64, IndicatorError> {
    let value = text.parse::<f64>().map_err(|_error| IndicatorError::BadRow)?;
    (value.is_finite() && value >= MIN_VALUE)
        .then_some(value)
        .ok_or(IndicatorError::ValueOutOfRange)
}


/// One answer row: no non-bad row of the tenant (an empty observation time) is `row: None` with the counts.
pub fn decode_row(scope: &TenantScope, now_micros: u64, row: &Row) -> Result<IndicatorOutcome, IndicatorError> {
    match row.as_slice() {
        [figure, open, resolved, cleared, bad, over_30, oldest_days, observed, database_seconds] => {
            check_clock(now_micros, database_seconds)?;
            let counts = IndicatorCounts {
                kev_open: parse_count(open)?,
                kev_resolved: parse_count(resolved)?,
                kev_cleared: parse_count(cleared)?,
                bad_time_rows: parse_count(bad)?,
                open_over_30: parse_count(over_30)?,
                oldest_open_days: parse_count(oldest_days)?,
            };
            let indicator = if observed.is_empty() {
                None
            } else {
                Some(IndicatorRow {
                    tenant: tenant_of(scope).to_owned(),
                    name: KEV_INDICATOR.to_owned(),
                    value: value_of(figure)?,
                    observed_at: observed_at_of(observed)?,
                    source: source_text(now_micros, &counts),
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


/// Computes the figure for the scope's tenant from `vuln_findings` in one statement.
pub async fn kev_indicator(exec: Executor<'_, '_>, scope: &TenantScope, now_micros: u64) -> Result<IndicatorOutcome, IndicatorError> {
    let now = i64::try_from(now_micros).map_err(|_error| IndicatorError::TimeOutOfRange)?;
    let rows = exec(scope.clone(), INDICATOR_SQL, vec![now.to_string()])
        .await
        .map_err(IndicatorError::Store)?;
    match rows.as_slice() {
        [row] => decode_row(scope, now_micros, row),
        _ => Err(IndicatorError::BadRow),
    }
}


/// A fixed category of a store failure, never server text: `deadline`, `server <class>` or `connection`.
pub fn store_category(error: &PgError) -> String {
    match error {
        PgError::StatementTimeout { .. } | PgError::ClientDeadline { .. } | PgError::ConnectTimeout { .. } | PgError::MigrationTimeout { .. } => {
            "deadline".to_owned()
        }
        PgError::Server { class, .. } => format!("server {class}"),
        _ => "connection".to_owned(),
    }
}


/// The line an operator reads: a store failure carries its fixed category, every other error its own message.
pub fn failure_text(error: &IndicatorError) -> String {
    match error {
        IndicatorError::Store(cause) => format!("{error}: {}", store_category(cause)),
        other => other.to_string(),
    }
}

//! GRC indicator `hardening.mean_score_ratio`, computed from the drift state of one tenant.

use crate::error::IndicatorError;
use crate::model::{Baseline, IndicatorCounts, IndicatorOutcome, IndicatorRow};
use alerts::types::{Executor, Row};
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const HARDENING_INDICATOR: &str = "hardening.mean_score_ratio";


/// Baselines of one computation; the pairs go to the statement as one jsonb parameter.
pub const MAX_BASELINES: usize = 8;


const MICROS_PER_SECOND: u64 = 1_000_000;


const NANOS_PER_MICRO: i128 = 1_000;


const MICROS_PER_HOUR: i64 = 3_600_000_000;


const STALE_AFTER_HOURS: i64 = 48;


const MAX_YEAR: i32 = 9_999;


const MIN_VALUE: f64 = 0.0;


const MAX_VALUE: f64 = 1.0;


/// The largest gap between the caller's clock and the database clock, in seconds.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


/// The GRC `max_age_hours` of the built-in controls; a row not seen within this span is stale.
pub const STALE_AFTER_MICROS: i64 = STALE_AFTER_HOURS * MICROS_PER_HOUR;


/// Params: `$2` JSON array of `{baseline, control}`, `$3` now, `$4` stale-after span; one answer row of text columns; the scoring rule is in the crate notes.
pub const INDICATOR_SQL: &str = "WITH pairs AS (\
SELECT p.baseline, p.control FROM jsonb_to_recordset($2::text::jsonb) AS p(baseline text, control text)\
), expected AS (\
SELECT baseline, count(*) AS wanted FROM pairs GROUP BY baseline\
), tenant_rows AS (\
SELECT s.asset, s.baseline, s.verdict, s.last_seen_micros, \
(s.baseline, s.control) IN (SELECT baseline, control FROM pairs) AS listed \
FROM compliance_state s WHERE s.tenant = $1\
), classified AS (\
SELECT asset, baseline, verdict, last_seen_micros, \
CASE WHEN last_seen_micros > $3::text::bigint THEN 'future' \
WHEN last_seen_micros < $3::text::bigint - $4::text::bigint THEN 'stale' ELSE 'fresh' END AS age \
FROM tenant_rows WHERE listed\
), per_baseline AS (\
SELECT c.asset, c.baseline, e.wanted - count(*) AS missing, \
count(*) FILTER (WHERE c.age = 'fresh' AND c.verdict = 'pass') AS passed, \
count(*) FILTER (WHERE c.age <> 'fresh' OR c.verdict IN ('fail', 'error')) AS failed \
FROM classified c JOIN expected e ON e.baseline = c.baseline GROUP BY c.asset, c.baseline, e.wanted\
), per_asset AS (\
SELECT asset, sum(passed) AS passed, sum(failed) + sum(missing) + sum(passed) AS denominator FROM per_baseline GROUP BY asset\
) SELECT \
COALESCE((SELECT avg(passed::numeric / NULLIF(denominator, 0))::text FROM per_asset WHERE denominator > 0), ''), \
(SELECT count(*) FROM per_asset WHERE denominator > 0)::text, \
(SELECT count(*) FROM per_asset WHERE denominator = 0)::text, \
(SELECT count(*) FROM classified WHERE age = 'fresh' AND verdict = 'excepted')::text, \
(SELECT count(*) FROM classified WHERE age = 'fresh' AND verdict = 'error')::text, \
(SELECT count(*) FROM classified WHERE age = 'stale')::text, \
(SELECT count(*) FROM classified WHERE age = 'future')::text, \
(SELECT COALESCE(sum(missing), 0) FROM per_baseline)::text, \
(SELECT count(*) FROM tenant_rows WHERE NOT listed)::text, \
(SELECT count(*) FROM tenant_rows)::text, \
COALESCE((SELECT min(last_seen_micros) FROM classified WHERE age = 'fresh')::text, ''), \
extract(epoch from statement_timestamp())::bigint::text";


pub fn check_baselines(scope: &TenantScope, baselines: &[Baseline]) -> Result<(), IndicatorError> {
    let names: BTreeSet<&str> = baselines.iter().map(|baseline| baseline.name.as_str()).collect();
    if baselines.len() > MAX_BASELINES {
        Err(IndicatorError::TooManyBaselines { max: MAX_BASELINES })
    } else if baselines.iter().any(|baseline| baseline.tenant != tenant_of(scope)) {
        Err(IndicatorError::TenantMismatch)
    } else if names.len() != baselines.len() {
        Err(IndicatorError::DuplicateBaseline)
    } else {
        Ok(())
    }
}


/// The distinct `(baseline, control)` pairs, sorted, as the JSON array of the statement.
pub fn pairs_json(baselines: &[Baseline]) -> String {
    let pairs: BTreeSet<(&str, &str)> = baselines
        .iter()
        .flat_map(|baseline| baseline.controls.iter().map(|control| (baseline.name.as_str(), control.id.as_str())))
        .collect();
    let items: Vec<Value> = pairs
        .iter()
        .map(|(baseline, control)| json!({ "baseline": baseline, "control": control }))
        .collect();
    Value::Array(items).to_string()
}


pub fn parse_count(text: &str) -> Result<u64, IndicatorError> {
    text.parse::<u64>().map_err(|_error| IndicatorError::BadRow)
}


pub fn counts_text(counts: &IndicatorCounts) -> String {
    format!(
        "assets={};exc_assets={};exc_rows={};err_rows={};stale_rows={};future_rows={};missing={};unlisted={};rows={}",
        counts.assets,
        counts.excepted_only,
        counts.excepted_rows,
        counts.error_rows,
        counts.stale_rows,
        counts.future_rows,
        counts.missing,
        counts.unlisted_rows,
        counts.rows
    )
}


pub fn source_text(now_micros: u64, counts: &IndicatorCounts) -> String {
    format!("compliance:computed={};{}", now_micros / MICROS_PER_SECOND, counts_text(counts))
}


/// The counts line written when no value is emitted: integers only.
pub fn warning_line(counts: &IndicatorCounts) -> String {
    format!("no hardening indicator emitted: {}", counts_text(counts))
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
    (value.is_finite() && (MIN_VALUE..=MAX_VALUE).contains(&value))
        .then_some(value + MIN_VALUE)
        .ok_or(IndicatorError::ValueOutOfRange)
}


/// One answer row: no figure (an empty value or no fresh row) is `row: None` with the counts.
pub fn decode_row(scope: &TenantScope, now_micros: u64, row: &Row) -> Result<IndicatorOutcome, IndicatorError> {
    match row.as_slice() {
        [value, assets, excepted_only, excepted_rows, error_rows, stale_rows, future_rows, missing, unlisted_rows, rows, oldest, database_seconds] => {
            check_clock(now_micros, database_seconds)?;
            let counts = IndicatorCounts {
                assets: parse_count(assets)?,
                excepted_only: parse_count(excepted_only)?,
                excepted_rows: parse_count(excepted_rows)?,
                error_rows: parse_count(error_rows)?,
                stale_rows: parse_count(stale_rows)?,
                future_rows: parse_count(future_rows)?,
                missing: parse_count(missing)?,
                unlisted_rows: parse_count(unlisted_rows)?,
                rows: parse_count(rows)?,
            };
            let indicator = if value.is_empty() || oldest.is_empty() {
                None
            } else {
                Some(IndicatorRow {
                    tenant: tenant_of(scope).to_owned(),
                    name: HARDENING_INDICATOR.to_owned(),
                    value: value_of(value)?,
                    observed_at: observed_at_of(oldest)?,
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


/// Computes the figure for the scope's tenant from `compliance_state` in one statement; the baselines must belong to that tenant.
pub async fn hardening_indicator(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    baselines: &[Baseline],
    now_micros: u64,
) -> Result<IndicatorOutcome, IndicatorError> {
    check_baselines(scope, baselines)?;
    let now = i64::try_from(now_micros).map_err(|_error| IndicatorError::TimeOutOfRange)?;
    let params = vec![pairs_json(baselines), now.to_string(), STALE_AFTER_MICROS.to_string()];
    let rows = exec(scope.clone(), INDICATOR_SQL, params).await.map_err(IndicatorError::Store)?;
    match rows.as_slice() {
        [row] => decode_row(scope, now_micros, row),
        _ => Err(IndicatorError::BadRow),
    }
}

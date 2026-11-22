//! The GRC indicator `backup.days_since_restore_test` (Unix only, like the store it reads).

use crate::error::RestoreStoreError;
use crate::model::Declarations;
use crate::store::{micros_of, test_key, TestKey, MAX_CLOCK_SKEW_SECONDS};
use crate::text::rfc3339_text;
use crate::types::{Executor, Row};
use core_pg::scope::tenant_of;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use time::OffsetDateTime;


pub const INDICATOR_NAME: &str = "backup.days_since_restore_test";


/// The value of a test that proves nothing (never run, replaced repository, failing now, future time) and the ceiling of every age.
pub const WORST_DAYS: i64 = 3650;


/// `WORST_DAYS` in microseconds, the literal the query carries.
pub const WORST_MICROS: i64 = 315_360_000_000_000;


pub const MICROS_PER_DAY: i64 = 86_400_000_000;


const NANOS_PER_MICRO: i128 = 1000;


/// Params: `$2` JSON array of declared tests, `$3` caller's now in microseconds, `$4` largest accepted skew in seconds.
pub const AGE_SQL: &str = "WITH params AS (\
SELECT $3::text::bigint AS now_micros, least(greatest($4::text::bigint, 0), 300) * 1000000 AS skew_micros, \
(extract(epoch from clock_timestamp()) * 1000000)::bigint AS db_micros\
), joined AS (\
SELECT t.tenant IS NULL AS no_row, t.restored_config_id IS NULL AS never, t.outcome, t.config_id, t.restored_config_id, t.tested_micros, \
t.snapshot_micros, t.restored_snapshot_micros, t.restored_tested_micros \
FROM jsonb_to_recordset($2::text::jsonb) AS w(repository text, host text, path text) \
LEFT JOIN backup_restore_tests t ON t.tenant = $1 AND t.repository = w.repository AND t.host = w.host AND t.path = w.path\
), judged AS (\
SELECT j.no_row, j.never, j.tested_micros, \
coalesce(greatest(j.tested_micros, j.snapshot_micros, j.restored_snapshot_micros, j.restored_tested_micros) > p.now_micros + p.skew_micros, false) AS future, \
coalesce(j.restored_config_id <> j.config_id, false) AS changed, \
coalesce(j.outcome IN ('digest_mismatch', 'not_covered', 'no_snapshot', 'run_error', 'listing_gap'), false) AS failing, \
coalesce(j.outcome IN ('timeout', 'failed', 'too_large'), false) AS failed_latest, \
least(greatest(p.now_micros - least(j.restored_snapshot_micros, j.restored_tested_micros), 0), 315360000000000) AS age \
FROM joined j CROSS JOIN params p\
), summary AS (\
SELECT count(*) AS tests, count(*) FILTER (WHERE NOT never) AS restored, count(*) FILTER (WHERE never) AS never_count, \
count(*) FILTER (WHERE future) AS future_count, count(*) FILTER (WHERE failed_latest) AS failed_count, count(*) FILTER (WHERE changed) AS changed_count, count(*) FILTER (WHERE failing) AS failing_count, \
max(CASE WHEN never OR future OR changed OR failing THEN 315360000000000 ELSE age END) AS age_micros, \
min(tested_micros) AS oldest_micros, count(*) FILTER (WHERE no_row) AS missing FROM judged\
) \
SELECT (abs(p.now_micros - p.db_micros) <= p.skew_micros)::text, s.tests::text, s.restored::text, s.never_count::text, s.future_count::text, \
s.failed_count::text, s.changed_count::text, coalesce(s.age_micros, 0)::text, coalesce(s.oldest_micros, 0)::text, s.missing::text, \
s.failing_count::text, p.db_micros::text \
FROM summary s CROSS JOIN params p";


/// The tests the figure covers: every declared restore test, and the critical hosts no declared test names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Population {
    pub tests: Vec<TestKey>,
    pub untested: u64,
}


/// What the query counted over the population's tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    pub tests: u64,
    pub restored: u64,
    pub never: u64,
    pub future: u64,
    pub failed_latest: u64,
    pub config_changed: u64,
    pub age_micros: i64,
    pub oldest_micros: i64,
    pub missing: u64,
    pub failing: u64,
    pub db_micros: i64,
}


#[derive(Debug, Clone, PartialEq)]
pub struct IndicatorRow {
    pub tenant: String,
    pub name: &'static str,
    pub value: f64,
    pub observed_at: String,
    pub source: String,
}


/// Every declared restore test, and every critical host that is the host of none (a PBS key such as `vm/100` is never the host of a restic test).
pub fn population(declarations: &Declarations) -> Population {
    let tests: Vec<TestKey> = declarations
        .repositories
        .iter()
        .filter_map(|repository| repository.restore_test.as_ref().map(|test| test_key(&repository.repository, test)))
        .collect();
    let tested: BTreeSet<&str> = tests.iter().map(|key| key.host.as_str()).collect();
    let untested = declarations
        .critical
        .iter()
        .filter(|critical| !tested.contains(critical.host.as_str()))
        .count() as u64;
    Population { tests, untested }
}


pub fn tests_json(tests: &[TestKey]) -> String {
    Value::Array(
        tests
            .iter()
            .map(|key| json!({ "repository": key.repository, "host": key.host, "path": key.path }))
            .collect(),
    )
    .to_string()
}


pub fn count_cell(cell: &str) -> Result<u64, RestoreStoreError> {
    cell.parse::<u64>().map_err(|_error| RestoreStoreError::BadRow)
}


pub fn micros_cell(cell: &str) -> Result<i64, RestoreStoreError> {
    cell.parse::<i64>().map_err(|_error| RestoreStoreError::BadRow)
}


/// The one answer row: `false` in the first cell is a clock refusal.
pub fn decode_counts(rows: &[Row]) -> Result<Counts, RestoreStoreError> {
    let cells = match rows {
        [only] => match only.as_slice() {
            [clock, tests, restored, never, future, failed, changed, age, oldest, missing, failing, db] => {
                Ok((clock, tests, restored, never, future, failed, changed, age, oldest, missing, failing, db))
            }
            _ => Err(RestoreStoreError::BadRow),
        },
        _ => Err(RestoreStoreError::BadRow),
    }?;
    let (clock, tests, restored, never, future, failed, changed, age, oldest, missing, failing, db) = cells;
    match clock.as_str() {
        "true" => Ok(Counts {
            tests: count_cell(tests)?,
            restored: count_cell(restored)?,
            never: count_cell(never)?,
            future: count_cell(future)?,
            failed_latest: count_cell(failed)?,
            config_changed: count_cell(changed)?,
            age_micros: micros_cell(age)?,
            oldest_micros: micros_cell(oldest)?,
            missing: count_cell(missing)?,
            failing: count_cell(failing)?,
            db_micros: micros_cell(db)?,
        }),
        "false" => Err(RestoreStoreError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS }),
        _ => Err(RestoreStoreError::BadRow),
    }
}


/// Integers only.
pub fn source_of(counts: &Counts, untested: u64) -> String {
    format!(
        "backup:tests={};restored={};never={};untested={};future={};failed_latest={};config_changed={};failing={}",
        counts.tests, counts.restored, counts.never, untested, counts.future, counts.failed_latest, counts.config_changed, counts.failing
    )
}


/// Days, exactly: never floored. An untested critical host is worth `WORST_DAYS`.
pub fn value_of(counts: &Counts, untested: u64) -> f64 {
    let micros = if untested > 0 {
        counts.age_micros.max(WORST_MICROS)
    } else {
        counts.age_micros
    };
    micros as f64 / MICROS_PER_DAY as f64
}


/// The oldest latest result of the population; the lesser of `now` and the database clock when any member has no row; never after either.
pub fn observed_micros(counts: &Counts, untested: u64, now_micros: i64) -> i64 {
    let cap = now_micros.min(counts.db_micros);
    if counts.missing > 0 || untested > 0 {
        cap
    } else {
        counts.oldest_micros.min(cap)
    }
}


pub fn time_of_micros(micros: i64) -> Result<String, RestoreStoreError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * NANOS_PER_MICRO)
        .ok()
        .and_then(rfc3339_text)
        .ok_or(RestoreStoreError::BadRow)
}


/// The indicator of the tenant, or `None` when the declarations hold no restore test and no critical host.
pub async fn restore_indicator(
    exec: Executor<'_, '_>,
    declarations: &Declarations,
    tenant: &str,
    now: OffsetDateTime,
) -> Result<Option<IndicatorRow>, RestoreStoreError> {
    let scope = &declarations.tenant;
    (tenant_of(scope) == tenant).then_some(()).ok_or(RestoreStoreError::DeclarationsTenant)?;
    let now_micros = micros_of(now).ok_or(RestoreStoreError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })?;
    let members = population(declarations);
    if members.tests.is_empty() && members.untested == 0 {
        Ok(None)
    } else {
        let params = vec![tests_json(&members.tests), now_micros.to_string(), MAX_CLOCK_SKEW_SECONDS.to_string()];
        let rows = exec(scope.clone(), AGE_SQL, params).await.map_err(RestoreStoreError::Store)?;
        let counts = decode_counts(&rows)?;
        let observed_at = time_of_micros(observed_micros(&counts, members.untested, now_micros))?;
        Ok(Some(IndicatorRow {
            tenant: tenant.to_owned(),
            name: INDICATOR_NAME,
            value: value_of(&counts, members.untested),
            observed_at,
            source: source_of(&counts, members.untested),
        }))
    }
}


/// The JSON array the GRC evaluator reads: one object, or an empty array.
pub fn indicator_json(row: Option<&IndicatorRow>) -> String {
    Value::Array(
        row.map(|value| {
            json!({
                "tenant": value.tenant,
                "name": value.name,
                "value": value.value,
                "observed_at": value.observed_at,
                "source": value.source,
            })
        })
        .into_iter()
        .collect(),
    )
    .to_string()
}

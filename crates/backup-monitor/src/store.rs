//! The last restore result of every declared test, one row per tenant, repository, host and path (Unix only, like the runner).

use crate::error::RestoreStoreError;
use crate::model::RestoreTest;
use crate::restic::MAX_HOST_BYTES;
use crate::restore::{outcome_label, valid_canary_path, RestoreOutcome, RestoreResult};
use crate::text::{valid_id, valid_text};
use crate::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use time::OffsetDateTime;


pub const MIGRATION_NAMESPACE: &str = "backup";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "backup_0001",
    sql: include_str!("../migrations/backup_0001.sql"),
}];


/// Rows of one tenant; at least the declarations cap of repositories, each with one test.
pub const MAX_RESTORE_ROWS: u64 = 10_000;


/// The largest accepted distance between the runner clock and the database clock, and between a snapshot time and its test time.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;


/// 0000-01-01T00:00:00Z in microseconds since the epoch.
pub const MIN_MICROS: i64 = -62_167_219_200_000_000;


/// 9999-12-31T23:59:59.999999Z in microseconds since the epoch.
pub const MAX_MICROS: i64 = 253_402_300_799_999_999;


const NANOS_PER_MICRO: i128 = 1000;


/// `MAX_CLOCK_SKEW_SECONDS` in microseconds, the value the table CHECK carries.
pub const SKEW_MICROS: i64 = 300_000_000;


const MAX_REPOSITORY_BYTES: usize = 253;


pub const OUTCOME_OK: &str = "ok";


pub const OUTCOME_CLOCK_SKEW: &str = "clock_skew";


pub const OUTCOME_ROW_CAP: &str = "row_cap";


/// Params: `$2` JSON array of results, `$3` JSON array of declared keys, `$4` row cap, `$5` largest accepted skew in seconds.
pub const RECORD_SQL: &str = "SELECT outcome, written::text, stale_write::text, config_changed::text, pruned::text, row_count::text \
FROM public.backup_restore_record($1, $2::text::jsonb, $3::text::jsonb, $4::text::bigint, $5::text::bigint)";


/// The declared identity of one test: the repository name folded to lowercase, the host and the canary path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestKey {
    pub repository: String,
    pub host: String,
    pub path: String,
}


#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WriteCounts {
    pub written: u64,
    pub stale_write: u64,
    pub config_changed: u64,
    pub pruned: u64,
    pub skipped_invalid: u64,
}


pub fn test_key(repository: &str, test: &RestoreTest) -> TestKey {
    TestKey {
        repository: repository.to_ascii_lowercase(),
        host: test.host.clone(),
        path: test.path.clone(),
    }
}


pub fn valid_key(key: &TestKey) -> bool {
    valid_text(&key.repository, MAX_REPOSITORY_BYTES)
        && key.repository == key.repository.to_ascii_lowercase()
        && valid_text(&key.host, MAX_HOST_BYTES)
        && valid_canary_path(&key.path)
}


/// Microseconds since the epoch, `None` outside the years 0 to 9999 (which RFC 3339 can write back).
pub fn micros_of(time: OffsetDateTime) -> Option<i64> {
    i64::try_from(time.unix_timestamp_nanos().div_euclid(NANOS_PER_MICRO))
        .ok()
        .filter(|micros| (MIN_MICROS..=MAX_MICROS).contains(micros))
}


/// The snapshot id and time of a result: both or neither, the id a 64-hex id, the time in range.
pub fn snapshot_parts(result: &RestoreResult) -> Option<Option<(&str, i64)>> {
    match (&result.snapshot_id, result.snapshot_time) {
        (Some(id), Some(time)) => micros_of(time).filter(|_| valid_id(id)).map(|micros| Some((id.as_str(), micros))),
        (None, None) => Some(None),
        _ => None,
    }
}


/// The JSON entry of one result, or `None` when this result alone cannot be stored.
pub fn result_entry(key: &TestKey, result: &RestoreResult) -> Option<Value> {
    let tested = micros_of(result.tested_at)?;
    let snapshot = snapshot_parts(result)?;
    let latest = tested.saturating_add(SKEW_MICROS);
    let in_skew = snapshot.is_none_or(|(_, micros)| micros <= latest);
    let restored_has_snapshot = result.outcome != RestoreOutcome::Restored || snapshot.is_some();
    (valid_id(&result.config_id) && in_skew && restored_has_snapshot).then(|| {
        json!({
            "repository": key.repository,
            "host": key.host,
            "path": key.path,
            "config_id": result.config_id,
            "snapshot_id": snapshot.map(|(id, _)| id),
            "snapshot_micros": snapshot.map(|(_, micros)| micros),
            "tested_micros": tested,
            "outcome": outcome_label(&result.outcome),
        })
    })
}


pub fn key_json(key: &TestKey) -> Value {
    json!({ "repository": key.repository, "host": key.host, "path": key.path })
}


/// Refuses the whole run on a caller defect (tenant, undeclared key, bad key, too many keys); skips and counts a result that alone cannot be stored.
pub fn plan_write(
    scope: &TenantScope,
    results: &[(TestKey, RestoreResult)],
    declared: &[TestKey],
    cap: u64,
) -> Result<(Vec<Value>, u64), RestoreStoreError> {
    let count = declared.len() as u64;
    let known: BTreeSet<&TestKey> = declared.iter().collect();
    if count > cap {
        Err(RestoreStoreError::RowCap {
            tenant: tenant_of(scope).to_owned(),
            count,
            max: cap,
        })
    } else if !declared.iter().all(valid_key) {
        Err(RestoreStoreError::InvalidKey)
    } else if results.iter().any(|(_, result)| &result.tenant != scope) {
        Err(RestoreStoreError::TenantMismatch)
    } else if results.iter().any(|(key, _)| !known.contains(key)) {
        Err(RestoreStoreError::UndeclaredResult)
    } else {
        let entries: Vec<Value> = results.iter().filter_map(|(key, result)| result_entry(key, result)).collect();
        let skipped = (results.len() - entries.len()) as u64;
        Ok((entries, skipped))
    }
}


pub fn count_cell(cell: &str) -> Result<u64, RestoreStoreError> {
    cell.parse::<u64>().map_err(|_error| RestoreStoreError::BadRow)
}


/// Reads the one answer row: `ok` gives the counts, `clock_skew` and `row_cap` are named refusals.
pub fn decode_rows(scope: &TenantScope, cap: u64, rows: &[Row]) -> Result<WriteCounts, RestoreStoreError> {
    let cells = match rows {
        [only] => match only.as_slice() {
            [outcome, written, stale, changed, pruned, total] => Ok((outcome, written, stale, changed, pruned, total)),
            _ => Err(RestoreStoreError::BadRow),
        },
        _ => Err(RestoreStoreError::BadRow),
    }?;
    let (outcome, written, stale, changed, pruned, total) = cells;
    match outcome.as_str() {
        OUTCOME_OK => Ok(WriteCounts {
            written: count_cell(written)?,
            stale_write: count_cell(stale)?,
            config_changed: count_cell(changed)?,
            pruned: count_cell(pruned)?,
            skipped_invalid: 0,
        }),
        OUTCOME_CLOCK_SKEW => Err(RestoreStoreError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS }),
        OUTCOME_ROW_CAP => Err(RestoreStoreError::RowCap {
            tenant: tenant_of(scope).to_owned(),
            count: count_cell(total)?,
            max: cap,
        }),
        _ => Err(RestoreStoreError::BadRow),
    }
}


/// `record_restore_results` with an explicit row cap (the example lowers it for the live proof).
pub async fn record_restore_results_with_cap(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    results: &[(TestKey, RestoreResult)],
    declared: &[TestKey],
    cap: u64,
) -> Result<WriteCounts, RestoreStoreError> {
    (0..=MAX_RESTORE_ROWS)
        .contains(&cap)
        .then_some(())
        .ok_or(RestoreStoreError::CapOutOfRange)?;
    let (entries, skipped_invalid) = plan_write(scope, results, declared, cap)?;
    let declared_json = Value::Array(declared.iter().map(key_json).collect()).to_string();
    let params = vec![
        Value::Array(entries).to_string(),
        declared_json,
        cap.to_string(),
        MAX_CLOCK_SKEW_SECONDS.to_string(),
    ];
    let rows = exec(scope.clone(), RECORD_SQL, params).await.map_err(RestoreStoreError::Store)?;
    let counts = decode_rows(scope, cap, &rows)?;
    if skipped_invalid > 0 {
        tracing::warn!(skipped_invalid, "restore results were not stored");
    }
    Ok(WriteCounts { skipped_invalid, ..counts })
}


/// Stores the results of one run for the tenant and deletes the tenant's rows whose test is no longer declared, in one transaction.
pub async fn record_restore_results(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    results: &[(TestKey, RestoreResult)],
    declared: &[TestKey],
) -> Result<WriteCounts, RestoreStoreError> {
    record_restore_results_with_cap(exec, scope, results, declared, MAX_RESTORE_ROWS).await
}

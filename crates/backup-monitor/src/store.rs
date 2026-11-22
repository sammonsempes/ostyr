//! The last restore result of every declared test, one row per tenant, repository, host and path (Unix only, like the runner).

use crate::error::RestoreStoreError;
use crate::model::RestoreTest;
use crate::restic::{ResticError, MAX_HOST_BYTES};
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


pub const OUTCOME_RUN_ERROR: &str = "run_error";


pub const OUTCOME_CLOCK_SKEW: &str = "clock_skew";


pub const OUTCOME_ROW_CAP: &str = "row_cap";


pub const OUTCOME_BAD_TIME: &str = "bad_time";


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
    pub run_error: u64,
}


/// The fixed category stored for a run that ended without an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunErrorCategory {
    Config,
    Listing,
    List,
    PasswordChanged,
    Timeout,
    Failed,
    Invalid,
}


/// A declared test whose run ended in an error: no outcome, so no config id and no snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunErrorRecord {
    pub tenant: TenantScope,
    pub tested_at: OffsetDateTime,
    pub category: RunErrorCategory,
}


/// The entries to send, how many results could not be stored as themselves, and how many entries are run errors.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedWrite {
    pub entries: Vec<Value>,
    pub skipped_invalid: u64,
    pub run_error: u64,
}


pub fn category_label(category: RunErrorCategory) -> &'static str {
    match category {
        RunErrorCategory::Config => "config",
        RunErrorCategory::Listing => "listing",
        RunErrorCategory::List => "list",
        RunErrorCategory::PasswordChanged => "password_changed",
        RunErrorCategory::Timeout => "timeout",
        RunErrorCategory::Failed => "failed",
        RunErrorCategory::Invalid => "invalid",
    }
}


/// The stored category of a run error; the command that failed is not told apart, only the variant.
pub fn run_error_category(error: &ResticError) -> RunErrorCategory {
    match error {
        ResticError::BadConfig => RunErrorCategory::Config,
        ResticError::Listing(_) => RunErrorCategory::Listing,
        ResticError::BadList => RunErrorCategory::List,
        ResticError::PasswordFileChanged => RunErrorCategory::PasswordChanged,
        ResticError::Timeout => RunErrorCategory::Timeout,
        ResticError::Refused => RunErrorCategory::Invalid,
        ResticError::PasswordFile
        | ResticError::Oversized
        | ResticError::Failed { .. }
        | ResticError::Spawn
        | ResticError::Io
        | ResticError::Unwaitable => RunErrorCategory::Failed,
    }
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
            "category": Value::Null,
        })
    })
}


/// The JSON entry of a run error, or `None` when its time cannot be stored.
pub fn error_entry(key: &TestKey, tested_at: OffsetDateTime, category: RunErrorCategory) -> Option<Value> {
    micros_of(tested_at).map(|tested| {
        json!({
            "repository": key.repository,
            "host": key.host,
            "path": key.path,
            "config_id": Value::Null,
            "snapshot_id": Value::Null,
            "snapshot_micros": Value::Null,
            "tested_micros": tested,
            "outcome": OUTCOME_RUN_ERROR,
            "category": category_label(category),
        })
    })
}


/// A run error `invalid` whose time cannot be stored: no time, so the function stamps its own clock read after the lock.
pub fn database_clock_entry(key: &TestKey) -> Value {
    json!({
        "repository": key.repository,
        "host": key.host,
        "path": key.path,
        "config_id": Value::Null,
        "snapshot_id": Value::Null,
        "snapshot_micros": Value::Null,
        "tested_micros": Value::Null,
        "db_clock": true,
        "outcome": OUTCOME_RUN_ERROR,
        "category": category_label(RunErrorCategory::Invalid),
    })
}


pub fn key_json(key: &TestKey) -> Value {
    json!({ "repository": key.repository, "host": key.host, "path": key.path })
}


/// Refuses the whole run on a caller defect; a result that alone cannot be stored becomes a run error `invalid`.
pub fn plan_write(
    scope: &TenantScope,
    results: &[(TestKey, RestoreResult)],
    errors: &[(TestKey, RunErrorRecord)],
    declared: &[TestKey],
    cap: u64,
) -> Result<PlannedWrite, RestoreStoreError> {
    let count = declared.len() as u64;
    let known: BTreeSet<&TestKey> = declared.iter().collect();
    let used: BTreeSet<&TestKey> = results.iter().map(|(key, _)| key).chain(errors.iter().map(|(key, _)| key)).collect();
    if count > cap {
        Err(RestoreStoreError::RowCap {
            tenant: tenant_of(scope).to_owned(),
            count,
            max: cap,
        })
    } else if !declared.iter().all(valid_key) {
        Err(RestoreStoreError::InvalidKey)
    } else if results.iter().any(|(_, result)| &result.tenant != scope) || errors.iter().any(|(_, record)| &record.tenant != scope) {
        Err(RestoreStoreError::TenantMismatch)
    } else if used.iter().any(|key| !known.contains(*key)) {
        Err(RestoreStoreError::UndeclaredResult)
    } else if used.len() != results.len() + errors.len() {
        Err(RestoreStoreError::DuplicateResult)
    } else {
        let stored: Vec<Option<Value>> = results.iter().map(|(key, result)| result_entry(key, result)).collect();
        let converted: Vec<Value> = results
            .iter()
            .zip(&stored)
            .filter(|(_, entry)| entry.is_none())
            .map(|((key, result), _)| error_entry(key, result.tested_at, RunErrorCategory::Invalid).unwrap_or_else(|| database_clock_entry(key)))
            .collect();
        let failed: Vec<(Value, bool)> = errors
            .iter()
            .map(|(key, record)| match error_entry(key, record.tested_at, record.category) {
                Some(entry) => (entry, false),
                None => (database_clock_entry(key), true),
            })
            .collect();
        let skipped_invalid = (converted.len() + failed.iter().filter(|(_, unstorable)| *unstorable).count()) as u64;
        let run_error = (converted.len() + failed.len()) as u64;
        Ok(PlannedWrite {
            entries: stored
                .into_iter()
                .flatten()
                .chain(converted)
                .chain(failed.into_iter().map(|(entry, _)| entry))
                .collect(),
            skipped_invalid,
            run_error,
        })
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
            run_error: 0,
        }),
        OUTCOME_CLOCK_SKEW => Err(RestoreStoreError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS }),
        OUTCOME_BAD_TIME => Err(RestoreStoreError::BadTime),
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
    errors: &[(TestKey, RunErrorRecord)],
    declared: &[TestKey],
    cap: u64,
) -> Result<WriteCounts, RestoreStoreError> {
    (0..=MAX_RESTORE_ROWS)
        .contains(&cap)
        .then_some(())
        .ok_or(RestoreStoreError::CapOutOfRange)?;
    let planned = plan_write(scope, results, errors, declared, cap)?;
    let declared_json = Value::Array(declared.iter().map(key_json).collect()).to_string();
    let params = vec![
        Value::Array(planned.entries).to_string(),
        declared_json,
        cap.to_string(),
        MAX_CLOCK_SKEW_SECONDS.to_string(),
    ];
    let rows = exec(scope.clone(), RECORD_SQL, params).await.map_err(RestoreStoreError::Store)?;
    let counts = decode_rows(scope, cap, &rows)?;
    let skipped_invalid = planned.skipped_invalid;
    if skipped_invalid > 0 {
        tracing::warn!(skipped_invalid, "restore results were not stored as such");
    }
    Ok(WriteCounts {
        skipped_invalid,
        run_error: planned.run_error,
        ..counts
    })
}


/// Stores the results of one run for the tenant and deletes the tenant's rows whose test is no longer declared, in one transaction.
pub async fn record_restore_results(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    results: &[(TestKey, RestoreResult)],
    errors: &[(TestKey, RunErrorRecord)],
    declared: &[TestKey],
) -> Result<WriteCounts, RestoreStoreError> {
    record_restore_results_with_cap(exec, scope, results, errors, declared, MAX_RESTORE_ROWS).await
}

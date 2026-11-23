#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use backup_monitor::error::{BackupError, RestoreStoreError};
use backup_monitor::model::RestoreTest;
use backup_monitor::restic::ResticError;
use backup_monitor::restore::{RestoreOutcome, RestoreResult};
use backup_monitor::store::{
    category_label, count_cell, decode_rows, error_entry, key_json, micros_of, plan_write, record_restore_results, record_restore_results_with_cap,
    result_entry, run_error_category, snapshot_parts, test_key, valid_key, RunErrorCategory, RunErrorRecord, TestKey, WriteCounts,
    MAX_CLOCK_SKEW_SECONDS, MAX_MICROS, MAX_RESTORE_ROWS, MIGRATIONS, MIGRATION_NAMESPACE, MIN_MICROS, OUTCOME_BAD_TIME, OUTCOME_CLOCK_SKEW,
    OUTCOME_OK, OUTCOME_ROW_CAP, RECORD_SQL, SKEW_MICROS,
};
use backup_monitor::text::rfc3339_text;
use backup_monitor::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::digest_of;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use serde_json::Value;
use std::error::Error;
use std::future::ready;
use std::sync::Mutex;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const ANSWER_CELLS: usize = 6;


const PUBLISHED_FIRST_DIGEST: &str = "6bc232daeb4041a1895e550bcd0f59efde128d6a9358d0d7b41079c6c3d25eaa";


const SEVEN: u64 = 7;


const TWO_KEYS: usize = 2;


const CAP_PARAM: usize = 2;


const SKEW_PARAM: usize = 3;


const BEFORE_YEAR_ZERO: OffsetDateTime = datetime!(-0001-01-01 0:00 UTC);


const YEAR_ZERO: OffsetDateTime = datetime!(0000-01-01 0:00 UTC);


const LAST_INSTANT: OffsetDateTime = datetime!(9999-12-31 23:59:59.999999 UTC);


const CONFIG: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


const SNAPSHOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";


const PATH: &str = "/data/.ostyr-restore-canary";


const TESTED: OffsetDateTime = datetime!(2026-11-22 12:00:00 UTC);


const SNAPSHOT_TIME: OffsetDateTime = datetime!(2026-11-22 03:00:00 UTC);


const TESTED_MICROS: i64 = 1_795_348_800_000_000;


const SMALL_CAP: u64 = 1;


const TWO: u64 = 2;


const THREE: u64 = 3;


const FOUR: u64 = 4;


const FIVE: u64 = 5;


const OVER_CAP: u64 = 10_001;


const SKEW_SECONDS: i64 = 300;


const MICROS_PER_SECOND: i64 = 1_000_000;


fn scope(name: &str) -> Result<TenantScope, Box<dyn Error>> {
    Ok(tenant_scope(name)?)
}


fn key(repository: &str) -> TestKey {
    TestKey {
        repository: repository.to_owned(),
        host: "web-1".to_owned(),
        path: PATH.to_owned(),
    }
}


fn result(tenant: &TenantScope, outcome: RestoreOutcome, snapshot: bool) -> RestoreResult {
    RestoreResult {
        tenant: tenant.clone(),
        config_id: CONFIG.to_owned(),
        snapshot_id: snapshot.then(|| SNAPSHOT.to_owned()),
        snapshot_time: snapshot.then_some(SNAPSHOT_TIME),
        tested_at: TESTED,
        outcome,
    }
}


fn failure(tenant: &TenantScope, category: RunErrorCategory) -> RunErrorRecord {
    RunErrorRecord {
        tenant: tenant.clone(),
        tested_at: TESTED,
        category,
    }
}


fn row(cells: [&str; ANSWER_CELLS]) -> Row {
    cells.map(str::to_owned).to_vec()
}


fn ok_row() -> Row {
    row([OUTCOME_OK, "1", "2", "3", "4", "5"])
}


#[test]
fn the_migration_constants_match_the_table_text() -> TestResult {
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    let function_sql = migration_sql()?;
    assert_eq!(MIGRATION_NAMESPACE, "backup");
    assert_eq!(MIGRATIONS.first().map(|migration| migration.version), Some("backup_0001"));
    assert_eq!(MIGRATIONS.get(1).map(|migration| migration.version), Some("backup_0002"));
    assert_eq!(SKEW_MICROS, i64::try_from(MAX_CLOCK_SKEW_SECONDS)? * MICROS_PER_SECOND);
    assert_eq!(SKEW_MICROS, SKEW_SECONDS * MICROS_PER_SECOND);
    assert_eq!(sql.matches(&SKEW_MICROS.to_string()).count(), TWO as usize);
    assert!(sql.contains(&format!("BETWEEN {MIN_MICROS} AND {MAX_MICROS}")));
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('backup_restore/' || p_tenant, 0::bigint))"));
    assert!(sql.contains("SET search_path = pg_catalog, public, pg_temp"));
    assert!(function_sql.contains("CREATE OR REPLACE FUNCTION backup_restore_record("));
    assert!(function_sql.contains("pg_advisory_xact_lock(hashtextextended('backup_restore/' || p_tenant, 0::bigint))"));
    assert!(function_sql.contains("SET search_path = pg_catalog, public, pg_temp"));
    assert!(RECORD_SQL.contains("public.backup_restore_record($1"));
    Ok(())
}


fn table_sql() -> Result<&'static str, Box<dyn Error>> {
    Ok(MIGRATIONS.first().ok_or("no migration")?.sql)
}


fn migration_sql() -> Result<&'static str, Box<dyn Error>> {
    Ok(MIGRATIONS.get(1).ok_or("no second migration")?.sql)
}


#[test]
fn the_function_checks_the_clock_after_the_lock() -> TestResult {
    let sql = migration_sql()?;
    let lock = sql.find("pg_advisory_xact_lock").ok_or("no lock")?;
    let clock = sql.find("clock_timestamp()").ok_or("no clock")?;
    let check = sql.find("r.tested_micros > now_micros + skew * 1000000").ok_or("no check")?;
    assert!(lock < clock && clock < check);
    assert!(sql.contains("'clock_skew'"));
    Ok(())
}


#[test]
fn the_function_never_overwrites_with_an_older_time() -> TestResult {
    let sql = migration_sql()?;
    assert!(sql.contains("WHERE j.old_tested IS NULL OR j.old_tested < j.tested_micros"));
    assert!(sql.contains("WHERE st.tested_micros < EXCLUDED.tested_micros"));
    Ok(())
}


#[test]
fn the_function_clears_the_restored_columns_on_a_config_change() -> TestResult {
    let sql = migration_sql()?;
    assert_eq!(
        sql.matches("WHEN st.restored_config_id IS DISTINCT FROM EXCLUDED.config_id THEN NULL")
            .count(),
        THREE as usize
    );
    assert!(sql.contains("old_restored <> config_id"));
    Ok(())
}


#[test]
fn the_function_clamps_its_own_bounds() -> TestResult {
    let sql = migration_sql()?;
    assert!(sql.contains("cap bigint := least(greatest(p_cap, 0), 10000)"));
    assert!(sql.contains("skew bigint := least(greatest(p_max_skew_seconds, 0), 300)"));
    assert_eq!(MAX_RESTORE_ROWS, OVER_CAP - 1);
    Ok(())
}


#[test]
fn the_function_keeps_the_restored_columns_on_a_run_error() -> TestResult {
    let sql = migration_sql()?;
    assert_eq!(
        sql.matches("WHEN EXCLUDED.outcome = 'run_error' THEN st.restored_").count(),
        THREE as usize
    );
    let table = table_sql()?;
    assert!(table.contains("(config_id IS NOT NULL OR outcome = 'run_error')"));
    assert!(table.contains("(outcome = 'run_error') = (category IS NOT NULL)"));
    assert!(table.contains("'config', 'listing', 'list', 'password_changed', 'timeout', 'failed', 'invalid'"));
    Ok(())
}


#[test]
fn the_function_filters_every_statement_by_tenant() -> TestResult {
    let sql = migration_sql()?;
    assert!(sql.contains("ON s.tenant = p_tenant AND s.repository = i.repository"));
    assert!(sql.contains("WHERE t.tenant = p_tenant AND t.repository = d.repository"));
    assert!(sql.contains("ORDER BY r.repository, r.host, r.path, r.tested_micros DESC, (r.outcome = 'restored') ASC, (r.outcome = 'run_error') DESC"));
    Ok(())
}


#[test]
fn the_function_prunes_undeclared_rows_of_the_tenant() -> TestResult {
    let sql = migration_sql()?;
    assert!(sql.contains("DELETE FROM backup_restore_tests t\n    WHERE t.tenant = p_tenant AND NOT EXISTS ("));
    assert!(sql.contains("GET DIAGNOSTICS done_pruned = ROW_COUNT"));
    assert!(sql.contains("IF total > cap THEN"));
    Ok(())
}


#[test]
fn a_test_key_folds_the_repository_only() -> TestResult {
    let test = RestoreTest {
        host: "Web-1".to_owned(),
        path: PATH.to_owned(),
        sha256: CONFIG.to_owned(),
        max_bytes: 1,
    };
    let folded = test_key("Repo-A", &test);
    assert_eq!(folded.repository, "repo-a");
    assert_eq!(folded.host, "Web-1");
    assert_eq!(folded.path, PATH);
    Ok(())
}


#[test]
fn a_key_outside_the_grammar_is_invalid() -> TestResult {
    assert!(valid_key(&key("repo-a")));
    assert!(!valid_key(&key("Repo-A")));
    assert!(!valid_key(&key("repo a")));
    assert!(!valid_key(&TestKey {
        host: "-web".to_owned(),
        ..key("repo-a")
    }));
    assert!(!valid_key(&TestKey {
        path: "/data/other".to_owned(),
        ..key("repo-a")
    }));
    Ok(())
}


#[test]
fn micros_outside_the_years_0_to_9999_are_refused() -> TestResult {
    assert_eq!(micros_of(TESTED), Some(TESTED_MICROS));
    assert!(micros_of(BEFORE_YEAR_ZERO).is_none());
    assert!(micros_of(YEAR_ZERO).is_some());
    assert!(micros_of(LAST_INSTANT).is_some());
    Ok(())
}


#[test]
fn snapshot_parts_are_both_or_neither() -> TestResult {
    let tenant = scope("acme")?;
    let full = result(&tenant, RestoreOutcome::Restored, true);
    assert_eq!(snapshot_parts(&full).flatten().map(|(id, _)| id), Some(SNAPSHOT));
    assert_eq!(snapshot_parts(&result(&tenant, RestoreOutcome::NoSnapshot, false)), Some(None));
    let half = RestoreResult {
        snapshot_time: None,
        ..full.clone()
    };
    assert!(snapshot_parts(&half).is_none());
    let bad_id = RestoreResult {
        snapshot_id: Some("zz".to_owned()),
        ..full.clone()
    };
    assert!(snapshot_parts(&bad_id).is_none());
    let bad_time = RestoreResult {
        snapshot_time: Some(BEFORE_YEAR_ZERO),
        ..full
    };
    assert!(snapshot_parts(&bad_time).is_none());
    Ok(())
}


#[test]
fn a_result_entry_carries_the_typed_values() -> TestResult {
    let tenant = scope("acme")?;
    let entry = result_entry(&key("repo-a"), &result(&tenant, RestoreOutcome::Restored, true)).ok_or("refused")?;
    assert_eq!(entry.get("repository"), Some(&Value::from("repo-a")));
    assert_eq!(entry.get("snapshot_id"), Some(&Value::from(SNAPSHOT)));
    assert_eq!(entry.get("tested_micros"), Some(&Value::from(TESTED_MICROS)));
    assert_eq!(entry.get("outcome"), Some(&Value::from("restored")));
    let bare = result_entry(&key("repo-a"), &result(&tenant, RestoreOutcome::NoSnapshot, false)).ok_or("refused")?;
    assert_eq!(bare.get("snapshot_id"), Some(&Value::Null));
    assert_eq!(bare.get("snapshot_micros"), Some(&Value::Null));
    assert_eq!(key_json(&key("repo-a")).get("path"), Some(&Value::from(PATH)));
    Ok(())
}


#[test]
fn a_result_that_cannot_be_stored_is_refused_alone() -> TestResult {
    let tenant = scope("acme")?;
    let good = result(&tenant, RestoreOutcome::Restored, true);
    let refuse = |changed: RestoreResult| result_entry(&key("repo-a"), &changed).is_none();
    assert!(refuse(RestoreResult {
        tested_at: BEFORE_YEAR_ZERO,
        ..good.clone()
    }));
    assert!(refuse(RestoreResult {
        snapshot_id: None,
        ..good.clone()
    }));
    assert!(refuse(RestoreResult {
        config_id: "short".to_owned(),
        ..good.clone()
    }));
    assert!(refuse(RestoreResult {
        snapshot_time: Some(TESTED + time::Duration::seconds(SKEW_SECONDS + 1)),
        ..good.clone()
    }));
    assert!(!refuse(RestoreResult {
        snapshot_time: Some(TESTED + time::Duration::seconds(SKEW_SECONDS)),
        ..good.clone()
    }));
    assert!(refuse(result(&tenant, RestoreOutcome::Restored, false)));
    Ok(())
}


#[test]
fn a_run_is_refused_whole_on_a_caller_defect() -> TestResult {
    let tenant = scope("acme")?;
    let other = scope("other")?;
    let declared = [key("repo-a")];
    let good = (key("repo-a"), result(&tenant, RestoreOutcome::Restored, true));
    let planned = plan_write(&tenant, std::slice::from_ref(&good), &[], &declared, MAX_RESTORE_ROWS)?;
    assert_eq!((planned.entries.len(), planned.skipped_invalid, planned.run_error), (1, 0, 0));
    let skipped_run = plan_write(
        &tenant,
        &[(key("repo-a"), result(&tenant, RestoreOutcome::Restored, false))],
        &[],
        &declared,
        MAX_RESTORE_ROWS,
    )?;
    assert_eq!((skipped_run.entries.len(), skipped_run.skipped_invalid, skipped_run.run_error), (1, 1, 1));
    assert_eq!(
        skipped_run.entries.first().and_then(|entry| entry.get("category")),
        Some(&Value::from("invalid"))
    );
    assert_eq!(
        skipped_run.entries.first().and_then(|entry| entry.get("outcome")),
        Some(&Value::from("run_error"))
    );
    let unwritable = RestoreResult {
        tested_at: BEFORE_YEAR_ZERO,
        ..result(&tenant, RestoreOutcome::Restored, true)
    };
    let dropped = plan_write(&tenant, &[(key("repo-a"), unwritable)], &[], &declared, MAX_RESTORE_ROWS)?;
    assert_eq!((dropped.entries.len(), dropped.skipped_invalid, dropped.run_error), (1, 1, 1));
    let stamped = dropped.entries.first().ok_or("no entry")?;
    assert_eq!(stamped.get("tested_micros"), Some(&Value::Null));
    assert_eq!(stamped.get("db_clock"), Some(&Value::Bool(true)));
    assert_eq!(stamped.get("outcome"), Some(&Value::from("run_error")));
    assert_eq!(stamped.get("category"), Some(&Value::from("invalid")));
    let over = plan_write(&tenant, &[], &[], &[key("repo-a"), key("repo-b")], SMALL_CAP);
    assert!(matches!(
        over,
        Err(RestoreStoreError::RowCap {
            count: TWO,
            max: SMALL_CAP,
            ..
        })
    ));
    let bad_key = plan_write(&tenant, &[], &[], &[key("Repo-A")], MAX_RESTORE_ROWS);
    assert!(matches!(bad_key, Err(RestoreStoreError::InvalidKey)));
    let foreign = (key("repo-a"), result(&other, RestoreOutcome::Restored, true));
    assert!(matches!(
        plan_write(&tenant, &[foreign], &[], &declared, MAX_RESTORE_ROWS),
        Err(RestoreStoreError::TenantMismatch)
    ));
    let foreign_error = (key("repo-a"), failure(&other, RunErrorCategory::Failed));
    assert!(matches!(
        plan_write(&tenant, &[], &[foreign_error], &declared, MAX_RESTORE_ROWS),
        Err(RestoreStoreError::TenantMismatch)
    ));
    let undeclared = (key("repo-b"), result(&tenant, RestoreOutcome::Restored, true));
    assert!(matches!(
        plan_write(&tenant, &[undeclared], &[], &declared, MAX_RESTORE_ROWS),
        Err(RestoreStoreError::UndeclaredResult)
    ));
    let twice = [good.clone(), good.clone()];
    assert!(matches!(
        plan_write(&tenant, &twice, &[], &declared, MAX_RESTORE_ROWS),
        Err(RestoreStoreError::DuplicateResult)
    ));
    let both = (key("repo-a"), failure(&tenant, RunErrorCategory::Failed));
    assert!(matches!(
        plan_write(&tenant, &[good], &[both], &declared, MAX_RESTORE_ROWS),
        Err(RestoreStoreError::DuplicateResult)
    ));
    Ok(())
}


#[test]
fn the_answer_row_is_decoded_or_named() -> TestResult {
    let tenant = scope("acme")?;
    let counts = decode_rows(&tenant, MAX_RESTORE_ROWS, &[ok_row()])?;
    assert_eq!(
        counts,
        WriteCounts {
            written: 1,
            stale_write: TWO,
            config_changed: THREE,
            pruned: FOUR,
            skipped_invalid: 0,
            run_error: 0
        }
    );
    assert!(matches!(
        decode_rows(&tenant, MAX_RESTORE_ROWS, &[row([OUTCOME_CLOCK_SKEW, "0", "0", "0", "0", "0"])]),
        Err(RestoreStoreError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
    ));
    assert!(matches!(
        decode_rows(&tenant, MAX_RESTORE_ROWS, &[row([OUTCOME_BAD_TIME, "0", "0", "0", "0", "0"])]),
        Err(RestoreStoreError::BadTime)
    ));
    let capped = decode_rows(&tenant, SMALL_CAP, &[row([OUTCOME_ROW_CAP, "0", "0", "0", "0", "7"])]);
    assert!(matches!(
        capped,
        Err(RestoreStoreError::RowCap {
            count: SEVEN,
            max: SMALL_CAP,
            ..
        })
    ));
    let unknown = decode_rows(&tenant, SMALL_CAP, &[row(["maybe", "0", "0", "0", "0", "0"])]);
    assert!(matches!(unknown, Err(RestoreStoreError::BadRow)));
    assert!(matches!(decode_rows(&tenant, SMALL_CAP, &[]), Err(RestoreStoreError::BadRow)));
    assert!(matches!(
        decode_rows(&tenant, SMALL_CAP, &[ok_row(), ok_row()]),
        Err(RestoreStoreError::BadRow)
    ));
    assert!(matches!(
        decode_rows(&tenant, SMALL_CAP, &[vec!["ok".to_owned()]]),
        Err(RestoreStoreError::BadRow)
    ));
    assert!(matches!(count_cell("-1"), Err(RestoreStoreError::BadRow)));
    assert!(matches!(count_cell("x"), Err(RestoreStoreError::BadRow)));
    assert_eq!(count_cell("5")?, FIVE);
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn one_statement_carries_the_typed_results_and_the_declared_keys() -> TestResult {
    let tenant = scope("acme")?;
    let seen: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
    let exec = |bound: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        assert_eq!(tenant_of(&bound), "acme");
        seen.lock().into_iter().for_each(|mut guard| guard.push((sql.to_owned(), params.clone())));
        Box::pin(ready(Ok(vec![ok_row()])))
    };
    let declared = [key("repo-a"), key("repo-b")];
    let results = [
        (key("repo-a"), result(&tenant, RestoreOutcome::Restored, true)),
        (key("repo-b"), result(&tenant, RestoreOutcome::Restored, false)),
    ];
    let counts = record_restore_results(&exec, &tenant, &results, &[], &declared).await?;
    assert_eq!(counts.skipped_invalid, 1);
    assert_eq!(counts.run_error, 1);
    assert_eq!(counts.pruned, FOUR);
    let calls = seen.lock().map_err(|_poisoned| "poisoned")?;
    let (sql, params) = calls.first().ok_or("no call")?;
    assert_eq!(sql, RECORD_SQL);
    let sent: Value = serde_json::from_str(params.first().ok_or("no results")?)?;
    assert_eq!(sent.as_array().map(Vec::len), Some(TWO_KEYS));
    let keys: Value = serde_json::from_str(params.get(1).ok_or("no keys")?)?;
    assert_eq!(keys.as_array().map(Vec::len), Some(TWO_KEYS));
    assert_eq!(params.get(CAP_PARAM).map(String::as_str), Some("10000"));
    assert_eq!(params.get(SKEW_PARAM).map(String::as_str), Some("300"));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn an_empty_run_still_prunes() -> TestResult {
    let tenant = scope("acme")?;
    let exec = |_bound: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Ok(vec![ok_row()]))) };
    let counts = record_restore_results(&exec, &tenant, &[], &[], &[]).await?;
    assert_eq!(counts.skipped_invalid, 0);
    assert_eq!(counts.run_error, 0);
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_cap_above_the_maximum_is_refused_before_any_call() -> TestResult {
    let tenant = scope("acme")?;
    let exec = |_bound: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let refused = record_restore_results_with_cap(&exec, &tenant, &[], &[], &[], OVER_CAP).await;
    assert!(matches!(refused, Err(RestoreStoreError::CapOutOfRange)));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_failing_store_keeps_its_cause() -> TestResult {
    let tenant = scope("acme")?;
    let exec = |_bound: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let failed = record_restore_results(&exec, &tenant, &[], &[], &[]).await;
    let error = failed.err().ok_or("no error")?;
    assert!(matches!(error, RestoreStoreError::Store(PgError::InvalidTenant)));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn an_unrepresentable_time_has_no_rfc3339_text() -> TestResult {
    assert_eq!(rfc3339_text(TESTED).as_deref(), Some("2026-11-22T12:00:00Z"));
    assert!(rfc3339_text(BEFORE_YEAR_ZERO).is_none());
    Ok(())
}


#[test]
fn a_run_error_has_no_config_snapshot_or_outcome_of_its_own() -> TestResult {
    let entry = error_entry(&key("repo-a"), TESTED, RunErrorCategory::Config).ok_or("refused")?;
    assert_eq!(entry.get("outcome"), Some(&Value::from("run_error")));
    assert_eq!(entry.get("category"), Some(&Value::from("config")));
    assert_eq!(entry.get("config_id"), Some(&Value::Null));
    assert_eq!(entry.get("snapshot_id"), Some(&Value::Null));
    assert_eq!(entry.get("tested_micros"), Some(&Value::from(TESTED_MICROS)));
    assert!(error_entry(&key("repo-a"), BEFORE_YEAR_ZERO, RunErrorCategory::Config).is_none());
    assert!(error_entry(&key("repo-a"), YEAR_ZERO, RunErrorCategory::Failed).is_some());
    assert!(error_entry(&key("repo-a"), LAST_INSTANT, RunErrorCategory::Failed).is_some());
    Ok(())
}


#[test]
fn every_restic_error_has_one_fixed_category() -> TestResult {
    let listing = ResticError::Listing(BackupError::TooManySnapshots { limit: 1 });
    let cases = [
        (ResticError::BadConfig, RunErrorCategory::Config, "config"),
        (listing, RunErrorCategory::Listing, "listing"),
        (ResticError::BadList, RunErrorCategory::List, "list"),
        (ResticError::PasswordFileChanged, RunErrorCategory::PasswordChanged, "password_changed"),
        (ResticError::Timeout, RunErrorCategory::Timeout, "timeout"),
        (ResticError::Refused, RunErrorCategory::Invalid, "invalid"),
        (ResticError::PasswordFile, RunErrorCategory::Failed, "failed"),
        (ResticError::Oversized, RunErrorCategory::Failed, "failed"),
        (ResticError::Failed { code: Some(1) }, RunErrorCategory::Failed, "failed"),
        (ResticError::Spawn, RunErrorCategory::Failed, "failed"),
        (ResticError::Io, RunErrorCategory::Failed, "failed"),
        (ResticError::Unwaitable, RunErrorCategory::Failed, "failed"),
    ];
    cases.iter().for_each(|(error, category, label)| {
        assert_eq!(run_error_category(error), *category);
        assert_eq!(category_label(*category), *label);
    });
    Ok(())
}


#[test]
fn run_errors_are_planned_beside_results() -> TestResult {
    let tenant = scope("acme")?;
    let declared = [key("repo-a"), key("repo-b"), key("repo-c")];
    let results = [(key("repo-a"), result(&tenant, RestoreOutcome::Restored, true))];
    let errors = [
        (key("repo-b"), failure(&tenant, RunErrorCategory::Config)),
        (
            key("repo-c"),
            RunErrorRecord {
                tested_at: BEFORE_YEAR_ZERO,
                ..failure(&tenant, RunErrorCategory::Failed)
            },
        ),
    ];
    let planned = plan_write(&tenant, &results, &errors, &declared, MAX_RESTORE_ROWS)?;
    assert_eq!(
        (planned.entries.len(), planned.skipped_invalid, planned.run_error),
        (THREE as usize, 1, TWO)
    );
    Ok(())
}


#[test]
fn a_row_cap_refusal_names_its_tenant() -> TestResult {
    let message = RestoreStoreError::RowCap {
        tenant: "acme".to_owned(),
        count: THREE,
        max: TWO,
    }
    .to_string();
    assert!(message.contains("tenant acme"));
    Ok(())
}


#[test]
fn the_function_refuses_a_result_without_a_time_by_name() -> TestResult {
    let sql = migration_sql()?;
    let refusal = sql.find("'bad_time'").ok_or("no bad_time")?;
    let clock = sql.find("clock_timestamp()").ok_or("no clock")?;
    assert!(clock < refusal);
    assert!(sql.contains("(r.tested_micros IS NULL AND r.db_clock IS NOT TRUE) OR (r.db_clock IS TRUE AND r.outcome IS DISTINCT FROM 'run_error')"));
    assert!(sql.contains("CASE WHEN e.db_clock IS TRUE THEN now_micros ELSE e.tested_micros END AS tested_micros"));
    Ok(())
}


#[test]
fn the_published_first_migration_is_never_edited() -> TestResult {
    let first = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert_eq!(digest_of(first), PUBLISHED_FIRST_DIGEST);
    Ok(())
}


#[test]
fn the_tie_order_is_fail_closed() -> TestResult {
    let sql = migration_sql()?;
    let restored_last = sql.find("(r.outcome = 'restored') ASC").ok_or("no restored order")?;
    let run_error_first = sql.find("(r.outcome = 'run_error') DESC").ok_or("no run_error order")?;
    let time_first = sql.find("r.tested_micros DESC").ok_or("no time order")?;
    assert!(time_first < restored_last && restored_last < run_error_first);
    Ok(())
}

#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use backup_monitor::declarations::load_declarations;
use backup_monitor::error::RestoreStoreError;
use backup_monitor::indicator::{
    count_cell, decode_counts, indicator_json, micros_cell, observed_micros, population, restore_indicator, source_of, tests_json, time_of_micros,
    value_of, Counts, IndicatorRow, AGE_SQL, INDICATOR_NAME, MICROS_PER_DAY, WORST_DAYS, WORST_MICROS,
};
use backup_monitor::model::Declarations;
use backup_monitor::store::MAX_CLOCK_SKEW_SECONDS;
use backup_monitor::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::error::Error;
use std::future::ready;
use std::sync::Mutex;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-22 12:00:00 UTC);


const NOW_MICROS: i64 = 1_795_348_800_000_000;


const OLD_MICROS: i64 = 1_795_262_400_000_000;


const SKEW_MICROS: i64 = 250_000_000;


const CELLS: usize = 12;


const TWO: u64 = 2;


const THREE: u64 = 3;


const FOUR: u64 = 4;


const FIVE: u64 = 5;


const SIX: u64 = 6;


const SEVEN: u64 = 7;


const EIGHT: u64 = 8;


const NINE: u64 = 9;


const DAYS_NINETY: i64 = 90;


const MICROS_NINETY_POINT_NINE: i64 = 7_853_760_000_000;


const MICROS_ONE_OVER_NINETY: i64 = 7_776_000_000_001;


const MAX_SOURCE_CHARS: usize = 200;


const AT_CAP: u64 = 20_000;


const BEYOND_RANGE_MICROS: i64 = i64::MAX;


const BEFORE_YEAR_ZERO_MICROS: i64 = -62_167_219_200_000_001;


const HEX_LEN: usize = 64;


const SKEW_PARAM: usize = 2;


const ORDINARY_DAYS: f64 = 90.9;


const TOLERANCE: f64 = 1e-9;


const ONE_DAY: f64 = 1.0;


const ONE_AND_A_HALF: f64 = 1.5;


const ZERO_DAYS: f64 = 0.0;


const YEAR_MINUS_ONE: OffsetDateTime = datetime!(-0001-01-01 0:00 UTC);


const AGE_OF_ONE_HUNDRED: i64 = 100;


const CANARY: &str = "/data/.ostyr-restore-canary";


fn declarations(text: &str) -> Result<Declarations, Box<dyn Error>> {
    Ok(load_declarations(text, "declarations.yaml")?)
}


fn repository(name: &str, host: &str) -> String {
    format!(
        "  - repository: {name}\n    expected_min_snapshots: 1\n    restore_test:\n      host: {host}\n      path: {CANARY}\n      sha256: {}\n      max_bytes: 10\n",
        "a".repeat(HEX_LEN)
    )
}


fn counts() -> Counts {
    Counts {
        tests: TWO,
        restored: 1,
        never: 1,
        future: 0,
        failed_latest: THREE,
        config_changed: FOUR,
        age_micros: OLD_MICROS,
        oldest_micros: OLD_MICROS,
        missing: 0,
        failing: TWO,
        db_micros: NOW_MICROS,
    }
}


fn answer(cells: [&str; CELLS]) -> Vec<Row> {
    vec![cells.map(str::to_owned).to_vec()]
}


fn good_answer() -> Vec<Row> {
    answer([
        "true",
        "2",
        "1",
        "1",
        "0",
        "3",
        "4",
        "100",
        "1795262400000000",
        "0",
        "2",
        "1795348800000000",
    ])
}


#[test]
fn the_population_is_every_test_and_every_critical_host_without_one() -> TestResult {
    let text = format!(
        "tenant: acme\ncritical:\n  - host: web1\n    max_age_hours: 24\n  - host: db1\n    max_age_hours: 24\n  - host: vm/100\n    max_age_hours: 24\nrepositories:\n{}{}",
        repository("Main", "web1"),
        repository("second", "web1")
    );
    let members = population(&declarations(&text)?);
    assert_eq!(members.tests.len(), usize::try_from(TWO)?);
    assert_eq!(members.untested, TWO);
    assert_eq!(members.tests.first().map(|key| key.repository.as_str()), Some("main"));
    let sent: Value = serde_json::from_str(&tests_json(&members.tests))?;
    assert_eq!(sent.as_array().map(Vec::len), Some(usize::try_from(TWO)?));
    assert_eq!(sent.pointer("/0/path").and_then(Value::as_str), Some(CANARY));
    Ok(())
}


#[test]
fn a_host_named_by_any_test_is_tested_and_a_repository_without_a_test_adds_nothing() -> TestResult {
    let text = format!(
        "tenant: acme\ncritical:\n  - host: web1\n    max_age_hours: 24\nrepositories:\n  - repository: bare\n    expected_min_snapshots: 1\n{}",
        repository("main", "web1")
    );
    let members = population(&declarations(&text)?);
    assert_eq!(members.tests.len(), 1);
    assert_eq!(members.untested, 0);
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn nothing_declared_gives_no_indicator_and_no_statement() -> TestResult {
    let exec = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let none = restore_indicator(&exec, &declarations("tenant: acme\n")?, "acme", NOW).await?;
    assert!(none.is_none());
    assert_eq!(indicator_json(none.as_ref()), "[]");
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_critical_host_alone_is_worth_the_worst_value_and_the_time_is_now() -> TestResult {
    let text = "tenant: acme\ncritical:\n  - host: web1\n    max_age_hours: 24\n";
    let exec = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> {
        Box::pin(ready(Ok(answer([
            "true",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "1795348800000000",
        ]))))
    };
    let row = restore_indicator(&exec, &declarations(text)?, "acme", NOW).await?.ok_or("no row")?;
    assert!((row.value - WORST_DAYS as f64).abs() < f64::EPSILON);
    assert_eq!(row.observed_at, "2026-11-22T12:00:00Z");
    assert_eq!(
        row.source,
        "backup:tests=0;restored=0;never=0;untested=1;future=0;failed_latest=0;config_changed=0;failing=0"
    );
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_tested_population_reads_the_oldest_result_and_sends_the_typed_inputs() -> TestResult {
    let text = format!("tenant: acme\nrepositories:\n{}", repository("main", "web1"));
    let seen: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
    let exec = |bound: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        assert_eq!(tenant_of(&bound), "acme");
        seen.lock().into_iter().for_each(|mut guard| guard.push((sql.to_owned(), params.clone())));
        Box::pin(ready(Ok(good_answer())))
    };
    let row = restore_indicator(&exec, &declarations(&text)?, "acme", NOW).await?.ok_or("no row")?;
    assert_eq!(row.tenant, "acme");
    assert_eq!(row.name, INDICATOR_NAME);
    assert_eq!(row.observed_at, "2026-11-21T12:00:00Z");
    assert!(row.value > ZERO_DAYS);
    let calls = seen.lock().map_err(|_poisoned| "poisoned")?;
    let (sql, params) = calls.first().ok_or("no call")?;
    assert_eq!(sql, AGE_SQL);
    assert_eq!(params.get(1).map(String::as_str), Some(NOW_MICROS.to_string().as_str()));
    assert_eq!(
        params.get(SKEW_PARAM).map(String::as_str),
        Some(MAX_CLOCK_SKEW_SECONDS.to_string().as_str())
    );
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn another_tenant_is_refused_before_any_statement() -> TestResult {
    let exec = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let text = format!("tenant: acme\nrepositories:\n{}", repository("main", "web1"));
    let refused = restore_indicator(&exec, &declarations(&text)?, "other", NOW).await;
    assert!(matches!(refused, Err(RestoreStoreError::DeclarationsTenant)));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_now_outside_the_years_is_refused_as_skew() -> TestResult {
    let exec = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let text = format!("tenant: acme\nrepositories:\n{}", repository("main", "web1"));
    let refused = restore_indicator(&exec, &declarations(&text)?, "acme", YEAR_MINUS_ONE).await;
    assert!(matches!(refused, Err(RestoreStoreError::ClockSkew { .. })));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_database_clock_refusal_and_a_failing_store_are_named() -> TestResult {
    let text = format!("tenant: acme\nrepositories:\n{}", repository("main", "web1"));
    let skewed = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> {
        Box::pin(ready(Ok(answer([
            "false",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "1795348800000000",
        ]))))
    };
    let refused = restore_indicator(&skewed, &declarations(&text)?, "acme", NOW).await;
    assert!(matches!(refused, Err(RestoreStoreError::ClockSkew { max }) if max == MAX_CLOCK_SKEW_SECONDS));
    let failing = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(Err(PgError::InvalidTenant))) };
    let error = restore_indicator(&failing, &declarations(&text)?, "acme", NOW)
        .await
        .err()
        .ok_or("no error")?;
    assert!(matches!(error, RestoreStoreError::Store(PgError::InvalidTenant)));
    assert!(error.source().is_some());
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn an_oldest_time_that_cannot_be_written_is_a_bad_row() -> TestResult {
    let text = format!("tenant: acme\nrepositories:\n{}", repository("main", "web1"));
    let exec = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'_> {
        Box::pin(ready(Ok(answer([
            "true",
            "1",
            "1",
            "0",
            "0",
            "0",
            "0",
            "1",
            "-62167219200000001",
            "0",
            "0",
            "1795348800000000",
        ]))))
    };
    let refused = restore_indicator(&exec, &declarations(&text)?, "acme", NOW).await;
    assert!(matches!(refused, Err(RestoreStoreError::BadRow)));
    Ok(())
}


#[test]
fn the_answer_row_is_read_cell_by_cell() -> TestResult {
    let read = decode_counts(&good_answer())?;
    assert_eq!(
        (
            read.tests,
            read.restored,
            read.never,
            read.future,
            read.failed_latest,
            read.config_changed,
            read.missing
        ),
        (TWO, 1, 1, 0, THREE, FOUR, 0)
    );
    assert_eq!((read.age_micros, read.oldest_micros), (AGE_OF_ONE_HUNDRED, OLD_MICROS));
    assert_eq!((read.failing, read.db_micros), (TWO, NOW_MICROS));
    assert!(matches!(
        decode_counts(&answer(["true", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "x"])),
        Err(RestoreStoreError::BadRow)
    ));
    assert!(matches!(
        decode_counts(&answer(["false", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1795348800000000"])),
        Err(RestoreStoreError::ClockSkew { .. })
    ));
    assert!(matches!(
        decode_counts(&answer(["maybe", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1795348800000000"])),
        Err(RestoreStoreError::BadRow)
    ));
    assert!(matches!(decode_counts(&[]), Err(RestoreStoreError::BadRow)));
    assert!(matches!(decode_counts(&[vec!["true".to_owned()]]), Err(RestoreStoreError::BadRow)));
    assert!(matches!(
        decode_counts(&[good_answer().remove(0), good_answer().remove(0)]),
        Err(RestoreStoreError::BadRow)
    ));
    assert!(matches!(count_cell("-1"), Err(RestoreStoreError::BadRow)));
    assert!(matches!(micros_cell("1.5"), Err(RestoreStoreError::BadRow)));
    assert!(matches!(
        decode_counts(&answer(["true", "x", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1795348800000000"])),
        Err(RestoreStoreError::BadRow)
    ));
    Ok(())
}


#[test]
fn the_value_is_exact_days_never_floored() -> TestResult {
    let partial = Counts {
        age_micros: MICROS_NINETY_POINT_NINE,
        ..counts()
    };
    let days = value_of(&partial, 0);
    assert!(days > DAYS_NINETY as f64 && days < (DAYS_NINETY + 1) as f64, "{days}");
    assert!((days - ORDINARY_DAYS).abs() < TOLERANCE);
    let one_over = Counts {
        age_micros: MICROS_ONE_OVER_NINETY,
        ..counts()
    };
    assert!(value_of(&one_over, 0) > DAYS_NINETY as f64);
    let exact = Counts {
        age_micros: DAYS_NINETY * MICROS_PER_DAY,
        ..counts()
    };
    assert!((value_of(&exact, 0) - DAYS_NINETY as f64).abs() < f64::EPSILON);
    Ok(())
}


#[test]
fn an_untested_critical_host_lifts_the_value_to_the_worst() -> TestResult {
    let fresh = Counts { age_micros: 1, ..counts() };
    assert!((value_of(&fresh, 1) - WORST_DAYS as f64).abs() < f64::EPSILON);
    assert!(value_of(&fresh, 0) < ONE_DAY);
    assert_eq!(WORST_MICROS, WORST_DAYS * MICROS_PER_DAY);
    let beyond = Counts {
        age_micros: WORST_MICROS,
        ..counts()
    };
    assert!((value_of(&beyond, 1) - WORST_DAYS as f64).abs() < f64::EPSILON);
    Ok(())
}


#[test]
fn the_observation_time_is_now_when_a_member_has_no_row() -> TestResult {
    assert_eq!(observed_micros(&counts(), 0, NOW_MICROS), OLD_MICROS);
    assert_eq!(observed_micros(&Counts { missing: 1, ..counts() }, 0, NOW_MICROS), NOW_MICROS);
    assert_eq!(observed_micros(&counts(), 1, NOW_MICROS), NOW_MICROS);
    let ahead = Counts {
        oldest_micros: NOW_MICROS + 1,
        ..counts()
    };
    assert_eq!(observed_micros(&ahead, 0, NOW_MICROS), NOW_MICROS);
    let ahead_caller = Counts {
        db_micros: NOW_MICROS - SKEW_MICROS,
        missing: 1,
        ..counts()
    };
    assert_eq!(observed_micros(&ahead_caller, 0, NOW_MICROS), NOW_MICROS - SKEW_MICROS);
    assert_eq!(
        observed_micros(
            &Counts {
                oldest_micros: NOW_MICROS,
                ..ahead_caller
            },
            0,
            NOW_MICROS
        ),
        NOW_MICROS - SKEW_MICROS
    );
    assert_eq!(
        observed_micros(
            &Counts {
                db_micros: NOW_MICROS + SKEW_MICROS,
                ..counts()
            },
            1,
            NOW_MICROS
        ),
        NOW_MICROS
    );
    Ok(())
}


#[test]
fn the_source_holds_integers_only_and_stays_short() -> TestResult {
    let all = Counts {
        tests: AT_CAP,
        restored: AT_CAP,
        never: AT_CAP,
        future: AT_CAP,
        failed_latest: AT_CAP,
        config_changed: AT_CAP,
        failing: AT_CAP,
        ..counts()
    };
    let text = source_of(&all, AT_CAP);
    assert!(text.len() < MAX_SOURCE_CHARS, "{}", text.len());
    assert_eq!(
        source_of(
            &Counts {
                tests: TWO,
                restored: THREE,
                never: FOUR,
                future: FIVE,
                failed_latest: SIX,
                config_changed: SEVEN,
                failing: NINE,
                ..counts()
            },
            EIGHT
        ),
        "backup:tests=2;restored=3;never=4;untested=8;future=5;failed_latest=6;config_changed=7;failing=9"
    );
    Ok(())
}


#[test]
fn a_time_is_written_or_refused() -> TestResult {
    assert_eq!(time_of_micros(NOW_MICROS)?, "2026-11-22T12:00:00Z");
    assert!(matches!(time_of_micros(BEYOND_RANGE_MICROS), Err(RestoreStoreError::BadRow)));
    assert!(matches!(time_of_micros(BEFORE_YEAR_ZERO_MICROS), Err(RestoreStoreError::BadRow)));
    Ok(())
}


#[test]
fn the_json_is_one_object_the_evaluator_reads() -> TestResult {
    let row = IndicatorRow {
        tenant: "acme".to_owned(),
        name: INDICATOR_NAME,
        value: ONE_AND_A_HALF,
        observed_at: "2026-11-22T12:00:00Z".to_owned(),
        source: "backup:tests=1".to_owned(),
    };
    let parsed: Value = serde_json::from_str(&indicator_json(Some(&row)))?;
    assert_eq!(parsed.as_array().map(Vec::len), Some(1));
    assert_eq!(parsed.pointer("/0/name").and_then(Value::as_str), Some("backup.days_since_restore_test"));
    assert_eq!(parsed.pointer("/0/value").and_then(Value::as_f64), Some(ONE_AND_A_HALF));
    Ok(())
}


#[test]
fn the_query_pins_what_the_figure_rests_on() -> TestResult {
    assert!(AGE_SQL.contains("t.tenant = $1"));
    assert!(AGE_SQL.contains("least(j.restored_snapshot_micros, j.restored_tested_micros)"));
    assert!(AGE_SQL.contains("'digest_mismatch', 'not_covered', 'no_snapshot', 'run_error'"));
    assert!(AGE_SQL.contains("'timeout', 'failed', 'too_large'), false) AS failed_latest"));
    assert!(AGE_SQL.contains("'no_snapshot', 'run_error', 'listing_gap'"));
    assert!(!AGE_SQL.contains("'too_large', 'listing_gap'"));
    assert!(AGE_SQL.contains("j.restored_config_id <> j.config_id"));
    assert!(AGE_SQL.contains("WHEN never OR future OR changed OR failing THEN 315360000000000 ELSE age END"));
    assert!(AGE_SQL.contains(&WORST_MICROS.to_string()));
    assert!(AGE_SQL.contains("min(tested_micros)"));
    assert!(AGE_SQL.contains("clock_timestamp()"));
    assert!(!AGE_SQL.contains("float8"));
    assert!(!AGE_SQL.contains("floor("));
    Ok(())
}

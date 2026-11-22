mod types;


use alerts::types::{Row, RowFuture};
use compliance::error::IndicatorError;
use compliance::indicator::{
    check_baselines, check_clock, counts_text, decode_row, hardening_indicator, indicator_json, observed_at_of, pairs_json, parse_count, source_text,
    value_of, warning_line, HARDENING_INDICATOR, INDICATOR_SQL, MAX_BASELINES, MAX_CLOCK_SKEW_SECONDS, STALE_AFTER_MICROS,
};
use compliance::model::{Baseline, Control, Expectation, IndicatorCounts, IndicatorRow, Severity};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use std::sync::Mutex;
use time::OffsetDateTime;
use types::{Call, TestResult};


const NOW: u64 = 1_700_000_000_000_000;


const DATABASE_NOW: &str = "1700000000";


const DATABASE_SECONDS: u64 = 1_700_000_000;


const LONG_DIGITS: usize = 1_000;


const SECONDS_PER_HOUR: u64 = 3_600;


const HOURS_AGO: u64 = 47;


const SEEN: &str = "1699990000000000";


const TWO: usize = 2;


const THREE: usize = 3;


const MAX_SOURCE_CHARS: usize = 200;


const EXPECTED_STALE: i64 = 172_800_000_000;


const MICROS_PER_SECOND: u64 = 1_000_000;


const COLUMNS: usize = 12;


const SHARE: f64 = 0.75;


const HALF: f64 = 0.5;


const OLDEST_SECONDS: i64 = 1_699_990_000;


const ROWS: u64 = 90;


const EXCEPTED_ROWS: u64 = 9;


const STALE_ROWS: u64 = 8;


const COUNT: u64 = 12;


const EARLY_SECONDS: i64 = -62_200_000_000;


const BIG_COUNT: u64 = 1_000_000;


const BIGGEST_COUNT: u64 = 10_000_000_000;


const NONE: f64 = 0.0;


const ALL: f64 = 1.0;


fn control(id: &str) -> Control {
    Control {
        id: id.to_owned(),
        query: "select 1".to_owned(),
        expect: Expectation::RowCount(1),
        severity: Severity::Low,
        frameworks: Vec::new(),
        correction: None,
    }
}


fn baseline(tenant: &str, name: &str, controls: &[&str]) -> Baseline {
    Baseline {
        version: 1,
        tenant: tenant.to_owned(),
        name: name.to_owned(),
        actions: Vec::new(),
        controls: controls.iter().map(|id| control(id)).collect(),
    }
}


fn answer(cells: [&str; COLUMNS]) -> Row {
    cells.map(str::to_owned).to_vec()
}


fn full_row() -> Row {
    answer(["0.75", "4", "1", "3", "2", "5", "6", "7", "8", "90", SEEN, DATABASE_NOW])
}


async fn run_with(
    rows: Result<Vec<Row>, PgError>,
    tenant: &str,
    baselines: &[Baseline],
    now: u64,
) -> Result<(Result<compliance::model::IndicatorOutcome, IndicatorError>, Vec<Call>), types::TestError> {
    let calls: Mutex<Vec<Call>> = Mutex::new(Vec::new());
    let result = {
        let exec = |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((tenant_of(&scope).to_owned(), sql, params));
            let reply = match &rows {
                Ok(found) => Ok(found.clone()),
                Err(_error) => Err(PgError::InvalidTenant),
            };
            Box::pin(std::future::ready(reply))
        };
        hardening_indicator(&exec, &tenant_scope(tenant)?, baselines, now).await
    };
    let seen = calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    Ok((result, seen))
}


#[tokio::test]
async fn the_figure_carries_the_oldest_fresh_row_as_observed_at() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "acme", &[baseline("acme", "base", &["c1", "c2"])], NOW).await?;
    let outcome = result?;
    let row = outcome.row.ok_or("no row")?;
    assert_eq!(row.tenant, "acme");
    assert_eq!(row.name, HARDENING_INDICATOR);
    assert!((row.value - SHARE).abs() < f64::EPSILON);
    assert_eq!(row.observed_at, OffsetDateTime::from_unix_timestamp(OLDEST_SECONDS)?);
    assert_ne!(
        row.observed_at,
        OffsetDateTime::from_unix_timestamp(i64::try_from(NOW / MICROS_PER_SECOND)?)?
    );
    assert_eq!(
        row.source,
        "compliance:computed=1700000000;assets=4;exc_assets=1;exc_rows=3;err_rows=2;stale_rows=5;future_rows=6;missing=7;unlisted=8;rows=90"
    );
    assert_eq!(outcome.counts.rows, ROWS);
    assert_eq!(calls.len(), 1);
    let (tenant, sql, params) = calls.first().ok_or("no call")?;
    assert_eq!(tenant, "acme");
    assert_eq!(*sql, INDICATOR_SQL);
    assert_eq!(
        params.first().map(String::as_str),
        Some(r#"[{"baseline":"base","control":"c1"},{"baseline":"base","control":"c2"}]"#)
    );
    assert_eq!(params.get(1).map(String::as_str), Some("1700000000000000"));
    assert_eq!(params.get(TWO), Some(&EXPECTED_STALE.to_string()));
    assert_eq!(STALE_AFTER_MICROS, EXPECTED_STALE);
    Ok(())
}


#[tokio::test]
async fn no_scored_asset_emits_nothing() -> TestResult {
    let none = answer(["", "0", "0", "0", "0", "0", "0", "0", "0", "0", "", DATABASE_NOW]);
    let (result, _calls) = run_with(Ok(vec![none]), "acme", &[baseline("acme", "base", &["c1"])], NOW).await?;
    let outcome = result?;
    assert!(outcome.row.is_none());
    assert_eq!(outcome.counts, IndicatorCounts::default());
    assert_eq!(
        warning_line(&outcome.counts),
        "no hardening indicator emitted: assets=0;exc_assets=0;exc_rows=0;err_rows=0;stale_rows=0;future_rows=0;missing=0;unlisted=0;rows=0"
    );
    assert_eq!(indicator_json(&[])?, "[]");
    Ok(())
}


#[tokio::test]
async fn all_excepted_assets_emit_nothing() -> TestResult {
    let excepted = answer(["", "0", "3", "9", "0", "0", "0", "0", "0", "9", SEEN, DATABASE_NOW]);
    let (result, _calls) = run_with(Ok(vec![excepted]), "acme", &[baseline("acme", "base", &["c1"])], NOW).await?;
    let outcome = result?;
    assert!(outcome.row.is_none());
    assert_eq!(outcome.counts.excepted_only, THREE as u64);
    assert_eq!(outcome.counts.excepted_rows, EXCEPTED_ROWS);
    Ok(())
}


#[tokio::test]
async fn only_stale_rows_emit_nothing_but_are_counted() -> TestResult {
    let stale = answer(["0", "2", "0", "0", "0", "8", "1", "0", "0", "9", "", DATABASE_NOW]);
    let (result, _calls) = run_with(Ok(vec![stale]), "acme", &[baseline("acme", "base", &["c1"])], NOW).await?;
    let outcome = result?;
    assert!(outcome.row.is_none());
    assert_eq!(outcome.counts.stale_rows, STALE_ROWS);
    assert_eq!(outcome.counts.future_rows, 1);
    assert!(warning_line(&outcome.counts).contains("stale_rows=8;future_rows=1"));
    Ok(())
}


#[tokio::test]
async fn two_tenants_are_asked_with_their_own_scope() -> TestResult {
    let (first, calls_a) = run_with(Ok(vec![full_row()]), "a", &[baseline("a", "base", &["c1"])], NOW).await?;
    let (second, calls_b) = run_with(Ok(vec![full_row()]), "b", &[baseline("b", "base", &["c1"])], NOW).await?;
    assert_eq!(first?.row.ok_or("none")?.tenant, "a");
    assert_eq!(second?.row.ok_or("none")?.tenant, "b");
    assert_eq!(calls_a.first().ok_or("none")?.0, "a");
    assert_eq!(calls_b.first().ok_or("none")?.0, "b");
    Ok(())
}


#[tokio::test]
async fn a_baseline_of_another_tenant_is_refused_before_any_io() -> TestResult {
    let (result, calls) = run_with(
        Ok(vec![full_row()]),
        "a",
        &[baseline("a", "one", &["c1"]), baseline("b", "two", &["c1"])],
        NOW,
    )
    .await?;
    assert!(matches!(result, Err(IndicatorError::TenantMismatch)));
    assert!(calls.is_empty());
    Ok(())
}


#[tokio::test]
async fn too_many_or_duplicate_baselines_are_refused_before_any_io() -> TestResult {
    let many: Vec<Baseline> = (0..=MAX_BASELINES).map(|index| baseline("a", &format!("b{index}"), &["c1"])).collect();
    let (too_many, calls) = run_with(Ok(vec![full_row()]), "a", &many, NOW).await?;
    assert!(matches!(too_many, Err(IndicatorError::TooManyBaselines { max: MAX_BASELINES })));
    let (duplicate, more_calls) = run_with(
        Ok(vec![full_row()]),
        "a",
        &[baseline("a", "same", &["c1"]), baseline("a", "same", &["c2"])],
        NOW,
    )
    .await?;
    assert!(matches!(duplicate, Err(IndicatorError::DuplicateBaseline)));
    assert!(calls.is_empty() && more_calls.is_empty());
    assert!(check_baselines(&tenant_scope("a")?, &many.iter().take(MAX_BASELINES).cloned().collect::<Vec<_>>()).is_ok());
    Ok(())
}


#[tokio::test]
async fn a_time_past_the_database_range_is_refused_before_any_io() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "a", &[baseline("a", "base", &["c1"])], u64::MAX).await?;
    assert!(matches!(result, Err(IndicatorError::TimeOutOfRange)));
    assert!(calls.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_store_and_a_wrong_row_count_are_errors() -> TestResult {
    let bases = [baseline("a", "base", &["c1"])];
    let (failed, _first) = run_with(Err(PgError::InvalidTenant), "a", &bases, NOW).await?;
    assert!(matches!(failed, Err(IndicatorError::Store(_))));
    let (none, _second) = run_with(Ok(Vec::new()), "a", &bases, NOW).await?;
    assert!(matches!(none, Err(IndicatorError::BadRow)));
    let (two, _third) = run_with(Ok(vec![full_row(), full_row()]), "a", &bases, NOW).await?;
    assert!(matches!(two, Err(IndicatorError::BadRow)));
    Ok(())
}


#[test]
fn a_malformed_answer_row_is_refused_whatever_the_cell() -> TestResult {
    let scope = tenant_scope("a")?;
    assert!(matches!(decode_row(&scope, NOW, &vec!["1".to_owned()]), Err(IndicatorError::BadRow)));
    (0..COLUMNS).try_for_each(|position| {
        let mut cells = full_row();
        cells.get_mut(position).ok_or("cell")?.clone_from(&"x".to_owned());
        assert!(decode_row(&scope, NOW, &cells).is_err(), "cell {position}");
        Ok::<(), types::TestError>(())
    })?;
    Ok(())
}


#[test]
fn the_value_is_finite_and_between_zero_and_one() -> TestResult {
    assert!((value_of("0")? - NONE).abs() < f64::EPSILON);
    assert!((value_of("1")? - ALL).abs() < f64::EPSILON);
    ["1.0000001", "-0.1", "NaN", "inf", "Infinity", "-0.0000001"]
        .iter()
        .for_each(|text| assert!(matches!(value_of(text), Err(IndicatorError::ValueOutOfRange)), "{text}"));
    assert!(matches!(value_of("abc"), Err(IndicatorError::BadRow)));
    assert!(matches!(parse_count("-1"), Err(IndicatorError::BadRow)));
    assert_eq!(parse_count("12")?, COUNT);
    Ok(())
}


#[test]
fn the_observed_time_stays_inside_the_rfc_3339_years() -> TestResult {
    assert_eq!(observed_at_of("0")?, OffsetDateTime::UNIX_EPOCH);
    assert!(matches!(observed_at_of("x"), Err(IndicatorError::BadRow)));
    assert!(matches!(observed_at_of("9223372036854775807"), Err(IndicatorError::TimeOutOfRange)));
    assert!(matches!(observed_at_of("-62200000000000000"), Err(IndicatorError::TimeOutOfRange)));
    assert!(observed_at_of("253402300799000000").is_ok());
    assert!(matches!(observed_at_of("253402300800000000"), Err(IndicatorError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn the_json_is_the_grc_indicator_shape_and_refuses_a_year_it_cannot_write() -> TestResult {
    let row = IndicatorRow {
        tenant: "acme".to_owned(),
        name: HARDENING_INDICATOR.to_owned(),
        value: HALF,
        observed_at: OffsetDateTime::from_unix_timestamp(0)?,
        source: "s".to_owned(),
    };
    assert_eq!(
        indicator_json(std::slice::from_ref(&row))?,
        r#"[{"name":"hardening.mean_score_ratio","observed_at":"1970-01-01T00:00:00Z","source":"s","tenant":"acme","value":0.5}]"#
    );
    let early = IndicatorRow {
        observed_at: OffsetDateTime::from_unix_timestamp(EARLY_SECONDS)?,
        ..row
    };
    assert!(matches!(indicator_json(&[early]), Err(IndicatorError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn the_source_holds_integers_only_and_fits_the_grc_limit() -> TestResult {
    let counts = IndicatorCounts {
        assets: BIG_COUNT,
        excepted_only: BIG_COUNT,
        excepted_rows: BIG_COUNT,
        error_rows: BIG_COUNT,
        stale_rows: BIG_COUNT,
        future_rows: BIG_COUNT,
        missing: BIGGEST_COUNT,
        unlisted_rows: BIG_COUNT,
        rows: BIG_COUNT,
    };
    let source = source_text(u64::MAX, &counts);
    assert!(source.chars().count() <= MAX_SOURCE_CHARS);
    assert!(source
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || ":;=_".contains(character)));
    assert!(counts_text(&counts).starts_with("assets=1000000;"));
    Ok(())
}


#[test]
fn the_pairs_are_distinct_sorted_and_carry_no_other_text() -> TestResult {
    let bases = [baseline("a", "two", &["z", "z", "a"]), baseline("a", "one", &["c"])];
    assert_eq!(
        pairs_json(&bases),
        r#"[{"baseline":"one","control":"c"},{"baseline":"two","control":"a"},{"baseline":"two","control":"z"}]"#
    );
    assert_eq!(pairs_json(&[]), "[]");
    Ok(())
}


#[test]
fn the_statement_reads_one_tenant_and_keeps_every_scoring_rule() -> TestResult {
    let sql = INDICATOR_SQL;
    assert_eq!(sql.matches("compliance_state").count(), 1);
    assert!(sql.contains("FROM compliance_state s WHERE s.tenant = $1"));
    assert!(sql.contains("(s.baseline, s.control) IN (SELECT baseline, control FROM pairs)"));
    assert!(sql.contains("jsonb_to_recordset($2::text::jsonb)"));
    assert!(sql.contains("last_seen_micros > $3::text::bigint THEN 'future'"));
    assert!(sql.contains("last_seen_micros < $3::text::bigint - $4::text::bigint THEN 'stale'"));
    assert!(sql.contains("e.wanted - count(*) AS missing"));
    assert!(sql.contains("count(*) FILTER (WHERE c.age = 'fresh' AND c.verdict = 'pass') AS passed"));
    assert!(sql.contains("count(*) FILTER (WHERE c.age <> 'fresh' OR c.verdict IN ('fail', 'error')) AS failed"));
    assert!(!sql.contains("'excepted')) AS"));
    assert!(sql.contains("sum(failed) + sum(missing) + sum(passed) AS denominator"));
    assert!(sql.contains("avg(passed::numeric / NULLIF(denominator, 0))::text"));
    assert!(!sql.contains("float8"));
    assert!(sql.contains("extract(epoch from statement_timestamp())::bigint::text"));
    assert!(!sql.contains("::float8 /") && !sql.contains("avg(passed::float8"));
    assert!(sql.contains("count(*) FROM classified WHERE age = 'fresh' AND verdict = 'excepted'"));
    assert!(sql.contains("count(*) FROM classified WHERE age = 'fresh' AND verdict = 'error'"));
    assert!(sql.contains("min(last_seen_micros) FROM classified WHERE age = 'fresh'"));
    assert!(sql.contains("count(*) FROM tenant_rows WHERE NOT listed"));
    assert!(sql.contains("WHERE denominator > 0"));
    Ok(())
}


#[test]
fn the_value_does_not_depend_on_the_server_float_settings() -> TestResult {
    assert!((value_of("0.28583333333333333333")? - value_of("0.28583333333333333")?).abs() < f64::EPSILON);
    assert_eq!(value_of("0.28583333333333333333")?.to_bits(), value_of("0.28583333333333333")?.to_bits());
    assert!(value_of("-0")?.is_sign_positive());
    let digits = format!("0.{}", "3".repeat(LONG_DIGITS));
    assert!(value_of(&digits)? < HALF);
    assert!(matches!(
        value_of(&format!("1.{}", "5".repeat(LONG_DIGITS))),
        Err(IndicatorError::ValueOutOfRange)
    ));
    Ok(())
}


#[test]
fn a_time_far_from_the_database_clock_emits_nothing() -> TestResult {
    let scope = tenant_scope("a")?;
    let skew = MAX_CLOCK_SKEW_SECONDS;
    check_clock(NOW, DATABASE_NOW)?;
    check_clock(NOW, &(DATABASE_SECONDS + skew).to_string())?;
    check_clock(NOW, &(DATABASE_SECONDS - skew).to_string())?;
    let late = (DATABASE_SECONDS + skew + 1).to_string();
    let early = (DATABASE_SECONDS - skew - 1).to_string();
    assert!(matches!(
        check_clock(NOW, &late),
        Err(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
    ));
    assert!(matches!(check_clock(NOW, &early), Err(IndicatorError::ClockSkew { .. })));
    assert!(matches!(check_clock(NOW, "x"), Err(IndicatorError::BadRow)));
    let mut cells = full_row();
    cells.get_mut(COLUMNS - 1).ok_or("cell")?.clone_from(&early);
    assert!(matches!(decode_row(&scope, NOW, &cells), Err(IndicatorError::ClockSkew { .. })));
    assert!(matches!(
        decode_row(&scope, NOW - HOURS_AGO * SECONDS_PER_HOUR * MICROS_PER_SECOND, &full_row()),
        Err(IndicatorError::ClockSkew { .. })
    ));
    Ok(())
}

mod types;


use alerts::types::{Row, RowFuture};
use cases::error::IndicatorError;
use cases::indicator::{
    check_clock, counts_text, decode_row, incident_indicator, indicator_json, observed_at_of, parse_count, parse_flag, source_text, value_of,
    warning_line, IndicatorCounts, INCIDENT_INDICATOR, INDICATOR_SQL, MAX_CLOCK_SKEW_SECONDS, WINDOW_SECONDS,
};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use std::sync::Mutex;
use time::OffsetDateTime;
use types::{Call, TestResult};


const NOW: i64 = 1_700_000_000;


const DATABASE_NOW: &str = "1700000000";


const THREE: u64 = 3;


const FOUR: u64 = 4;


const HOURS_AGO: i64 = 47;


const SECONDS_PER_HOUR: i64 = 3_600;


const SKEW: i64 = 300;


const OVER_SKEW: i64 = 301;


const LONG_HOURS: f64 = 2_160.5;


const LAST_SECOND: i64 = 253_402_300_799;


const FIRST_BAD_SECOND: i64 = 253_402_300_800;


const HALF: f64 = 0.5;


const THREE_CELLS: usize = 3;


const TWO: u64 = 2;


const COLUMNS: usize = 7;


const HALF_DAY_HOURS: f64 = 12.5;


const BIG_COUNT: u64 = 10_000_000_000;


const MAX_SOURCE_CHARS: usize = 200;


const NINETY_DAYS: i64 = 7_776_000;


const EARLY_SECONDS: i64 = -62_200_000_000;


fn answer(cells: [&str; COLUMNS]) -> Row {
    cells.map(str::to_owned).to_vec()
}


fn full_row() -> Row {
    answer(["12.5", "1", "3", "1", "2", "true", DATABASE_NOW])
}


async fn run_with(
    rows: Result<Vec<Row>, PgError>,
    tenant: &str,
    now: i64,
) -> Result<(Result<cases::indicator::IndicatorOutcome, IndicatorError>, Vec<Call>), Box<dyn std::error::Error>> {
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
        incident_indicator(&exec, &tenant_scope(tenant)?, now).await
    };
    let seen = calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    Ok((result, seen))
}


#[tokio::test]
async fn the_figure_is_observed_at_now_and_asks_with_the_tenant_now_and_window() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "acme", NOW).await?;
    let outcome = result?;
    let row = outcome.row.ok_or("no row")?;
    assert_eq!(row.tenant, "acme");
    assert_eq!(row.name, INCIDENT_INDICATOR);
    assert!((row.value - HALF_DAY_HOURS).abs() < f64::EPSILON);
    assert_eq!(row.observed_at, OffsetDateTime::from_unix_timestamp(NOW)?);
    assert_eq!(row.source, "cases:computed=1700000000;open=1;closed=3;bad=1;excluded=2;window_days=90");
    assert_eq!(outcome.counts.closed, THREE);
    assert_eq!(calls.len(), 1);
    let (tenant, sql, params) = calls.first().ok_or("no call")?;
    assert_eq!(tenant, "acme");
    assert_eq!(*sql, INDICATOR_SQL);
    assert_eq!(params, &vec!["1700000000".to_owned(), NINETY_DAYS.to_string()]);
    assert_eq!(WINDOW_SECONDS, NINETY_DAYS);
    Ok(())
}


#[tokio::test]
async fn no_case_at_all_and_an_empty_population_emit_nothing_and_name_the_reason() -> TestResult {
    let none = answer(["", "0", "0", "0", "0", "false", DATABASE_NOW]);
    let (result, _calls) = run_with(Ok(vec![none]), "acme", NOW).await?;
    let outcome = result?;
    assert!(outcome.row.is_none());
    assert_eq!(
        warning_line(&outcome.counts),
        "no incident indicator emitted (no case at all): open=0;closed=0;bad=0;excluded=0"
    );
    let excluded = answer(["", "0", "0", "0", "4", "true", DATABASE_NOW]);
    let (second, _more) = run_with(Ok(vec![excluded]), "acme", NOW).await?;
    let counts = second?.counts;
    assert_eq!(counts.excluded, FOUR);
    assert_eq!(
        warning_line(&counts),
        "no incident indicator emitted (no incident case in the window): open=0;closed=0;bad=0;excluded=4"
    );
    assert_eq!(indicator_json(&[])?, "[]");
    Ok(())
}


#[tokio::test]
async fn a_clock_far_from_the_database_is_refused_with_no_figure() -> TestResult {
    let hours_ago = NOW - HOURS_AGO * SECONDS_PER_HOUR;
    let (old, _first) = run_with(Ok(vec![full_row()]), "acme", hours_ago).await?;
    assert!(matches!(old, Err(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })));
    assert!(check_clock(NOW + SKEW, DATABASE_NOW).is_ok());
    assert!(check_clock(NOW - SKEW, DATABASE_NOW).is_ok());
    assert!(check_clock(NOW + OVER_SKEW, DATABASE_NOW).is_err());
    assert!(check_clock(NOW - OVER_SKEW, DATABASE_NOW).is_err());
    assert!(matches!(check_clock(NOW, "x"), Err(IndicatorError::BadRow)));
    Ok(())
}


#[tokio::test]
async fn a_time_out_of_range_is_refused_before_any_io() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "acme", i64::MAX).await?;
    assert!(matches!(result, Err(IndicatorError::TimeOutOfRange)));
    assert!(calls.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_store_and_a_wrong_row_count_are_errors() -> TestResult {
    let (failed, _first) = run_with(Err(PgError::InvalidTenant), "a", NOW).await?;
    assert!(matches!(failed, Err(IndicatorError::Store(_))));
    let (none, _second) = run_with(Ok(Vec::new()), "a", NOW).await?;
    assert!(matches!(none, Err(IndicatorError::BadRow)));
    let (two, _third) = run_with(Ok(vec![full_row(), full_row()]), "a", NOW).await?;
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
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[test]
fn the_value_is_finite_and_at_least_zero() -> TestResult {
    assert!(value_of("0")?.abs() < f64::EPSILON);
    assert!((value_of("2160.5")? - LONG_HOURS).abs() < f64::EPSILON);
    ["-0.1", "NaN", "inf", "Infinity", "-1e400"]
        .iter()
        .for_each(|text| assert!(matches!(value_of(text), Err(IndicatorError::ValueOutOfRange)), "{text}"));
    assert!(matches!(value_of("abc"), Err(IndicatorError::BadRow)));
    assert!(matches!(parse_count("-1"), Err(IndicatorError::BadRow)));
    assert_eq!(parse_count("2")?, TWO);
    assert!(parse_flag("true")? && !parse_flag("false")?);
    assert!(matches!(parse_flag("t"), Err(IndicatorError::BadRow)));
    Ok(())
}


#[test]
fn the_observed_time_stays_inside_the_rfc_3339_years() -> TestResult {
    assert_eq!(observed_at_of(0)?, OffsetDateTime::UNIX_EPOCH);
    assert!(matches!(observed_at_of(i64::MAX), Err(IndicatorError::TimeOutOfRange)));
    assert!(matches!(observed_at_of(EARLY_SECONDS), Err(IndicatorError::TimeOutOfRange)));
    assert!(observed_at_of(LAST_SECOND).is_ok());
    assert!(matches!(observed_at_of(FIRST_BAD_SECOND), Err(IndicatorError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn the_json_is_the_grc_indicator_shape_and_refuses_a_year_it_cannot_write() -> TestResult {
    let row = cases::indicator::IndicatorRow {
        tenant: "acme".to_owned(),
        name: INCIDENT_INDICATOR.to_owned(),
        value: HALF,
        observed_at: OffsetDateTime::from_unix_timestamp(0)?,
        source: "s".to_owned(),
    };
    assert_eq!(
        indicator_json(std::slice::from_ref(&row))?,
        r#"[{"name":"incident.mean_hours_to_close","observed_at":"1970-01-01T00:00:00Z","source":"s","tenant":"acme","value":0.5}]"#
    );
    let early = cases::indicator::IndicatorRow {
        observed_at: OffsetDateTime::from_unix_timestamp(EARLY_SECONDS)?,
        ..row
    };
    assert!(matches!(indicator_json(&[early]), Err(IndicatorError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn the_source_holds_integers_only_and_fits_the_grc_limit() -> TestResult {
    let counts = IndicatorCounts {
        open: BIG_COUNT,
        closed: BIG_COUNT,
        bad: BIG_COUNT,
        excluded: BIG_COUNT,
        any_case: true,
    };
    let source = source_text(i64::MAX, &counts);
    assert!(source.chars().count() <= MAX_SOURCE_CHARS);
    assert!(source.chars().all(|found| found.is_ascii_alphanumeric() || ":;=_".contains(found)));
    assert_eq!(
        counts_text(&counts),
        "open=10000000000;closed=10000000000;bad=10000000000;excluded=10000000000"
    );
    Ok(())
}


#[test]
fn the_statement_reads_one_tenant_in_each_branch_and_no_free_text() -> TestResult {
    let sql = INDICATOR_SQL;
    assert_eq!(sql.matches("FROM cases WHERE tenant = $1").count(), THREE_CELLS);
    ["history", "comments", "observables", "title", "updated_at", "resolution"]
        .iter()
        .for_each(|word| assert!(!sql.contains(word), "{word}"));
    assert!(sql.contains("ever_incident OR status <> 'closed'"));
    assert!(sql.contains("closed_at < created_at"));
    assert!(sql.contains("GREATEST($3::text::bigint"));
    assert!(sql.contains("extract(epoch from statement_timestamp())"));
    Ok(())
}

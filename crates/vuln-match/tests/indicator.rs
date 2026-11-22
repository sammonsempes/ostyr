#[path = "common/store/types.rs"]
mod store_types;
#[path = "common/types.rs"]
mod types;


use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use std::sync::Mutex;
use store_types::Call;
use time::OffsetDateTime;
use types::TestResult;
use vuln_match::error::IndicatorError;
use vuln_match::indicator::{
    check_clock, counts_text, decode_row, indicator_json, kev_indicator, observed_at_of, parse_count, source_text, value_of, warning_line,
    ANSWER_COLUMNS, INDICATOR_SQL, KEV_INDICATOR, MAX_CLOCK_SKEW_SECONDS, WINDOW_DAYS,
};
use vuln_match::model::{IndicatorCounts, IndicatorRow};
use vuln_match::store::MIGRATIONS;


const NOW: u64 = 1_700_000_000_000_000;


const DATABASE_NOW: &str = "1700000000";


const SEEN: &str = "1699990000000000";


const OLDEST_SECONDS: i64 = 1_699_990_000;


const MICROS_PER_SECOND: u64 = 1_000_000;


const SIXTH: usize = 5;


const FOURTH: usize = 4;


const FOUR_READS: usize = 4;


const TWO_ROWS: u64 = 2;


const THREE: u64 = 3;


const FOUR: u64 = 4;


const FIVE: u64 = 5;


const SIX: u64 = 6;


const SEVEN: u64 = 7;


const DAYS_IN_WINDOW: u64 = 90;


const ZERO_VALUE: f64 = 0.0;


const HOURS_AGO: u64 = 47;


const SECONDS_PER_HOUR: u64 = 3_600;


const DECIMALS_MEAN: f64 = 90.0;


const TWO: usize = 2;


const MAX_SOURCE_CHARS: usize = 200;


const YEAR_10000_MICROS: &str = "253402300800000000";


const YEAR_BEFORE_ZERO_MICROS: &str = "-62167219201000000";


const BEFORE_YEAR_ZERO_SECONDS: i64 = -62_167_219_201;


const MEAN: f64 = 60.5;


const MICROS_PER_DAY: u64 = 86_400_000_000;


const WINDOW_MICROS: u64 = 7_776_000_000_000;


fn answer(cells: [&str; ANSWER_COLUMNS]) -> Row {
    cells.map(str::to_owned).to_vec()
}


fn full_row() -> Row {
    answer(["60.500000", "4", "3", "2", "1", "5", "61", SEEN, DATABASE_NOW])
}


async fn run_with(
    rows: Result<Vec<Row>, PgError>,
    tenant: &str,
    now: u64,
) -> Result<(Result<vuln_match::model::IndicatorOutcome, IndicatorError>, Vec<Call>), types::TestError> {
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
        kev_indicator(&exec, &tenant_scope(tenant)?, now).await
    };
    let seen = calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    Ok((result, seen))
}


#[tokio::test]
async fn the_figure_carries_the_oldest_open_row_as_observed_at() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "acme", NOW).await?;
    let outcome = result?;
    let row = outcome.row.ok_or("no row")?;
    assert_eq!(row.tenant, "acme");
    assert_eq!(row.name, KEV_INDICATOR);
    assert_eq!(KEV_INDICATOR, "vuln.kev_mean_days_to_fix");
    assert!((row.value - MEAN).abs() < f64::EPSILON);
    assert_eq!(row.observed_at, OffsetDateTime::from_unix_timestamp(OLDEST_SECONDS)?);
    assert_ne!(
        row.observed_at,
        OffsetDateTime::from_unix_timestamp(i64::try_from(NOW / MICROS_PER_SECOND)?)?
    );
    assert_eq!(
        row.source,
        "vuln:computed=1700000000;kev_open=4;kev_resolved=3;kev_cleared=2;bad_time_rows=1;open_over_30=5;oldest_open_days=61;window_days=90"
    );
    assert_eq!(calls.len(), 1);
    let (tenant, sql, params) = calls.first().ok_or("no call")?;
    assert_eq!(tenant, "acme");
    assert_eq!(*sql, INDICATOR_SQL);
    assert_eq!(params, &vec!["1700000000000000".to_owned()]);
    Ok(())
}


#[tokio::test]
async fn a_tenant_with_no_usable_row_emits_nothing() -> TestResult {
    let none = answer(["0", "0", "0", "0", "0", "0", "0", "", DATABASE_NOW]);
    let (result, _) = run_with(Ok(vec![none]), "acme", NOW).await?;
    let outcome = result?;
    assert!(outcome.row.is_none());
    assert_eq!(outcome.counts, IndicatorCounts::default());
    assert_eq!(
        warning_line(&outcome.counts),
        "no vulnerability indicator emitted: kev_open=0;kev_resolved=0;kev_cleared=0;bad_time_rows=0;open_over_30=0;oldest_open_days=0;window_days=90"
    );
    assert_eq!(indicator_json(&[])?, "[]");
    assert_eq!(WINDOW_DAYS, DAYS_IN_WINDOW);
    Ok(())
}


#[tokio::test]
async fn a_store_failure_keeps_its_cause_and_a_wrong_row_count_is_refused() -> TestResult {
    let (failed, _) = run_with(Err(PgError::InvalidTenant), "acme", NOW).await?;
    assert!(matches!(failed, Err(IndicatorError::Store(PgError::InvalidTenant))));
    let (empty, _) = run_with(Ok(Vec::new()), "acme", NOW).await?;
    assert!(matches!(empty, Err(IndicatorError::BadRow)));
    let (twice, _) = run_with(Ok(vec![full_row(), full_row()]), "acme", NOW).await?;
    assert!(matches!(twice, Err(IndicatorError::BadRow)));
    let (short, _) = run_with(Ok(vec![vec!["1".to_owned()]]), "acme", NOW).await?;
    assert!(matches!(short, Err(IndicatorError::BadRow)));
    Ok(())
}


#[tokio::test]
async fn a_time_that_does_not_fit_a_bigint_is_refused_before_any_call() -> TestResult {
    let (result, calls) = run_with(Ok(vec![full_row()]), "acme", u64::MAX).await?;
    assert!(matches!(result, Err(IndicatorError::TimeOutOfRange)));
    assert!(calls.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_caller_clock_far_from_the_database_clock_is_refused() -> TestResult {
    let far = NOW - HOURS_AGO * SECONDS_PER_HOUR * MICROS_PER_SECOND;
    let (result, _) = run_with(Ok(vec![full_row()]), "acme", far).await?;
    assert!(matches!(result, Err(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })));
    let edge = NOW + MAX_CLOCK_SKEW_SECONDS * MICROS_PER_SECOND;
    let (accepted, _) = run_with(Ok(vec![full_row()]), "acme", edge).await?;
    assert!(accepted.is_ok());
    let beyond = NOW + (MAX_CLOCK_SKEW_SECONDS + 1) * MICROS_PER_SECOND;
    let (refused, _) = run_with(Ok(vec![full_row()]), "acme", beyond).await?;
    assert!(matches!(refused, Err(IndicatorError::ClockSkew { .. })));
    assert!(matches!(check_clock(NOW, "not a number"), Err(IndicatorError::BadRow)));
    assert!(matches!(check_clock(NOW, "-1"), Err(IndicatorError::BadRow)));
    Ok(())
}


#[test]
fn every_unreadable_cell_is_a_bad_row() -> TestResult {
    let scope = tenant_scope("acme")?;
    (0..ANSWER_COLUMNS)
        .filter(|index| *index != 0 && *index != ANSWER_COLUMNS - TWO)
        .try_for_each(|index| -> TestResult {
            let mut cells = full_row();
            *cells.get_mut(index).ok_or("no cell")? = "x".to_owned();
            assert!(matches!(decode_row(&scope, NOW, &cells), Err(IndicatorError::BadRow)), "cell {index}");
            Ok(())
        })?;
    let mut bad_figure = full_row();
    *bad_figure.first_mut().ok_or("no figure")? = "x".to_owned();
    assert!(matches!(decode_row(&scope, NOW, &bad_figure), Err(IndicatorError::BadRow)));
    let mut negative = full_row();
    *negative.get_mut(FOURTH).ok_or("no cell")? = "-1".to_owned();
    assert!(matches!(decode_row(&scope, NOW, &negative), Err(IndicatorError::BadRow)));
    Ok(())
}


#[test]
fn the_value_is_a_finite_number_of_at_least_zero() -> TestResult {
    assert!((value_of("0.000000")? - ZERO_VALUE).abs() < f64::EPSILON);
    assert!((value_of("90")? - DECIMALS_MEAN).abs() < f64::EPSILON);
    assert!(matches!(value_of("-0.5"), Err(IndicatorError::ValueOutOfRange)));
    assert!(matches!(value_of("NaN"), Err(IndicatorError::ValueOutOfRange)));
    assert!(matches!(value_of("inf"), Err(IndicatorError::ValueOutOfRange)));
    assert!(matches!(value_of("1e999"), Err(IndicatorError::ValueOutOfRange)));
    assert!(matches!(value_of(""), Err(IndicatorError::BadRow)));
    assert!(matches!(value_of("1,5"), Err(IndicatorError::BadRow)));
    Ok(())
}


#[test]
fn the_observation_time_is_checked_for_range_and_text() -> TestResult {
    assert_eq!(observed_at_of(SEEN)?, OffsetDateTime::from_unix_timestamp(OLDEST_SECONDS)?);
    assert!(matches!(observed_at_of("x"), Err(IndicatorError::BadRow)));
    assert!(matches!(observed_at_of(YEAR_10000_MICROS), Err(IndicatorError::TimeOutOfRange)));
    assert!(matches!(observed_at_of(YEAR_BEFORE_ZERO_MICROS), Err(IndicatorError::TimeOutOfRange)));
    assert!(matches!(observed_at_of("9223372036854775807"), Err(IndicatorError::TimeOutOfRange)));
    assert!(observed_at_of("0").is_ok());
    assert!(matches!(parse_count("-1"), Err(IndicatorError::BadRow)));
    assert_eq!(parse_count("7")?, SEVEN);
    Ok(())
}


#[test]
fn the_source_holds_integers_only_and_fits_the_grc_limit() -> TestResult {
    let counts = IndicatorCounts {
        kev_open: 1,
        kev_resolved: TWO_ROWS,
        kev_cleared: THREE,
        bad_time_rows: FOUR,
        open_over_30: FIVE,
        oldest_open_days: SIX,
    };
    let text = source_text(NOW, &counts);
    assert_eq!(
        text,
        "vuln:computed=1700000000;kev_open=1;kev_resolved=2;kev_cleared=3;bad_time_rows=4;open_over_30=5;oldest_open_days=6;window_days=90"
    );
    assert!(text.len() < MAX_SOURCE_CHARS);
    assert_eq!(counts_text(&counts), text.split_once(';').ok_or("no split")?.1);
    Ok(())
}


#[test]
fn the_json_file_has_the_grc_shape_and_an_unwritable_year_is_refused() -> TestResult {
    let row = IndicatorRow {
        tenant: "acme".to_owned(),
        name: KEV_INDICATOR.to_owned(),
        value: MEAN,
        observed_at: OffsetDateTime::from_unix_timestamp(OLDEST_SECONDS)?,
        source: "vuln:computed=1".to_owned(),
    };
    assert_eq!(
        indicator_json(std::slice::from_ref(&row))?,
        r#"[{"name":"vuln.kev_mean_days_to_fix","observed_at":"2023-11-14T19:26:40Z","source":"vuln:computed=1","tenant":"acme","value":60.5}]"#
    );
    let early = IndicatorRow {
        observed_at: OffsetDateTime::from_unix_timestamp(BEFORE_YEAR_ZERO_SECONDS)?,
        ..row
    };
    assert!(matches!(indicator_json(&[early]), Err(IndicatorError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn the_sixth_migration_is_one_stable_pinned_function_with_a_tenant_filter_on_every_read() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.get(SIXTH).ok_or("no sixth migration")?.sql;
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(
        "LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET enable_sort = off SET jit = off AS $$"
    ));
    assert_eq!(flat.matches("FROM vuln_findings").count(), FOUR_READS);
    assert_eq!(flat.matches(".tenant = tenant_name").count(), FOUR_READS);
    assert!(flat.contains("f.kev_since_micros IS NOT NULL AND f.resolved_micros IS NULL"));
    assert!(flat.contains("f.kev_since_micros IS NOT NULL AND f.resolved_micros >= now_micros - 7776000000000"));
    assert!(!flat.contains("f.kev "));
    assert!(!flat.contains("float"));
    assert!(flat.contains("round(sum(w.micros) / count(*) / 86400000000, 6)::text"));
    assert!(flat.contains("IS TRUE AS bad"));
    assert!(flat.contains("WHEN t.bad THEN greatest(7776000000000, CASE WHEN t.first_seen <= now_micros THEN now_micros - t.first_seen ELSE 0 END)"));
    assert!(flat.contains("extract(epoch from statement_timestamp())::bigint::text"));
    assert!(INDICATOR_SQL.contains("FROM vuln_kev_indicator($1, $2::text::bigint)"));
    assert!(!INDICATOR_SQL.contains("::float"));
    assert_eq!(WINDOW_DAYS * MICROS_PER_DAY, WINDOW_MICROS);
    Ok(())
}

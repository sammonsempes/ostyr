mod types;


use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::coverage::{
    check_period, coverage_report, read_coverage, CoverageError, CoveragePeriod, FindingsRow, RunRow, TechniqueState, FINDINGS_SQL, MAX_REPORT_DAYS,
    MAX_STORED_ROWS, RUNS_SQL, SECONDS_PER_DAY,
};
use hunt_packs::model::{Baseline, Cost, HuntPack, Source};
use hunt_packs::store::{Param, StateError};
use std::cell::RefCell;
use std::future::{ready, Ready};
use std::rc::Rc;
use types::{Calls, FindingsAnswer, RunsAnswer, TestResult};


const FROM: i64 = 1_000_000;


const TO: i64 = 2_000_000;


const PERIOD: CoveragePeriod = CoveragePeriod { from: FROM, to: TO };


const YEAR_10000: i64 = 253_402_300_800;


const DAY: u64 = 86_400;


const QUERY: &str = "SELECT 1;";


const COST_ROWS: u64 = 1_000;


const COST_SECONDS: u64 = 10;


const COST_BYTES: u64 = 1_000_000;


const SOON: i64 = 5;


const LATER: i64 = 9;


const EARLY: i64 = 2;


const TEN: i64 = 10;


const SIX: i64 = 6;


const FOUR: u64 = 4;


const SIXTEEN: i64 = 16;


const THREE: i64 = 3;


const TWO_WINDOWS: i64 = 2;


const TWO_UNKNOWN: usize = 2;


const THREE_SKIPPED: usize = 3;


fn pack_of(id: &str, technique: &str) -> HuntPack {
    HuntPack {
        id: id.to_owned(),
        title: "Sample".to_owned(),
        hypothesis: "A sample".to_owned(),
        technique: technique.to_owned(),
        source: Source::Clickhouse,
        query: QUERY.to_owned(),
        schedule_seconds: DAY,
        window_seconds: DAY,
        cost: Cost {
            max_rows: COST_ROWS,
            max_seconds: COST_SECONDS,
            max_bytes_read: Some(COST_BYTES),
        },
        baseline: Baseline { max_matches: 0 },
        tests: Vec::new(),
    }
}


fn run(id: &str, end: i64) -> RunRow {
    RunRow {
        pack_id: id.to_owned(),
        last_done_end: end,
    }
}


fn found(id: &str, windows: i64, matches: i64, saturated: bool) -> FindingsRow {
    FindingsRow {
        pack_id: id.to_owned(),
        windows,
        matches,
        saturated,
    }
}


#[test]
fn no_pack_gives_an_empty_report() -> TestResult {
    let report = coverage_report(&[], &[], &[], &PERIOD);
    assert_eq!((report.packs_loaded, report.techniques, report.entries.len()), (0, 0, 0));
    assert_eq!((report.from, report.to, report.truncated), (FROM, TO, false));
    Ok(())
}


#[test]
fn a_technique_with_two_packs_takes_the_latest_run() -> TestResult {
    let packs = [pack_of("b", "T1059"), pack_of("a", "T1059"), pack_of("c", "T1071.001")];
    let runs = [run("a", FROM + SOON), run("b", FROM + LATER)];
    let report = coverage_report(&packs, &runs, &[], &PERIOD);
    assert_eq!(report.techniques, TWO_UNKNOWN);
    let first = report.entries.first().ok_or("entry")?;
    assert_eq!(first.technique, "T1059");
    assert_eq!(first.packs, vec!["a".to_owned(), "b".to_owned()]);
    assert_eq!(first.last_hunted, Some(FROM + LATER));
    assert_eq!(first.state, TechniqueState::HuntedClear);
    let second = report.entries.get(1).ok_or("entry")?;
    assert_eq!(
        (second.technique.as_str(), second.state, second.last_hunted),
        ("T1071.001", TechniqueState::NotHunted, None)
    );
    Ok(())
}


#[test]
fn a_sub_technique_is_never_rolled_into_its_parent() -> TestResult {
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1059.001")];
    let report = coverage_report(&packs, &[run("b", FROM + 1)], &[], &PERIOD);
    let parent = report.entries.first().ok_or("entry")?;
    assert_eq!((parent.technique.as_str(), parent.state), ("T1059", TechniqueState::NotHunted));
    let child = report.entries.get(1).ok_or("entry")?;
    assert_eq!((child.technique.as_str(), child.state), ("T1059.001", TechniqueState::HuntedClear));
    Ok(())
}


#[test]
fn a_run_at_from_is_inside_and_at_to_is_outside() -> TestResult {
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1071")];
    let report = coverage_report(&packs, &[run("a", FROM), run("b", TO)], &[], &PERIOD);
    assert_eq!(report.entries.first().ok_or("entry")?.state, TechniqueState::HuntedClear);
    let outside = report.entries.get(1).ok_or("entry")?;
    assert_eq!((outside.state, outside.last_hunted), (TechniqueState::NotHunted, Some(TO)));
    Ok(())
}


#[test]
fn findings_decide_the_state_and_are_summed_per_technique() -> TestResult {
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1059")];
    let findings = [found("a", TWO_WINDOWS, TEN, false), found("b", 1, SOON, false), found("a", 1, 1, false)];
    let report = coverage_report(&packs, &[], &findings, &PERIOD);
    let entry = report.entries.first().ok_or("entry")?;
    assert_eq!(
        (entry.state, entry.findings, entry.matches, entry.matches_saturated),
        (TechniqueState::HuntedFindings, FOUR, SIXTEEN, false)
    );
    Ok(())
}


#[test]
fn findings_only_outside_the_period_are_not_in_the_rows() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let report = coverage_report(&packs, &[run("a", TO + 1)], &[], &PERIOD);
    let entry = report.entries.first().ok_or("entry")?;
    assert_eq!((entry.state, entry.findings, entry.matches), (TechniqueState::NotHunted, 0, 0));
    Ok(())
}


#[test]
fn matches_saturate_and_are_flagged() -> TestResult {
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1059"), pack_of("c", "T1071")];
    let findings = [found("a", 1, i64::MAX, false), found("b", 1, 1, false), found("c", 1, THREE, true)];
    let report = coverage_report(&packs, &[], &findings, &PERIOD);
    let summed = report.entries.first().ok_or("entry")?;
    assert_eq!((summed.matches, summed.matches_saturated), (i64::MAX, true));
    let flagged = report.entries.get(1).ok_or("entry")?;
    assert_eq!((flagged.matches, flagged.matches_saturated), (THREE, true));
    Ok(())
}


#[test]
fn an_unknown_stored_pack_is_counted_once_and_never_listed() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let hostile = "x\u{1b}[31mred";
    let runs = [run(hostile, FROM), run("gone", FROM)];
    let findings = [found(hostile, 1, 1, false), found("gone", 1, 1, false)];
    let report = coverage_report(&packs, &runs, &findings, &PERIOD);
    assert_eq!(report.unknown_packs, TWO_UNKNOWN);
    let text = format!("{report:?}");
    assert!(!text.contains("gone") && !text.contains("red"));
    assert_eq!(report.entries.len(), 1);
    Ok(())
}


#[test]
fn rows_that_do_not_parse_are_skipped_and_counted() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let runs = [run("a", YEAR_10000), run("a", FROM)];
    let findings = [found("a", 0, 1, false), found("a", 1, -1, false), found("a", 1, EARLY, false)];
    let report = coverage_report(&packs, &runs, &findings, &PERIOD);
    assert_eq!(report.skipped, THREE_SKIPPED);
    let entry = report.entries.first().ok_or("entry")?;
    assert_eq!((entry.findings, entry.matches, entry.last_hunted), (1, EARLY, Some(FROM)));
    Ok(())
}


#[test]
fn duplicate_run_rows_keep_the_latest() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let report = coverage_report(&packs, &[run("a", FROM + LATER), run("a", FROM + EARLY)], &[], &PERIOD);
    assert_eq!(report.entries.first().ok_or("entry")?.last_hunted, Some(FROM + LATER));
    let flipped = coverage_report(&packs, &[run("a", FROM + EARLY), run("a", FROM + SIX)], &[], &PERIOD);
    assert_eq!(flipped.entries.first().ok_or("entry")?.last_hunted, Some(FROM + SIX));
    Ok(())
}


#[test]
fn the_period_is_checked() -> TestResult {
    assert_eq!(check_period(FROM, TO)?, PERIOD);
    let longest = FROM + MAX_REPORT_DAYS * SECONDS_PER_DAY;
    assert_eq!(check_period(FROM, longest)?.to, longest);
    assert!(matches!(check_period(FROM, longest + 1), Err(CoverageError::TooLong { field: "to" })));
    assert!(matches!(check_period(FROM, FROM), Err(CoverageError::Reversed { field: "to" })));
    assert!(matches!(check_period(TO, FROM), Err(CoverageError::Reversed { field: "to" })));
    assert!(matches!(
        check_period(-YEAR_10000, FROM),
        Err(CoverageError::OutOfRange { field: "from", .. })
    ));
    assert!(matches!(
        check_period(FROM, YEAR_10000),
        Err(CoverageError::OutOfRange { field: "to", .. })
    ));
    let message = check_period(FROM, FROM).err().ok_or("error")?.to_string();
    assert!(message.contains("`to`"));
    Ok(())
}


fn runs_fake(calls: &Calls, answer: impl Fn() -> RunsAnswer) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<RunsAnswer> {
    let log = Rc::clone(calls);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params));
        ready(answer())
    }
}


fn findings_fake(calls: &Calls, answer: impl Fn() -> FindingsAnswer) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<FindingsAnswer> {
    let log = Rc::clone(calls);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params));
        ready(answer())
    }
}


#[tokio::test]
async fn two_statements_both_bind_the_tenant_first() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs = runs_fake(&calls, || Ok(vec![run("a", FROM)]));
    let mut finds = findings_fake(&calls, || Ok(vec![found("a", 1, FOUR_MATCHES, false)]));
    let report = read_coverage(&mut runs, &mut finds, "acme", &[pack_of("a", "T1059")], &PERIOD).await?;
    assert_eq!(report.entries.first().ok_or("entry")?.matches, FOUR_MATCHES);
    let seen = calls.borrow().clone();
    let limit = Param::Int(MAX_STORED_ROWS + 1);
    assert_eq!(
        seen,
        vec![
            ("acme".to_owned(), RUNS_SQL, vec![limit.clone()]),
            ("acme".to_owned(), FINDINGS_SQL, vec![Param::Int(FROM), Param::Int(TO), limit]),
        ]
    );
    assert!(RUNS_SQL.contains("WHERE tenant = $1"));
    assert!(FINDINGS_SQL.contains("WHERE tenant = $1 AND window_end >= $2 AND window_end < $3"));
    Ok(())
}


const FOUR_MATCHES: i64 = 4;


#[tokio::test]
async fn a_statement_over_the_row_cap_is_flagged_truncated() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let many = usize::try_from(MAX_STORED_ROWS)? + 1;
    let mut runs = runs_fake(&calls, || Ok((0..many).map(|index| run(&format!("p{index}"), FROM)).collect()));
    let mut finds = findings_fake(&calls, || Ok(Vec::new()));
    let report = read_coverage(&mut runs, &mut finds, "acme", &[], &PERIOD).await?;
    assert!(report.truncated);
    assert_eq!(report.unknown_packs, many - 1);
    let mut runs_ok = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds_over = findings_fake(&calls, || Ok((0..many).map(|index| found(&format!("p{index}"), 1, 1, false)).collect()));
    assert!(read_coverage(&mut runs_ok, &mut finds_over, "acme", &[], &PERIOD).await?.truncated);
    let mut runs_none = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds_none = findings_fake(&calls, || Ok(Vec::new()));
    assert!(!read_coverage(&mut runs_none, &mut finds_none, "acme", &[], &PERIOD).await?.truncated);
    Ok(())
}


#[tokio::test]
async fn store_failures_and_bad_tenants_are_typed() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs_bad = runs_fake(&calls, || Err(PgError::InvalidTenant));
    let mut finds = findings_fake(&calls, || Ok(Vec::new()));
    let failed = read_coverage(&mut runs_bad, &mut finds, "acme", &[], &PERIOD).await;
    assert!(matches!(failed, Err(CoverageError::Store(StateError::Pg(_)))));
    let mut runs = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds_bad = findings_fake(&calls, || Err(PgError::InvalidTenant));
    let second = read_coverage(&mut runs, &mut finds_bad, "acme", &[], &PERIOD).await;
    assert!(matches!(second, Err(CoverageError::Store(_))));
    let before = calls.borrow().len();
    let refused = read_coverage(&mut runs, &mut finds_bad, "-x", &[], &PERIOD).await;
    assert!(matches!(refused, Err(CoverageError::Store(StateError::Pg(PgError::InvalidTenant)))));
    assert_eq!(calls.borrow().len(), before);
    Ok(())
}

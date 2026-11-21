mod types;


use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::coverage::{
    bad_pack_index, check_period, coverage_report, joined_ids, read_coverage, CoverageError, CoveragePeriod, FindingsRow, RunRow, TechniqueState,
    FINDINGS_SQL, KIND_OVERSIZED, KIND_PACK, KIND_UNKNOWN, MAX_REPORT_DAYS, QUERY_CANCELED, RUNS_SQL, SECONDS_PER_DAY,
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
        kind: KIND_PACK,
        pack_id: id.to_owned(),
        value: end,
    }
}


fn run_count(kind: i32, count: i64) -> RunRow {
    RunRow {
        kind,
        pack_id: String::new(),
        value: count,
    }
}


fn found(id: &str, windows: i64, matches: i64, saturated: bool) -> FindingsRow {
    FindingsRow {
        kind: KIND_PACK,
        pack_id: id.to_owned(),
        windows,
        matches,
        saturated,
        negative: 0,
    }
}


fn negative_only(id: &str, negative: i64) -> FindingsRow {
    FindingsRow {
        negative,
        ..found(id, 0, 0, false)
    }
}


fn found_count(kind: i32, count: i64) -> FindingsRow {
    FindingsRow {
        kind,
        pack_id: String::new(),
        windows: count,
        matches: 0,
        saturated: false,
        negative: 0,
    }
}


#[test]
fn no_pack_gives_an_empty_report() -> TestResult {
    let report = coverage_report(&[], &[], &[], &PERIOD);
    assert_eq!((report.packs_loaded, report.techniques, report.entries.len()), (0, 0, 0));
    assert_eq!((report.from, report.to, report.skipped), (FROM, TO, 0));
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
fn unknown_and_oversized_ids_are_counts_only() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let runs = [run("a", FROM), run_count(KIND_UNKNOWN, RETIRED), run_count(KIND_OVERSIZED, TWO_WINDOWS)];
    let findings = [found_count(KIND_UNKNOWN, THREE), found_count(KIND_OVERSIZED, 1)];
    let report = coverage_report(&packs, &runs, &findings, &PERIOD);
    assert_eq!(
        (
            report.unknown_packs,
            report.unknown_finding_packs,
            report.oversized_run_ids,
            report.oversized_finding_ids,
            report.skipped
        ),
        (RETIRED as u64, THREE as u64, TWO_UNKNOWN as u64, 1, 0)
    );
    assert_eq!(report.entries.first().ok_or("entry")?.state, TechniqueState::HuntedClear);
    Ok(())
}


#[test]
fn a_row_of_a_pack_nobody_loaded_is_skipped_and_never_listed() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let hostile = "x\u{1b}[31mred";
    let report = coverage_report(&packs, &[run(hostile, FROM)], &[found(hostile, 1, 1, false)], &PERIOD);
    assert_eq!(report.skipped, TWO_UNKNOWN as u64);
    assert!(!format!("{report:?}").contains("red"));
    Ok(())
}


#[test]
fn rows_that_do_not_parse_are_skipped_and_counted() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let runs = [run("a", YEAR_10000), run("a", FROM)];
    let findings = [
        found("a", -1, 1, false),
        found("a", 1, -1, false),
        found("a", 1, EARLY, false),
        negative_only("a", -1),
    ];
    let report = coverage_report(&packs, &runs, &findings, &PERIOD);
    assert_eq!(report.skipped, FOUR);
    let entry = report.entries.first().ok_or("entry")?;
    assert_eq!((entry.findings, entry.matches, entry.last_hunted), (1, EARLY, Some(FROM)));
    Ok(())
}


#[test]
fn a_row_with_no_window_at_all_is_skipped() -> TestResult {
    let report = coverage_report(&[pack_of("a", "T1059")], &[], &[found("a", 0, 0, false)], &PERIOD);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.entries.first().ok_or("entry")?.state, TechniqueState::NotHunted);
    Ok(())
}


#[test]
fn negative_matches_rows_are_counted_and_the_report_survives() -> TestResult {
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1071")];
    let mixed = FindingsRow {
        negative: 1,
        ..found("a", 1, TEN, false)
    };
    let findings = [mixed, negative_only("b", TWO_WINDOWS)];
    let report = coverage_report(&packs, &[], &findings, &PERIOD);
    assert_eq!(report.skipped, THREE_SKIPPED as u64);
    let first = report.entries.first().ok_or("entry")?;
    assert_eq!((first.state, first.findings, first.matches), (TechniqueState::HuntedFindings, 1, TEN));
    let only_negative = report.entries.get(1).ok_or("entry")?;
    assert_eq!(
        (only_negative.state, only_negative.findings, only_negative.matches),
        (TechniqueState::NotHunted, 0, 0)
    );
    Ok(())
}


#[test]
fn a_pack_with_only_negative_rows_is_hunted_clear_when_a_run_ends_in_the_period() -> TestResult {
    let packs = [pack_of("a", "T1059")];
    let report = coverage_report(&packs, &[run("a", FROM)], &[negative_only("a", TWO_WINDOWS)], &PERIOD);
    let entry = report.entries.first().ok_or("entry")?;
    assert_eq!(
        (entry.state, entry.findings, report.skipped),
        (TechniqueState::HuntedClear, 0, TWO_WINDOWS as u64)
    );
    let outside = coverage_report(&packs, &[run("a", TO)], &[negative_only("a", 1)], &PERIOD);
    assert_eq!(outside.entries.first().ok_or("entry")?.state, TechniqueState::NotHunted);
    assert_eq!(outside.skipped, 1);
    Ok(())
}


#[test]
fn bad_counts_and_stray_kinds_are_skipped() -> TestResult {
    let runs = [run_count(KIND_UNKNOWN, -1), run_count(KIND_OVERSIZED, -1), run_count(STRAY_KIND, 1)];
    let findings = [found_count(KIND_UNKNOWN, -1), found_count(KIND_OVERSIZED, -1), found_count(STRAY_KIND, 1)];
    let report = coverage_report(&[], &runs, &findings, &PERIOD);
    assert_eq!(report.skipped, SIX_SKIPPED);
    assert_eq!((report.unknown_packs, report.oversized_finding_ids), (0, 0));
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


fn runs_fake(calls: &Calls, answer: fn() -> RunsAnswer) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<RunsAnswer> {
    let log = Rc::clone(calls);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params));
        ready(answer())
    }
}


fn findings_fake(calls: &Calls, answer: fn() -> FindingsAnswer) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<FindingsAnswer> {
    let log = Rc::clone(calls);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params));
        ready(answer())
    }
}


const STRAY_KIND: i32 = 7;


const LOADED_LIMIT: usize = 4_096;


#[tokio::test]
async fn two_statements_both_bind_the_tenant_first() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs = runs_fake(&calls, || Ok(vec![run("a", FROM)]));
    let mut finds = findings_fake(&calls, || Ok(vec![found("a", 1, FOUR_MATCHES, false)]));
    let packs = [pack_of("b", "T1071"), pack_of("a", "T1059"), pack_of("a", "T1059")];
    let report = coverage_report_of(&mut runs, &mut finds, &packs).await?;
    assert_eq!(report.entries.first().ok_or("entry")?.matches, FOUR_MATCHES);
    let seen = calls.borrow().clone();
    let ids = Param::Text("a,b".to_owned());
    assert_eq!(
        seen,
        vec![
            ("acme".to_owned(), RUNS_SQL, vec![ids.clone()]),
            ("acme".to_owned(), FINDINGS_SQL, vec![Param::Int(FROM), Param::Int(TO), ids]),
        ]
    );
    assert_eq!(joined_ids(&[]), "");
    Ok(())
}


async fn coverage_report_of(
    runs: &mut impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<RunsAnswer>,
    finds: &mut impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<FindingsAnswer>,
    packs: &[HuntPack],
) -> Result<hunt_packs::coverage::CoverageReport, CoverageError> {
    read_coverage(runs, finds, "acme", packs, &PERIOD).await
}


const FOUR_MATCHES: i64 = 4;


#[test]
fn the_statements_bind_the_tenant_and_only_the_loaded_ids() -> TestResult {
    assert!(RUNS_SQL.contains("WHERE tenant = $1 AND pack_id = ANY(string_to_array($2, ','))"));
    assert!(FINDINGS_SQL.contains(
        "WHERE tenant = $1 AND window_end >= $2 AND window_end < $3 AND octet_length(pack_id) <= 64 AND pack_id = ANY(string_to_array($4, ','))"
    ));
    assert_eq!(FINDINGS_SQL.matches("octet_length(pack_id) <= 64").count(), TWO_UNKNOWN);
    assert_eq!(RUNS_SQL.matches("octet_length(pack_id) <= 64").count(), 1);
    assert_eq!(RUNS_SQL.matches("tenant = $1").count(), THREE_SKIPPED);
    assert_eq!(FINDINGS_SQL.matches("tenant = $1").count(), THREE_SKIPPED);
    assert_eq!(RUNS_SQL.matches("<> ALL(string_to_array($2, ','))").count(), 1);
    assert_eq!(FINDINGS_SQL.matches("<> ALL(string_to_array($4, ','))").count(), 1);
    Ok(())
}


#[test]
fn the_findings_statement_keeps_negative_rows_out_of_the_sum() -> TestResult {
    assert!(FINDINGS_SQL.contains("sum(matches) FILTER (WHERE matches >= 0)::numeric"));
    assert!(FINDINGS_SQL.contains("count(*) FILTER (WHERE matches < 0)"));
    assert!(FINDINGS_SQL.contains("window_end >= $2 AND window_end < $3"));
    assert!(FINDINGS_SQL.contains("LEAST(COALESCE(sum(matches) FILTER (WHERE matches >= 0)::numeric, 0), 9223372036854775807)"));
    Ok(())
}


#[test]
fn both_statements_count_oversized_and_unknown_ids() -> TestResult {
    assert!(RUNS_SQL.ends_with("octet_length(pack_id) > 64"));
    assert!(FINDINGS_SQL.ends_with("octet_length(pack_id) > 64"));
    assert!(RUNS_SQL.contains("octet_length(pack_id) <= 64 AND pack_id <> ALL"));
    assert!(FINDINGS_SQL.contains("octet_length(pack_id) <= 64 AND pack_id <> ALL"));
    Ok(())
}


#[tokio::test]
async fn more_loaded_packs_than_the_limit_are_refused_before_any_statement() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds = findings_fake(&calls, || Ok(Vec::new()));
    let packs: Vec<HuntPack> = (0..=LOADED_LIMIT).map(|index| pack_of(&format!("p{index}"), "T1059")).collect();
    let refused = coverage_report_of(&mut runs, &mut finds, &packs).await;
    assert!(matches!(refused, Err(CoverageError::TooManyPacks { count }) if count == LOADED_LIMIT + 1));
    assert!(calls.borrow().is_empty());
    let at_limit: Vec<HuntPack> = packs.into_iter().take(LOADED_LIMIT).collect();
    assert!(coverage_report_of(&mut runs, &mut finds, &at_limit).await.is_ok());
    assert_eq!(calls.borrow().len(), TWO_UNKNOWN);
    Ok(())
}


#[tokio::test]
async fn store_failures_and_bad_tenants_are_typed() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs_bad = runs_fake(&calls, || Err(PgError::InvalidTenant));
    let mut finds = findings_fake(&calls, || Ok(Vec::new()));
    let failed = coverage_report_of(&mut runs_bad, &mut finds, &[]).await;
    assert!(matches!(failed, Err(CoverageError::Store(StateError::Pg(_)))));
    let mut runs = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds_bad = findings_fake(&calls, || Err(PgError::InvalidTenant));
    let second = coverage_report_of(&mut runs, &mut finds_bad, &[]).await;
    assert!(matches!(second, Err(CoverageError::Store(_))));
    let before = calls.borrow().len();
    let refused = read_coverage(&mut runs, &mut finds_bad, "-x", &[], &PERIOD).await;
    assert!(matches!(refused, Err(CoverageError::Store(StateError::Pg(PgError::InvalidTenant)))));
    assert_eq!(calls.borrow().len(), before);
    Ok(())
}


fn runs_client_timeout() -> RunsAnswer {
    Err(PgError::StatementTimeout { seconds: 1 })
}


fn runs_server_timeout() -> RunsAnswer {
    Err(PgError::Server {
        code: QUERY_CANCELED.to_owned(),
        class: "operator intervention",
    })
}


fn runs_other_failure() -> RunsAnswer {
    Err(PgError::Server {
        code: "23505".to_owned(),
        class: "integrity constraint violation",
    })
}


fn finds_client_timeout() -> FindingsAnswer {
    Err(PgError::StatementTimeout { seconds: 1 })
}


fn finds_server_timeout() -> FindingsAnswer {
    Err(PgError::Server {
        code: QUERY_CANCELED.to_owned(),
        class: "operator intervention",
    })
}


fn runs_empty() -> RunsAnswer {
    Ok(Vec::new())
}


fn finds_empty() -> FindingsAnswer {
    Ok(Vec::new())
}


#[tokio::test]
async fn a_statement_deadline_is_named_with_the_period_and_the_pack_count() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let packs = [pack_of("a", "T1059"), pack_of("b", "T1071")];
    let runs_timeouts: [fn() -> RunsAnswer; TWO_UNKNOWN] = [runs_client_timeout, runs_server_timeout];
    let finds_timeouts: [fn() -> FindingsAnswer; TWO_UNKNOWN] = [finds_client_timeout, finds_server_timeout];
    for (runs_answer, finds_answer) in runs_timeouts.into_iter().zip(finds_timeouts) {
        let mut runs_slow = runs_fake(&calls, runs_answer);
        let mut finds = findings_fake(&calls, finds_empty);
        let first = coverage_report_of(&mut runs_slow, &mut finds, &packs).await;
        assert!(matches!(
            first,
            Err(CoverageError::DeadlineReached {
                from: FROM,
                to: TO,
                packs: TWO_UNKNOWN
            })
        ));
        let mut runs = runs_fake(&calls, runs_empty);
        let mut finds_slow = findings_fake(&calls, finds_answer);
        let second = coverage_report_of(&mut runs, &mut finds_slow, &packs).await;
        let message = second.err().ok_or("error")?.to_string();
        assert!(message.contains("deadline") && message.contains("2 packs") && message.contains("narrow the period"));
    }
    let mut runs_other = runs_fake(&calls, runs_other_failure);
    let mut finds = findings_fake(&calls, finds_empty);
    assert!(matches!(
        coverage_report_of(&mut runs_other, &mut finds, &packs).await,
        Err(CoverageError::Store(_))
    ));
    Ok(())
}


#[tokio::test]
async fn a_hand_built_pack_id_is_refused_before_any_statement() -> TestResult {
    let calls: Calls = Rc::new(RefCell::new(Vec::new()));
    let mut runs = runs_fake(&calls, || Ok(Vec::new()));
    let mut finds = findings_fake(&calls, || Ok(Vec::new()));
    let bad_ids = ["x,y", "", "Upper", "-x", &"a".repeat(OVER_LONG)];
    for bad in bad_ids {
        let packs = [pack_of("ok", "T1059"), pack_of(bad, "T1071")];
        let refused = coverage_report_of(&mut runs, &mut finds, &packs).await;
        assert!(matches!(refused, Err(CoverageError::BadPackId { index: 1 })), "{bad}");
    }
    assert!(calls.borrow().is_empty());
    assert_eq!(bad_pack_index(&[pack_of("ok", "T1059")]), None);
    let message = CoverageError::BadPackId { index: 1 }.to_string();
    assert!(message.contains("pack 1"));
    Ok(())
}


const RETIRED: i64 = 4_100;


const SIX_SKIPPED: u64 = 6;


const OVER_LONG: usize = 65;

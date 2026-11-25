#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::model::Alert;
use alerts::types::RowFuture;
use core_config::parse::parse_document;
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;
use std::time::Duration;
use synthetic_checks::alerting::store_outage_alerts;
use synthetic_checks::load::{text_ok, validate_check};
use synthetic_checks::model::{Check, CheckFile, CheckKind, FailureRun, RawCheck, MAX_CHECKS};
use synthetic_checks::round::{
    new_runner, placement_of, reload_checks, run_round, Placement, RoundContext, RoundReport, Runner, MAX_PENDING_OUTAGES, MAX_PROBES_PER_ROUND,
};
use types::TestResult;


const WALL_START: u64 = 1_700_000_000;


const STEP: u64 = 10;


const MANY: usize = 300;


const HUGE_WALL: u64 = 1_000_000_000_000_000;


const THREE_ROUNDS: usize = 3;


const TWO: usize = 2;


const TWO_U64: u64 = 2;


const FOUR: usize = 4;


const FIVE: usize = 5;


const SEVEN: usize = 7;


const DAY: u64 = 86_400;


const FLAP_ROUNDS: usize = 2 * MAX_PENDING_OUTAGES + 20;


const FLAP_OUTAGES: usize = FLAP_ROUNDS / 2 + 1;


const THREE_FAILURES: u64 = 3;


#[derive(Clone, Copy, PartialEq)]
pub enum StoreMode {
    Accept,
    Fail,
    AlreadyThere,
    Real,
}


pub struct Harness {
    pub mono: Cell<u64>,
    pub wall: Cell<u64>,
    pub failing: RefCell<BTreeSet<String>>,
    pub probed: RefCell<Vec<String>>,
    pub stored: RefCell<Vec<Vec<Alert>>>,
    pub mode: Cell<StoreMode>,
    pub stop_after: Cell<usize>,
    pub rows: Mutex<BTreeSet<String>>,
}


pub fn harness() -> Harness {
    Harness {
        mono: Cell::new(STEP),
        wall: Cell::new(WALL_START),
        failing: RefCell::new(BTreeSet::new()),
        probed: RefCell::new(Vec::new()),
        stored: RefCell::new(Vec::new()),
        mode: Cell::new(StoreMode::Accept),
        stop_after: Cell::new(usize::MAX),
        rows: Mutex::new(BTreeSet::new()),
    }
}


pub fn fail(harness: &Harness, names: &[&str]) {
    *harness.failing.borrow_mut() = names.iter().map(|name| (*name).to_owned()).collect();
}


pub fn checks_text(names: &[String], interval: u64, failures: u64, target: &str, locations: &str) -> String {
    let items: String = names
        .iter()
        .map(|name| {
            format!(
                "  - name: {name}\n    kind: tcp\n    target: {target}\n    interval_seconds: {interval}\n    consecutive_failures: {failures}\n    locations: {locations}\n"
            )
        })
        .collect();
    format!("checks:\n{items}")
}


pub fn checks(names: &[&str], interval: u64, failures: u64, target: &str, locations: &str) -> Result<Vec<Check>, Box<dyn std::error::Error>> {
    let owned: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    let file: CheckFile = parse_document(&checks_text(&owned, interval, failures, target, locations), "checks.yaml")?;
    Ok(file.checks)
}


pub fn simple(names: &[&str]) -> Result<Vec<Check>, Box<dyn std::error::Error>> {
    checks(names, STEP, TWO_U64, "x:1", "[paris]")
}


pub fn prepared(names: &[&str]) -> Result<(Runner, TenantScope), Box<dyn std::error::Error>> {
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    reload_checks(&mut runner, &simple(names)?)?;
    Ok((runner, scope))
}


pub fn real_store(rows_store: &Mutex<BTreeSet<String>>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let executor = |_scope: TenantScope, _sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        let docs: Result<Vec<Value>, PgError> = params
            .first()
            .ok_or(PgError::InvalidTenant)
            .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant));
        let answer = docs.and_then(|list| {
            let mut rows = rows_store.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
            let new = list
                .iter()
                .filter_map(|doc| doc.get("id").and_then(Value::as_str))
                .filter(|id| rows.insert((*id).to_owned()))
                .count();
            Ok(vec![vec![new.to_string()]])
        });
        Box::pin(ready(answer))
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_bad| StoreError::TenantMismatch)?;
    runtime.block_on(store_outage_alerts(&executor, scope, alerts))
}


pub fn round(harness: &Harness, runner: &mut Runner, scope: &TenantScope) -> RoundReport {
    let seen = Cell::new(usize::default());
    let clock = || Duration::from_secs(harness.mono.get());
    let wall = || harness.wall.get();
    let probe = |check: &Check| {
        harness.probed.borrow_mut().push(check.name.clone());
        !harness.failing.borrow().contains(&check.name)
    };
    let store = |alerts: &[Alert]| match harness.mode.get() {
        StoreMode::Fail => Err(StoreError::TenantMismatch),
        StoreMode::AlreadyThere => Ok(0),
        StoreMode::Real => real_store(&harness.rows, scope, alerts),
        StoreMode::Accept => {
            harness.stored.borrow_mut().push(alerts.to_vec());
            Ok(alerts.len())
        }
    };
    let stopped = || {
        seen.set(seen.get() + 1);
        seen.get() > harness.stop_after.get()
    };
    let context = RoundContext {
        scope,
        clock: &clock,
        wall: &wall,
        probe: &probe,
        store: &store,
        stopped: &stopped,
    };
    let report = run_round(runner, &context);
    harness.mono.set(harness.mono.get() + STEP);
    harness.wall.set(harness.wall.get() + STEP);
    report
}


pub fn rounds(harness: &Harness, runner: &mut Runner, scope: &TenantScope, count: usize) -> Vec<RoundReport> {
    (0..count).map(|_i| round(harness, runner, scope)).collect()
}


pub fn stored_count(harness: &Harness) -> usize {
    harness.stored.borrow().iter().map(Vec::len).sum()
}


#[test]
fn outage_raised_once_with_the_run_start_not_the_ring() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    fail(&harness, &["web"]);
    let reports = rounds(&harness, &mut runner, &scope, FIVE);
    assert_eq!(stored_count(&harness), 1);
    assert_eq!(reports.iter().map(|report| report.stored).sum::<usize>(), 1);
    let alert = harness
        .stored
        .borrow()
        .first()
        .and_then(|batch| batch.first())
        .cloned()
        .ok_or("no alert")?;
    assert_eq!(alert.event_ids.get(1), Some(&format!("since:{WALL_START}")));
    assert_eq!(runner.counters.outages_stored, 1);
    assert_eq!(runner.counters.probes, FIVE as u64);
    Ok(())
}


#[test]
fn recovery_clears_the_outage_and_a_later_failure_raises_again() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, THREE_ROUNDS);
    fail(&harness, &[]);
    round(&harness, &mut runner, &scope);
    let state = runner.states.first().ok_or("no state")?;
    assert!(!state.raised && state.run_started.is_none());
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, THREE_ROUNDS);
    assert_eq!(stored_count(&harness), TWO);
    Ok(())
}


#[test]
fn a_failing_store_keeps_the_pending_outage_even_after_recovery() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    fail(&harness, &["web"]);
    let reports = rounds(&harness, &mut runner, &scope, THREE_ROUNDS);
    assert!(reports.iter().skip(1).all(|report| report.store_failed && report.pending == 1));
    assert!(!runner.states.first().ok_or("no state")?.raised);
    fail(&harness, &[]);
    round(&harness, &mut runner, &scope);
    assert_eq!(runner.pending.len(), 1);
    assert_eq!(runner.counters.store_failures, THREE_ROUNDS as u64);
    harness.mode.set(StoreMode::Accept);
    let report = round(&harness, &mut runner, &scope);
    assert_eq!((report.stored, report.pending), (1, 0));
    assert_eq!(stored_count(&harness), 1);
    Ok(())
}


#[test]
fn a_pending_outage_survives_the_removal_of_its_check() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, TWO);
    let report = reload_checks(&mut runner, &[])?;
    assert_eq!(report.removed, 1);
    harness.mode.set(StoreMode::Accept);
    round(&harness, &mut runner, &scope);
    assert_eq!(stored_count(&harness), 1);
    assert!(runner.states.is_empty() && runner.pending.is_empty());
    Ok(())
}


#[test]
fn an_answer_of_zero_is_outage_already_stored() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::AlreadyThere);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, FOUR);
    assert_eq!(runner.counters.outage_already_stored, 1);
    assert!(runner.states.first().ok_or("no state")?.raised);
    Ok(())
}


#[test]
fn the_fair_cap_runs_the_most_overdue_first_and_every_check_in_the_end() -> TestResult {
    let names: Vec<String> = (0..MANY).map(|i| format!("c{i:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let (mut runner, scope) = prepared(&refs)?;
    let harness = harness();
    let first = round(&harness, &mut runner, &scope);
    assert_eq!(
        (first.due, first.probed, first.deferred),
        (MANY, MAX_PROBES_PER_ROUND, MANY - MAX_PROBES_PER_ROUND)
    );
    assert_eq!((first.largest_overdue, first.never_run), (Duration::ZERO, MANY));
    let probed_first: Vec<String> = harness.probed.borrow().clone();
    assert_eq!(probed_first, names.iter().take(MAX_PROBES_PER_ROUND).cloned().collect::<Vec<_>>());
    let second = round(&harness, &mut runner, &scope);
    assert_eq!((second.never_run, second.largest_overdue), (MANY - MAX_PROBES_PER_ROUND, Duration::ZERO));
    rounds(&harness, &mut runner, &scope, MANY / MAX_PROBES_PER_ROUND);
    let seen: BTreeSet<String> = harness.probed.borrow().iter().cloned().collect();
    assert!(seen.contains(names.last().ok_or("no names")?));
    assert!(runner.counters.deferred >= first.deferred as u64);
    Ok(())
}


#[test]
fn the_tail_check_is_probed_in_round_two_before_a_repeat() -> TestResult {
    let names: Vec<String> = (0..=MAX_PROBES_PER_ROUND).map(|i| format!("c{i:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let (mut runner, scope) = prepared(&refs)?;
    let harness = harness();
    round(&harness, &mut runner, &scope);
    harness.probed.borrow_mut().clear();
    round(&harness, &mut runner, &scope);
    let second: Vec<String> = harness.probed.borrow().clone();
    assert_eq!(second.first(), names.last());
    assert_eq!(second.len(), MAX_PROBES_PER_ROUND);
    Ok(())
}


#[test]
fn a_check_is_probed_again_only_after_its_interval() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    reload_checks(&mut runner, &checks(&["web"], THREE_ROUNDS as u64 * STEP, TWO_U64, "x:1", "[paris]")?)?;
    let harness = harness();
    let counts: Vec<usize> = rounds(&harness, &mut runner, &scope, SEVEN).iter().map(|report| report.probed).collect();
    assert_eq!(counts, [1, 0, 0, 1, 0, 0, 1]);
    harness.mono.set(0);
    let backwards = round(&harness, &mut runner, &scope);
    assert_eq!((backwards.due, backwards.largest_overdue), (0, Duration::ZERO));
    Ok(())
}


#[test]
fn the_stop_flag_is_read_between_probes() -> TestResult {
    let (mut runner, scope) = prepared(&["a", "b", "c"])?;
    let harness = harness();
    harness.stop_after.set(1);
    let report = round(&harness, &mut runner, &scope);
    assert_eq!((report.due, report.probed, report.deferred), (THREE_ROUNDS, 1, TWO));
    assert_eq!(harness.probed.borrow().len(), 1);
    Ok(())
}


#[test]
fn every_current_run_keeps_its_own_slot_beyond_the_shared_cap() -> TestResult {
    let names: Vec<String> = (0..MANY).map(|i| format!("c{i:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    reload_checks(&mut runner, &checks(&refs, STEP, 1, "x:1", "[paris]")?)?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    *harness.failing.borrow_mut() = names.iter().cloned().collect();
    rounds(&harness, &mut runner, &scope, MANY / MAX_PROBES_PER_ROUND + TWO);
    assert_eq!(runner.pending.len(), MANY);
    assert_eq!(runner.counters.pending_dropped, 0);
    Ok(())
}


#[test]
fn a_flapping_check_cannot_evict_another_checks_single_outage() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    let mut both = checks(&["flap"], STEP, 1, "x:1", "[paris]")?;
    both.extend(checks(&["steady"], DAY, 1, "x:1", "[paris]")?);
    reload_checks(&mut runner, &both)?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    (0..FLAP_ROUNDS).for_each(|k| {
        let failing: &[&str] = if k % TWO == 0 { &["flap", "steady"] } else { &["steady"] };
        fail(&harness, failing);
        round(&harness, &mut runner, &scope);
    });
    assert!(runner.counters.pending_dropped > 0);
    assert_eq!(runner.counters.pending_dropped as usize + runner.pending.len(), FLAP_OUTAGES);
    assert_eq!(runner.pending.iter().filter(|outage| outage.check == "steady").count(), 1);
    assert!(runner.pending.len() <= MAX_PENDING_OUTAGES + TWO);
    harness.mode.set(StoreMode::Accept);
    let last = round(&harness, &mut runner, &scope);
    assert_eq!(last.pending_dropped, 0);
    assert_eq!(stored_count(&harness) + runner.counters.pending_dropped as usize, FLAP_OUTAGES);
    let steady_stored = harness
        .stored
        .borrow()
        .iter()
        .flatten()
        .filter(|alert| alert.event_ids.first().is_some_and(|id| id == "check:steady"))
        .count();
    assert_eq!(steady_stored, 1);
    assert!(runner
        .states
        .iter()
        .filter(|state| state.check.name == "steady")
        .all(|state| state.raised));
    Ok(())
}


#[test]
fn a_recovered_check_keeps_its_outage_while_another_flaps() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    let mut both = checks(&["flap"], STEP, 1, "x:1", "[paris]")?;
    both.extend(checks(&["steady"], STEP, 1, "x:1", "[paris]")?);
    reload_checks(&mut runner, &both)?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    (0..FLAP_ROUNDS).for_each(|k| {
        let failing: &[&str] = match (k, k % TWO) {
            (0, _) => &["flap", "steady"],
            (_, 0) => &["flap"],
            _ => &[],
        };
        fail(&harness, failing);
        round(&harness, &mut runner, &scope);
    });
    assert!(runner.counters.pending_dropped > 0);
    assert_eq!(runner.counters.pending_dropped as usize + runner.pending.len(), FLAP_OUTAGES);
    assert!(runner
        .states
        .iter()
        .all(|state| state.run_started.is_none() || state.check.name == "flap"));
    harness.mode.set(StoreMode::Accept);
    let last = round(&harness, &mut runner, &scope);
    assert_eq!(last.pending_dropped, 0);
    assert_eq!(stored_count(&harness) + runner.counters.pending_dropped as usize, FLAP_OUTAGES);
    let steady_stored = harness
        .stored
        .borrow()
        .iter()
        .flatten()
        .filter(|alert| alert.event_ids.first().is_some_and(|id| id == "check:steady"))
        .count();
    assert_eq!(steady_stored, 1);
    Ok(())
}


#[test]
fn a_kind_change_in_the_same_second_never_merges_two_outages() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, TWO);
    let changed: Vec<Check> = simple(&["web"])?
        .into_iter()
        .map(|check| Check {
            kind: CheckKind::Icmp,
            target: "127.0.0.1".to_owned(),
            ..check
        })
        .collect();
    reload_checks(&mut runner, &changed)?;
    harness.wall.set(WALL_START);
    harness.mono.set(harness.mono.get() + DAY);
    let report = rounds(&harness, &mut runner, &scope, TWO).pop().ok_or("no round")?;
    assert_eq!(report.pending, TWO);
    harness.mode.set(StoreMode::Accept);
    let stored = round(&harness, &mut runner, &scope);
    assert_eq!((stored.stored, stored.pending), (TWO, 0));
    assert!(runner.states.iter().all(|state| state.raised));
    Ok(())
}


#[test]
fn a_duplicate_check_name_is_refused_and_nothing_changes() -> TestResult {
    let (mut runner, _scope) = prepared(&["web"])?;
    let mut twice = simple(&["a"])?;
    twice.extend(simple(&["a"])?);
    assert!(reload_checks(&mut runner, &twice).is_err());
    assert_eq!(runner.states.len(), 1);
    assert_eq!(runner.states.first().map(|state| state.check.name.as_str()), Some("web"));
    Ok(())
}


#[test]
fn an_outage_whose_time_does_not_fit_the_store_is_dropped_and_counted() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.wall.set(HUGE_WALL);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, THREE_ROUNDS);
    assert_eq!(runner.counters.outages_rejected, TWO as u64);
    assert!(runner.pending.is_empty() && harness.stored.borrow().is_empty());
    Ok(())
}


#[test]
fn placement_fails_closed_for_several_or_foreign_locations() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    let mut all = checks(&["solo"], STEP, TWO_U64, "x:1", "[paris]")?;
    all.extend(checks(&["pair"], STEP, TWO_U64, "x:1", "[paris, oslo]")?);
    all.extend(checks(&["far"], STEP, TWO_U64, "x:1", "[oslo]")?);
    all.extend(checks(&["far2"], STEP, TWO_U64, "x:1", "[oslo, rome]")?);
    let report = reload_checks(&mut runner, &all)?;
    assert_eq!((report.needs_other_locations, report.other_location, report.added), (1, TWO, FOUR));
    let found: Vec<Placement> = all.iter().map(|check| placement_of(check, "paris")).collect();
    assert_eq!(
        found,
        [
            Placement::Runs,
            Placement::NeedsOtherLocations,
            Placement::OtherLocation,
            Placement::OtherLocation
        ]
    );
    let harness = harness();
    fail(&harness, &["solo", "pair", "far", "far2"]);
    rounds(&harness, &mut runner, &scope, THREE_ROUNDS);
    assert!(harness.probed.borrow().iter().all(|name| name == "solo"));
    assert_eq!(stored_count(&harness), 1);
    Ok(())
}


#[test]
fn reload_keeps_state_on_timing_changes_and_resets_on_any_other_change() -> TestResult {
    let (mut runner, scope) = prepared(&["web", "gone"])?;
    let harness = harness();
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, TWO);
    assert!(runner.states.iter().any(|state| state.raised));
    let timing = checks(&["web"], TWO_U64 * STEP, TWO_U64, "x:1", "[paris]")?;
    let report = reload_checks(&mut runner, &timing)?;
    assert_eq!((report.kept, report.reset, report.removed, report.added), (1, 0, 1, 0));
    let state = runner.states.first().ok_or("no state")?;
    assert!(state.raised && state.run_started.is_some() && state.check.interval_seconds == TWO_U64 * STEP);
    let moved = checks(&["web"], TWO_U64 * STEP, TWO_U64, "y:2", "[paris]")?;
    let changed = reload_checks(&mut runner, &moved)?;
    assert_eq!((changed.kept, changed.reset), (0, 1));
    let reset = runner.states.first().ok_or("no state")?;
    assert!(!reset.raised && reset.run_started.is_none() && reset.ring.is_empty() && reset.last_start.is_none());
    Ok(())
}


#[test]
fn the_runner_location_must_be_ascii_text() -> TestResult {
    let scope = tenant_scope("acme")?;
    let refused: Vec<bool> = ["", "pa\nris", "pari\u{df}", "a\u{7}"]
        .iter()
        .map(|location| new_runner(&scope, location).is_err())
        .collect();
    assert_eq!(refused, [true, true, true, true]);
    assert!(new_runner(&scope, "paris").is_ok());
    Ok(())
}


pub fn raw(name: &str, target: &str, location: &str) -> RawCheck {
    RawCheck {
        name: name.to_owned(),
        kind: CheckKind::Tcp,
        target: target.to_owned(),
        interval_seconds: STEP,
        timeout_seconds: 1,
        consecutive_failures: 1,
        locations: vec![location.to_owned()],
        min_failing_locations: 1,
        certificate_days: vec![1],
        nat64_prefix: None,
    }
}


#[test]
fn control_characters_are_refused_in_names_targets_and_locations() -> TestResult {
    assert!(validate_check(raw("a", "x:1", "p")).is_ok());
    assert!(validate_check(raw("a\nb", "x:1", "p")).is_err());
    assert!(validate_check(raw("a", "x\n\n:1", "p")).is_err());
    assert!(validate_check(raw("a", "x:1", "p\nq")).is_err());
    assert!(text_ok("name", "a\nb", STEP as usize).is_err());
    let blank_line = "checks:\n  - name: \"a\n\n    b\"\n    kind: tcp\n    target: x:1\n    locations: [paris]\n";
    let parsed: Result<CheckFile, _> = parse_document(blank_line, "checks.yaml");
    assert!(parsed.is_err());
    Ok(())
}


#[test]
fn the_real_store_dedupes_a_retried_outage_and_stores_each_run_once() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Real);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, FIVE);
    assert_eq!(harness.rows.lock().map_err(|_poisoned| "poisoned")?.len(), 1);
    assert_eq!(runner.counters.outages_stored, 1);
    Ok(())
}


#[test]
fn a_stored_outage_never_raises_the_reset_check_that_replaced_its_run() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, TWO);
    reload_checks(&mut runner, &checks(&["web"], STEP, TWO_U64, "y:2", "[paris]")?)?;
    harness.mode.set(StoreMode::Accept);
    round(&harness, &mut runner, &scope);
    assert_eq!(stored_count(&harness), 1);
    assert!(!runner.states.first().ok_or("no state")?.raised);
    Ok(())
}


#[test]
fn a_dropped_pending_outage_is_reported_by_the_round() -> TestResult {
    let names: Vec<String> = (0..TWO).map(|i| format!("c{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    reload_checks(&mut runner, &checks(&refs, STEP, 1, "x:1", "[paris]")?)?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    let dropped: usize = (0..FLAP_ROUNDS)
        .map(|k| {
            let failing: &[&str] = if k % TWO == 0 { &["c0", "c1"] } else { &["c1"] };
            fail(&harness, failing);
            round(&harness, &mut runner, &scope).pending_dropped
        })
        .sum();
    assert_eq!(dropped as u64, runner.counters.pending_dropped);
    assert!(dropped > 0);
    Ok(())
}


#[test]
fn a_kind_change_with_the_same_run_start_is_still_alerted_later() -> TestResult {
    let (mut runner, scope) = prepared(&["web"])?;
    let harness = harness();
    harness.mode.set(StoreMode::Fail);
    fail(&harness, &["web"]);
    rounds(&harness, &mut runner, &scope, TWO);
    let three = FailureRun::try_from(THREE_FAILURES)?;
    let changed: Vec<Check> = simple(&["web"])?
        .into_iter()
        .map(|check| Check {
            kind: CheckKind::Icmp,
            target: "127.0.0.1".to_owned(),
            consecutive_failures: three,
            ..check
        })
        .collect();
    reload_checks(&mut runner, &changed)?;
    harness.wall.set(WALL_START);
    harness.mono.set(harness.mono.get() + DAY);
    harness.mode.set(StoreMode::Accept);
    rounds(&harness, &mut runner, &scope, THREE_ROUNDS + 1);
    assert_eq!(stored_count(&harness), TWO);
    Ok(())
}


#[test]
fn more_than_the_maximum_checks_are_refused_by_the_reload() -> TestResult {
    let template = simple(&["a"])?.into_iter().next().ok_or("no check")?;
    let many: Vec<Check> = (0..=MAX_CHECKS)
        .map(|i| Check {
            name: format!("c{i}"),
            ..template.clone()
        })
        .collect();
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    assert!(reload_checks(&mut runner, &many).is_err());
    assert!(runner.states.is_empty());
    Ok(())
}

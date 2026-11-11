mod common;


use alerts::types::RowFuture;
use common::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::error::RuleError;
use metric_alerts::fetch::{FetchError, LineFaults};
use metric_alerts::model::{Capacity, Condition, Direction, Rule, RuleFile, Severity};
use metric_alerts::query::MetricQuery;
use metric_alerts::round::{class_of, evaluate_round, store_round, RoundFault, RoundStates, MAX_ROUND_STATES};
use metric_alerts::state::AlertState;
use metric_alerts::types::{FetchResult, Point};
use serde_json::Value;
use siem_ingest::error::InsertClass;
use siem_schema::metrics::MetricsRetention;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::io;
use std::sync::Mutex;


const NOW: u64 = 1_700_000_000;


const STEP: u64 = 60;


const HOLD: u64 = 120;


const CAPACITY_VALUE: f64 = 1000.0;


const FORECAST_WINDOW: u64 = 600;


const FORECAST_POINTS: u64 = 10;


const FORECAST_GROWTH: f64 = 10.0;


const BREACH: f64 = 95.0;


const THRESHOLD: f64 = 90.0;


const HORIZON: u64 = 6000;


const MIN_CONFIDENCE: f64 = 0.9;


const MIN_POINTS: usize = 5;


const TWO: usize = 2;


const SELECTOR_COUNT: usize = 17;


struct Fake {
    seen: Mutex<Vec<MetricQuery>>,
    script: Box<dyn Fn(&MetricQuery) -> FetchResult>,
}


fn fake(script: Box<dyn Fn(&MetricQuery) -> FetchResult>) -> Fake {
    Fake {
        seen: Mutex::new(Vec::new()),
        script,
    }
}


fn ask(fake: &Fake, query: &MetricQuery) -> FetchResult {
    if let Ok(mut seen) = fake.seen.lock() {
        seen.push(query.clone());
    }
    (fake.script)(query)
}


fn seen(fake: &Fake) -> Result<Vec<MetricQuery>, Box<dyn std::error::Error>> {
    Ok(fake.seen.lock().map_err(|_| "poisoned")?.clone())
}


fn param(query: &MetricQuery, name: &str) -> String {
    query
        .params
        .iter()
        .find(|(key, _)| key == name)
        .map_or_else(String::new, |(_, value)| value.clone())
}


fn rule(id: &str, metric: &str, condition: Condition, hold_for: u64) -> Rule {
    Rule {
        id: id.to_owned(),
        metric: metric.to_owned(),
        selector: BTreeMap::new(),
        condition,
        hold_for,
        close_after: STEP,
        severity: Severity::High,
        labels: BTreeMap::new(),
        runbook: "https://r.example.org".to_owned(),
    }
}


fn threshold(id: &str, hold_for: u64) -> Rule {
    rule(
        id,
        "disk.used",
        Condition::Threshold {
            direction: Direction::Above,
            threshold: THRESHOLD,
            clear: None,
        },
        hold_for,
    )
}


fn forecast(capacity: Capacity) -> Rule {
    rule(
        "full",
        "disk.used",
        Condition::Forecast {
            window: FORECAST_WINDOW,
            capacity,
            horizon: HORIZON,
            min_confidence: MIN_CONFIDENCE,
            min_points: MIN_POINTS,
        },
        0,
    )
}


fn file(rules: Vec<Rule>) -> RuleFile {
    RuleFile { rules }
}


fn breaching(now: u64) -> Vec<Point> {
    vec![(now - STEP, BREACH), (now, BREACH)]
}


fn tenant_series(query: &MetricQuery) -> FetchResult {
    Ok(if param(query, "tenant") == "a" { breaching(NOW) } else { Vec::new() })
}


fn unavailable() -> FetchResult {
    Err(FetchError::Failed(InsertClass::Unavailable))
}


#[test]
fn a_threshold_fires_after_the_hold_over_three_rounds() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![threshold("disk", HOLD)]);
    let settings = MetricsRetention::default();
    let mut states = RoundStates::default();
    let source = fake(Box::new(|query| Ok(vec![(to_of(query)?, BREACH)])));
    let first = evaluate_round(&rules, &scope, NOW, &settings, &|query| ask(&source, query), &mut states)?;
    let second = evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| ask(&source, query), &mut states)?;
    let third = evaluate_round(&rules, &scope, NOW + HOLD, &settings, &|query| ask(&source, query), &mut states)?;
    assert!(first.firings.is_empty() && second.firings.is_empty());
    assert_eq!(third.firings.len(), 1);
    let firing = third.firings.first().ok_or("no firing")?;
    assert_eq!((firing.since, firing.rule_id.as_str()), (NOW, "disk"));
    assert_eq!(tenant_of(&firing.tenant), "acme");
    assert_eq!(third.counts.evaluated, 1);
    assert!(third.counts.fetch_failures.is_empty());
    Ok(())
}


#[test]
fn a_failed_fetch_keeps_the_previous_state_and_the_other_rules_run() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![
        threshold("disk", HOLD),
        rule("quiet", "cpu", Condition::Absence { interval: STEP }, 0),
    ]);
    let settings = MetricsRetention::default();
    let mut states = RoundStates::default();
    let good = fake(Box::new(|query| Ok(breaching(to_of(query)?))));
    evaluate_round(&rules, &scope, NOW, &settings, &|query| ask(&good, query), &mut states)?;
    let bad = fake(Box::new(|query| {
        if param(query, "metric") == "disk.used" {
            unavailable()
        } else {
            Ok(breaching(NOW + STEP))
        }
    }));
    let second = evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| ask(&bad, query), &mut states)?;
    assert_eq!(second.counts.fetch_failures.get("unavailable"), Some(&1));
    assert_eq!(second.counts.evaluated, 1);
    assert!(states.states.values().any(|state| *state == AlertState::Pending { since: NOW - STEP }));
    let third = evaluate_round(&rules, &scope, NOW + HOLD, &settings, &|query| ask(&good, query), &mut states)?;
    assert_eq!(third.firings.len(), 1);
    assert!(third.counts.fetch_failures.is_empty());
    Ok(())
}


#[test]
fn a_failed_fetch_never_resolves_a_firing_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![threshold("disk", 0)]);
    let settings = MetricsRetention::default();
    let mut states = RoundStates::default();
    let good = fake(Box::new(|query| Ok(breaching(to_of(query)?))));
    let first = evaluate_round(&rules, &scope, NOW, &settings, &|query| ask(&good, query), &mut states)?;
    let bad = fake(Box::new(|_| unavailable()));
    let second = evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| ask(&bad, query), &mut states)?;
    assert_eq!(first.firings, second.firings);
    assert!(states.states.values().all(|state| matches!(state, AlertState::Firing { .. })));
    Ok(())
}


fn forecast_script(capacity: Option<f64>) -> Box<dyn Fn(&MetricQuery) -> FetchResult> {
    Box::new(move |query| {
        Ok(if param(query, "metric") == "disk.total" {
            capacity.map_or_else(Vec::new, |value| vec![(NOW, value)])
        } else {
            (0..=FORECAST_POINTS)
                .map(|step| (NOW - FORECAST_WINDOW + step * STEP, FORECAST_GROWTH * step as f64))
                .collect()
        })
    })
}


#[test]
fn a_metric_capacity_is_fetched_with_the_last_value() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![forecast(Capacity::Metric {
        name: "disk.total".to_owned(),
    })]);
    let source = fake(forecast_script(Some(CAPACITY_VALUE)));
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &rules,
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| ask(&source, query),
        &mut states,
    )?;
    let queries = seen(&source)?;
    assert_eq!(queries.len(), TWO);
    let capacity = queries.get(1).ok_or("no capacity query")?;
    assert_eq!(param(capacity, "metric"), "disk.total");
    assert!(capacity.sql.contains("anyLast"));
    assert_eq!(outcome.firings.len(), 1);
    assert_eq!(outcome.counts.capacity_missing, 0);
    Ok(())
}


#[test]
fn a_missing_capacity_holds_nothing() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![forecast(Capacity::Metric {
        name: "disk.total".to_owned(),
    })]);
    let source = fake(forecast_script(None));
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &rules,
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert!(outcome.firings.is_empty());
    assert_eq!((outcome.counts.capacity_missing, outcome.counts.evaluated), (1, 1));
    Ok(())
}


#[test]
fn a_capacity_fetch_failure_counts_and_keeps_the_state() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![forecast(Capacity::Metric {
        name: "disk.total".to_owned(),
    })]);
    let source = fake(Box::new(|query| {
        if param(query, "metric") == "disk.total" {
            unavailable()
        } else {
            Ok(Vec::new())
        }
    }));
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &rules,
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert_eq!(outcome.counts.fetch_failures.get("unavailable"), Some(&1));
    assert_eq!(outcome.counts.evaluated, 0);
    Ok(())
}


#[test]
fn two_tenants_never_share_states_or_firings() -> TestResult {
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let rules = file(vec![threshold("disk", 0)]);
    let settings = MetricsRetention::default();
    let source = fake(Box::new(tenant_series));
    let mut states_a = RoundStates::default();
    let mut states_b = RoundStates::default();
    let outcome_a = evaluate_round(&rules, &scope_a, NOW, &settings, &|query| ask(&source, query), &mut states_a)?;
    let outcome_b = evaluate_round(&rules, &scope_b, NOW, &settings, &|query| ask(&source, query), &mut states_b)?;
    assert_eq!(outcome_a.firings.len(), 1);
    assert!(outcome_b.firings.is_empty());
    assert!(outcome_a.firings.iter().all(|firing| tenant_of(&firing.tenant) == "a"));
    assert_ne!(states_a, states_b);
    let tenants: Vec<String> = seen(&source)?.iter().map(|query| param(query, "tenant")).collect();
    assert_eq!(tenants, vec!["a".to_owned(), "b".to_owned()]);
    Ok(())
}


#[test]
fn rules_beyond_the_state_cap_are_counted_and_evaluated_from_inactive() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file((0..=MAX_ROUND_STATES).map(|index| threshold(&format!("r{index}"), 0)).collect());
    let source = fake(Box::new(|query| Ok(breaching(to_of(query)?))));
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &rules,
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert_eq!(outcome.counts.skipped_by_cap, 1);
    assert_eq!(states.states.len(), MAX_ROUND_STATES);
    assert_eq!(outcome.firings.len(), MAX_ROUND_STATES + 1);
    Ok(())
}


#[test]
fn a_rule_that_left_the_file_leaves_the_states() -> TestResult {
    let scope = tenant_scope("acme")?;
    let settings = MetricsRetention::default();
    let source = fake(Box::new(|query| Ok(breaching(to_of(query)?))));
    let mut states = RoundStates::default();
    evaluate_round(
        &file(vec![threshold("one", 0), threshold("two", 0)]),
        &scope,
        NOW,
        &settings,
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert_eq!(states.states.len(), TWO);
    evaluate_round(
        &file(vec![threshold("one", 0)]),
        &scope,
        NOW,
        &settings,
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert_eq!(states.states.len(), 1);
    Ok(())
}


#[test]
fn a_rule_that_cannot_compile_is_counted_without_a_fetch() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut bad = threshold("bad", 0);
    bad.selector = (0..SELECTOR_COUNT).map(|index| (format!("l{index}"), "v".to_owned())).collect();
    let source = fake(Box::new(|_| Ok(Vec::new())));
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &file(vec![bad]),
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| ask(&source, query),
        &mut states,
    )?;
    assert_eq!(outcome.counts.fetch_failures.get("query"), Some(&1));
    assert!(seen(&source)?.is_empty());
    Ok(())
}


#[test]
fn every_failure_has_a_fixed_class() -> TestResult {
    let fetch = |error: FetchError| class_of(&RoundFault::Fetch(error));
    assert_eq!(fetch(FetchError::Failed(InsertClass::ParseError)), "parse_error");
    assert_eq!(fetch(FetchError::Failed(InsertClass::Unavailable)), "unavailable");
    assert_eq!(fetch(FetchError::Failed(InsertClass::Timeout)), "timeout");
    assert_eq!(fetch(FetchError::Failed(InsertClass::Unauthorized)), "unauthorized");
    assert_eq!(fetch(FetchError::Failed(InsertClass::Rejected)), "rejected");
    assert_eq!(fetch(FetchError::Body(io::Error::other("x"))), "body");
    assert_eq!(fetch(FetchError::TooLarge), "too_large");
    assert_eq!(fetch(FetchError::TooManyPoints), "too_large");
    assert_eq!(fetch(FetchError::Malformed(LineFaults::default())), "malformed");
    assert_eq!(fetch(FetchError::User), "settings");
    assert_eq!(class_of(&RoundFault::Query(RuleError::TimeOutOfRange)), "query");
    Ok(())
}


#[derive(Default)]
struct Store {
    rows: Mutex<BTreeSet<(String, String)>>,
}


fn run(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let tenant = tenant_of(scope).to_owned();
    let new = docs
        .iter()
        .filter_map(|doc| doc.get("id").and_then(Value::as_str))
        .filter(|id| rows.insert((tenant.clone(), (*id).to_owned())))
        .count();
    Ok(vec![vec![new.to_string()]])
}


#[tokio::test]
async fn storing_a_round_twice_inserts_once() -> TestResult {
    let scope = tenant_scope("acme")?;
    let rules = file(vec![threshold("disk", 0)]);
    let source = fake(Box::new(|query| Ok(breaching(to_of(query)?))));
    let mut states = RoundStates::default();
    let settings = MetricsRetention::default();
    let outcome = evaluate_round(&rules, &scope, NOW, &settings, &|query| ask(&source, query), &mut states)?;
    let store = Store::default();
    let exec = |caller: TenantScope, _sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(run(&store, &caller, &params))) };
    let first = store_round(&exec, &scope, &outcome, NOW).await?;
    let again = evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| ask(&source, query), &mut states)?;
    let rerun = store_round(&exec, &scope, &again, NOW + STEP).await?;
    assert_eq!((first, rerun), (1, 0));
    Ok(())
}


fn to_of(query: &MetricQuery) -> Result<u64, FetchError> {
    param(query, "to").parse().map_err(|_| FetchError::TooLarge)
}

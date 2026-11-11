mod common;


use alerts::types::RowFuture;
use common::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::alerting::RULE_ID_PREFIX;
use metric_alerts::fetch::FetchError;
use metric_alerts::model::{Capacity, Condition, Direction, Rule, RuleFile, Severity};
use metric_alerts::query::MetricQuery;
use metric_alerts::recover::{candidate_of, fits, held_since, recover_states, since_of, RECOVER_SQL};
use metric_alerts::round::{evaluate_round, state_key, store_round, RoundError, RoundStates};
use metric_alerts::types::FetchResult;
use serde_json::Value;
use siem_ingest::error::InsertClass;
use siem_schema::metrics::MetricsRetention;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;


const NOW: u64 = 1_700_000_000;


const STEP: u64 = 60;


const RESTART: u64 = 600;


const FORECAST_WINDOW: u64 = 600;


const FORECAST_POINTS: u64 = 10;


const FORECAST_GROWTH: f64 = 10.0;


const CAPACITY: f64 = 1000.0;


const HORIZON: u64 = 6000;


const MIN_CONFIDENCE: f64 = 0.9;


const MIN_POINTS: usize = 5;


const THRESHOLD: f64 = 90.0;


const TWO: usize = 2;


const SAMPLE: f64 = 1.0;


const SINCE_FIRST: u64 = 42;


const STARVING_ROWS: usize = 5000;


const FUTURE: u64 = 4_000_000_000;


#[derive(Default)]
struct Store {
    rows: Mutex<Vec<(String, String, String, String)>>,
    closed: Mutex<BTreeSet<String>>,
    recoveries: Mutex<Vec<String>>,
    asked: Mutex<Vec<String>>,
    fail: AtomicBool,
    lax: AtomicBool,
}


fn insert(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let tenant = tenant_of(scope).to_owned();
    let mut new = 0;
    for doc in &docs {
        let id = doc.get("id").and_then(Value::as_str).ok_or(PgError::InvalidTenant)?.to_owned();
        let rule_id = doc.get("rule_id").and_then(Value::as_str).ok_or(PgError::InvalidTenant)?.to_owned();
        let events = doc.get("event_ids").ok_or(PgError::InvalidTenant)?.to_string();
        if !rows.iter().any(|(owner, stored, _, _)| *owner == tenant && *stored == id) {
            rows.push((tenant.clone(), id, rule_id, events));
            new += 1;
        }
    }
    Ok(vec![vec![new.to_string()]])
}


fn recover(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    store.recoveries.lock().map_err(|_poisoned| PgError::InvalidTenant)?.push(tenant.clone());
    let text = params.first().ok_or(PgError::InvalidTenant)?;
    store.asked.lock().map_err(|_poisoned| PgError::InvalidTenant)?.push(text.clone());
    let wanted: Vec<Value> = serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant)?;
    let closed = store.closed.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let lax = store.lax.load(Ordering::SeqCst);
    Ok(wanted
        .iter()
        .filter_map(|entry| {
            let rule_id = entry.get("rule_id").and_then(Value::as_str)?;
            let series = entry.get("series").and_then(Value::as_str)?;
            rows.iter()
                .rev()
                .find(|(owner, id, stored_rule, events)| {
                    *owner == tenant && !closed.contains(id) && (lax || (stored_rule == rule_id && events.contains(&format!("\"{series}\""))))
                })
                .map(|(_, _, stored_rule, events)| vec![stored_rule.clone(), events.clone()])
        })
        .collect())
}


fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        if store.fail.load(Ordering::SeqCst) {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else if sql == RECOVER_SQL {
            Box::pin(ready(recover(store, &scope, &params)))
        } else {
            Box::pin(ready(insert(store, &scope, &params)))
        }
    }
}


fn rule(id: &str, condition: Condition) -> Rule {
    Rule {
        id: id.to_owned(),
        metric: "disk.used".to_owned(),
        selector: BTreeMap::new(),
        condition,
        hold_for: 0,
        close_after: STEP,
        severity: Severity::High,
        labels: BTreeMap::new(),
        runbook: "https://r.example.org".to_owned(),
    }
}


fn forecast() -> Rule {
    rule(
        "full",
        Condition::Forecast {
            window: FORECAST_WINDOW,
            capacity: Capacity::Fixed { value: CAPACITY },
            horizon: HORIZON,
            min_confidence: MIN_CONFIDENCE,
            min_points: MIN_POINTS,
        },
    )
}


fn absence() -> Rule {
    rule("quiet", Condition::Absence { interval: STEP })
}


fn threshold() -> Rule {
    rule(
        "disk",
        Condition::Threshold {
            direction: Direction::Above,
            threshold: THRESHOLD,
            clear: None,
        },
    )
}


fn file(rules: Vec<Rule>) -> RuleFile {
    RuleFile { rules }
}


fn param(query: &MetricQuery, name: &str) -> String {
    query
        .params
        .iter()
        .find(|(key, _)| key == name)
        .map_or_else(String::new, |(_, value)| value.clone())
}


fn growing(query: &MetricQuery) -> FetchResult {
    let to: u64 = param(query, "to").parse().unwrap_or(NOW);
    Ok((0..=FORECAST_POINTS)
        .map(|step| (to - FORECAST_WINDOW + step * STEP, FORECAST_GROWTH * step as f64))
        .collect())
}


fn nothing(_query: &MetricQuery) -> FetchResult {
    Ok(Vec::new())
}


fn flat(_query: &MetricQuery) -> FetchResult {
    Ok(vec![(NOW + STEP, SAMPLE)])
}


fn unavailable(_query: &MetricQuery) -> FetchResult {
    Err(FetchError::Failed(InsertClass::Unavailable))
}


async fn run_round(
    store: &Store,
    rules: &RuleFile,
    now: u64,
    states: &mut RoundStates,
    fetch: fn(&MetricQuery) -> FetchResult,
) -> Result<(usize, u64), Box<dyn std::error::Error>> {
    let scope = tenant_scope("a")?;
    let exec = executor(store);
    recover_states(&exec, &scope, rules, now, states).await?;
    let outcome = evaluate_round(rules, &scope, now, &MetricsRetention::default(), &|query| fetch(query), states)?;
    let since = outcome.firings.first().map_or(0, |firing| firing.since);
    Ok((store_round(&exec, &scope, &outcome, now).await?, since))
}


fn stored(store: &Store) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(store.rows.lock().map_err(|_| "poisoned")?.len())
}


fn push_row(store: &Store, rule_id: &str, events: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let id = format!("forged-{}", stored(store)?);
    store
        .rows
        .lock()
        .map_err(|_| "poisoned")?
        .push(("a".to_owned(), id, rule_id.to_owned(), serde_json::to_string(events)?));
    Ok(())
}


fn events_of(rule: &Rule, since: &str) -> Vec<String> {
    vec![
        format!("rule:{}", rule.id),
        format!("series:{}", state_key(rule)),
        format!("since:{since}"),
    ]
}


fn started() -> RoundStates {
    RoundStates {
        recovered: true,
        ..RoundStates::default()
    }
}


#[tokio::test]
async fn a_forecast_after_a_restart_keeps_its_since() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    let first = run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let again = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), growing).await?;
    assert_eq!((first, again), ((1, NOW), (0, NOW)));
    let beyond = run_round(&store, &rules, NOW + RESTART + RESTART, &mut RoundStates::default(), growing).await?;
    assert_eq!(beyond, (1, NOW + RESTART + RESTART));
    assert_eq!(stored(&store)?, TWO);
    Ok(())
}


#[tokio::test]
async fn an_absence_after_a_restart_keeps_its_since() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    let first = run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let again = run_round(&store, &rules, NOW + STEP, &mut RoundStates::default(), nothing).await?;
    assert_eq!((first, again), ((1, NOW), (0, NOW)));
    assert_eq!(stored(&store)?, 1);
    Ok(())
}


#[tokio::test]
async fn a_cleared_outage_does_not_mask_the_next_one() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let later = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), nothing).await?;
    assert_eq!(later, (1, NOW + RESTART));
    assert_eq!(stored(&store)?, TWO);
    Ok(())
}


#[tokio::test]
async fn a_sample_after_since_refuses_the_seed() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let resumed = run_round(&store, &rules, NOW + STEP + STEP, &mut RoundStates::default(), flat).await?;
    assert_eq!(resumed.0, 0);
    Ok(())
}


#[tokio::test]
async fn without_recovery_a_restart_stores_a_second_alert() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let settings = MetricsRetention::default();
    let first = evaluate_round(&rules, &scope, NOW, &settings, &|query| growing(query), &mut started())?;
    store_round(&exec, &scope, &first, NOW).await?;
    let second = evaluate_round(&rules, &scope, NOW + RESTART, &settings, &|query| growing(query), &mut started())?;
    assert_eq!(store_round(&exec, &scope, &second, NOW + RESTART).await?, 1);
    Ok(())
}


#[tokio::test]
async fn a_closed_alert_is_not_recovered() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let id = store.rows.lock().map_err(|_| "poisoned")?.first().ok_or("no row")?.1.clone();
    store.closed.lock().map_err(|_| "poisoned")?.insert(id);
    let again = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), growing).await?;
    assert_eq!(again, (1, NOW + RESTART));
    Ok(())
}


#[tokio::test]
async fn a_threshold_rule_is_never_a_candidate_and_asks_nothing() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let rules = file(vec![threshold(), forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await?, 1);
    assert!(!states.candidates.contains_key(&state_key(&threshold())));
    assert_eq!(states.candidates.get(&state_key(&forecast())), Some(&NOW));
    let asked = store.asked.lock().map_err(|_| "poisoned")?.last().cloned().ok_or("not asked")?;
    assert!(asked.contains("metric.full") && !asked.contains("metric.disk"));
    let mut quiet = RoundStates::default();
    let before = store.recoveries.lock().map_err(|_| "poisoned")?.len();
    assert_eq!(recover_states(&exec, &scope, &file(vec![threshold()]), NOW, &mut quiet).await?, 0);
    assert_eq!(store.recoveries.lock().map_err(|_| "poisoned")?.len(), before);
    assert!(quiet.recovered);
    Ok(())
}


#[tokio::test]
async fn recovery_runs_once_and_never_overwrites_a_state() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let rules = file(vec![forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let mut states = RoundStates::default();
    states.states.insert(state_key(&forecast()), metric_alerts::state::AlertState::Inactive);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW, &mut states).await?, 0);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW, &mut states).await?, 0);
    assert!(states.candidates.is_empty() && states.recovered);
    assert_eq!(store.recoveries.lock().map_err(|_| "poisoned")?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn another_tenants_alert_never_seeds() -> TestResult {
    let store = Store::default();
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let exec = executor(&store);
    let rules = file(vec![forecast()]);
    let outcome = evaluate_round(
        &rules,
        &scope_b,
        NOW,
        &MetricsRetention::default(),
        &|query| growing(query),
        &mut started(),
    )?;
    store_round(&exec, &scope_b, &outcome, NOW).await?;
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope_a, &rules, NOW, &mut states).await?, 0);
    assert_eq!(store.recoveries.lock().map_err(|_| "poisoned")?.as_slice(), ["a"]);
    Ok(())
}


#[tokio::test]
async fn states_of_one_tenant_refuse_another() -> TestResult {
    let store = Store::default();
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let exec = executor(&store);
    let rules = file(vec![forecast()]);
    let mut states = RoundStates::default();
    recover_states(&exec, &scope_a, &rules, NOW, &mut states).await?;
    evaluate_round(&rules, &scope_a, NOW, &MetricsRetention::default(), &|query| growing(query), &mut states)?;
    assert_eq!(states.tenant.as_deref(), Some("a"));
    let refused = evaluate_round(&rules, &scope_b, NOW, &MetricsRetention::default(), &|query| nothing(query), &mut states);
    assert!(matches!(refused, Err(RoundError::TenantMismatch)));
    let recovery = recover_states(&exec, &scope_b, &rules, NOW, &mut states).await;
    assert!(matches!(recovery, Err(RoundError::TenantMismatch)));
    assert_eq!(states.tenant.as_deref(), Some("a"));
    Ok(())
}


#[tokio::test]
async fn a_pending_recovery_evaluates_nothing_until_it_succeeds() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    store.fail.store(true, Ordering::SeqCst);
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    let failed = recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await;
    assert!(matches!(failed, Err(RoundError::Store(_))));
    assert!(!states.recovered);
    let fetches = Cell::<usize>::default();
    let counting = |query: &MetricQuery| {
        fetches.set(fetches.get() + 1);
        growing(query)
    };
    let pending = evaluate_round(&rules, &scope, NOW + RESTART, &MetricsRetention::default(), &counting, &mut states);
    assert!(matches!(pending, Err(RoundError::RecoveryPending)));
    assert_eq!(fetches.get(), 0);
    assert!(states.states.is_empty());
    store.fail.store(false, Ordering::SeqCst);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await?, 1);
    let outcome = evaluate_round(&rules, &scope, NOW + RESTART, &MetricsRetention::default(), &counting, &mut states)?;
    assert_eq!(store_round(&exec, &scope, &outcome, NOW + RESTART).await?, 0);
    Ok(())
}


#[test]
fn a_file_without_forecast_or_absence_needs_no_recovery() -> TestResult {
    let scope = tenant_scope("a")?;
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &file(vec![threshold()]),
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| nothing(query),
        &mut states,
    )?;
    assert_eq!(outcome.counts.evaluated, 1);
    assert!(!states.recovered);
    Ok(())
}


#[tokio::test]
async fn a_failed_fetch_keeps_the_candidate_for_the_next_round() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let settings = MetricsRetention::default();
    let mut states = RoundStates::default();
    recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await?;
    evaluate_round(&rules, &scope, NOW + RESTART, &settings, &|query| unavailable(query), &mut states)?;
    assert_eq!(states.candidates.len(), 1);
    let outcome = evaluate_round(&rules, &scope, NOW + RESTART, &settings, &|query| growing(query), &mut states)?;
    assert_eq!(outcome.firings.first().map(|firing| firing.since), Some(NOW));
    assert!(states.candidates.is_empty());
    Ok(())
}


#[tokio::test]
async fn other_rules_cannot_starve_the_recovery() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence(), threshold()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    (0..STARVING_ROWS).try_for_each(|index| {
        push_row(
            &store,
            "metric.disk",
            &["rule:disk".to_owned(), format!("series:other{index}"), "since:1".to_owned()],
        )
    })?;
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 1);
    Ok(())
}


#[tokio::test]
async fn forged_rows_never_seed() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    let quiet = absence();
    push_row(&store, "metric.quiet", &events_of(&quiet, &u64::MAX.to_string()))?;
    push_row(&store, "metric.quiet", &events_of(&quiet, &FUTURE.to_string()))?;
    push_row(&store, "metric.sigma-x", &events_of(&quiet, &(NOW - 1).to_string()))?;
    store.lax.store(true, Ordering::SeqCst);
    let outcome = run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    assert_eq!(outcome, (1, NOW));
    Ok(())
}


#[test]
fn a_row_is_checked_for_rule_series_and_time() -> TestResult {
    let quiet = absence();
    let key = state_key(&quiet);
    let good = serde_json::to_string(&events_of(&quiet, "42"))?;
    assert_eq!(since_of(&quiet, &key, &good, NOW), Some(SINCE_FIRST));
    assert_eq!(since_of(&quiet, &key, "not json", NOW), None);
    assert_eq!(since_of(&quiet, &key, r#"["rule:quiet"]"#, NOW), None);
    assert_eq!(since_of(&quiet, &key, &serde_json::to_string(&events_of(&quiet, "-1"))?, NOW), None);
    assert_eq!(since_of(&quiet, &key, &good, SINCE_FIRST - 1), None);
    assert_eq!(since_of(&quiet, "other", &good, NOW), None);
    assert_eq!(since_of(&forecast(), &key, &good, NOW), None);
    assert!(fits(NOW) && !fits(u64::MAX));
    let rows = vec![
        vec!["metric.other".to_owned(), good.clone()],
        vec!["metric.quiet".to_owned()],
        Vec::new(),
        vec!["metric.quiet".to_owned(), "garbage".to_owned()],
        vec!["metric.quiet".to_owned(), good],
    ];
    assert_eq!(candidate_of(&quiet, &key, NOW, &rows), Some(SINCE_FIRST));
    let refused: Vec<Vec<String>> = rows.into_iter().take(TWO).collect();
    assert_eq!(candidate_of(&quiet, &key, NOW, &refused), None);
    Ok(())
}


#[test]
fn a_breach_must_reach_back_and_still_hold() -> TestResult {
    let growth: Vec<(u64, f64)> = (0..=FORECAST_POINTS)
        .map(|step| (NOW + step * STEP, FORECAST_GROWTH * step as f64))
        .collect();
    let end = NOW + FORECAST_WINDOW;
    assert!(held_since(&forecast(), &growth, None, NOW, end));
    assert!(!held_since(&forecast(), &growth, None, NOW - 1, end));
    assert!(!held_since(&forecast(), &[], None, end, end));
    let metric_capacity = Condition::Forecast {
        window: FORECAST_WINDOW,
        capacity: Capacity::Metric { name: "size".to_owned() },
        horizon: HORIZON,
        min_confidence: MIN_CONFIDENCE,
        min_points: MIN_POINTS,
    };
    assert!(!held_since(&rule("full", metric_capacity), &growth, None, NOW, end));
    assert!(held_since(&absence(), &[(NOW, SAMPLE)], None, NOW, NOW + STEP));
    assert!(!held_since(&absence(), &[(NOW + 1, SAMPLE)], None, NOW, NOW + STEP));
    assert!(!held_since(&threshold(), &[], None, NOW, NOW));
    Ok(())
}


#[test]
fn the_statement_is_tenant_scoped_one_row_per_rule_and_skips_closed_alerts() -> TestResult {
    assert!(RECOVER_SQL.contains("alerts.tenant = $1"));
    assert!(RECOVER_SQL.contains("alerts.rule_id = wanted.rule_id"));
    assert!(RECOVER_SQL.contains("alerts.event_ids ? wanted.series"));
    assert!(RECOVER_SQL.contains("alert_triage.tenant = alerts.tenant"));
    assert!(RECOVER_SQL.contains("status = 'closed'"));
    assert!(RECOVER_SQL.contains("LIMIT 1)"));
    assert!(!RECOVER_SQL.contains("LIKE"));
    assert!(RULE_ID_PREFIX.ends_with('.'));
    Ok(())
}

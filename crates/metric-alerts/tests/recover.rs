mod common;


use alerts::types::RowFuture;
use common::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::alerting::RULE_ID_PREFIX;
use metric_alerts::model::{Capacity, Condition, Direction, Rule, RuleFile, Severity};
use metric_alerts::query::MetricQuery;
use metric_alerts::recover::{identity_of, recover_states, since_by_series, RECOVER_SQL};
use metric_alerts::round::{evaluate_round, state_key, store_round, RoundError, RoundStates};
use metric_alerts::state::AlertState;
use metric_alerts::types::FetchResult;
use serde_json::Value;
use siem_schema::metrics::MetricsRetention;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
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


const SINCE_FIRST: u64 = 42;


const SINCE_NEWEST: u64 = 200;


const SINCE_OTHER: u64 = 7;


#[derive(Default)]
struct Store {
    rows: Mutex<Vec<(String, String, String)>>,
    closed: Mutex<BTreeSet<String>>,
    recoveries: Mutex<Vec<String>>,
    fail: bool,
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
        let events = doc.get("event_ids").ok_or(PgError::InvalidTenant)?.to_string();
        if !rows.iter().any(|(owner, stored, _)| *owner == tenant && *stored == id) {
            rows.push((tenant.clone(), id, events));
            new += 1;
        }
    }
    Ok(vec![vec![new.to_string()]])
}


fn recover(store: &Store, scope: &TenantScope) -> Result<Vec<Vec<String>>, PgError> {
    store
        .recoveries
        .lock()
        .map_err(|_poisoned| PgError::InvalidTenant)?
        .push(tenant_of(scope).to_owned());
    let closed = store.closed.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    Ok(rows
        .iter()
        .rev()
        .filter(|(owner, id, _)| owner == tenant_of(scope) && !closed.contains(id))
        .map(|(_, _, events)| vec![events.clone()])
        .collect())
}


fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        if store.fail {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else if sql == RECOVER_SQL {
            Box::pin(ready(recover(store, &scope)))
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


async fn run_round(
    store: &Store,
    rules: &RuleFile,
    now: u64,
    states: &mut RoundStates,
    fetch: fn(&MetricQuery) -> FetchResult,
) -> Result<(usize, u64), Box<dyn std::error::Error>> {
    let scope = tenant_scope("a")?;
    let exec = executor(store);
    recover_states(&exec, &scope, rules, states).await?;
    let outcome = evaluate_round(rules, &scope, now, &MetricsRetention::default(), &|query| fetch(query), states)?;
    let since = outcome.firings.first().map_or(0, |firing| firing.since);
    Ok((store_round(&exec, &scope, &outcome, now).await?, since))
}


fn stored(store: &Store) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(store.rows.lock().map_err(|_| "poisoned")?.len())
}


#[tokio::test]
async fn a_forecast_after_a_restart_keeps_its_since() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    let first = run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let again = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), growing).await?;
    let third = run_round(&store, &rules, NOW + RESTART + RESTART, &mut RoundStates::default(), growing).await?;
    assert_eq!((first, again, third), ((1, NOW), (0, NOW), (0, NOW)));
    assert_eq!(stored(&store)?, 1);
    Ok(())
}


#[tokio::test]
async fn an_absence_after_a_restart_keeps_its_since() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    let first = run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let again = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), nothing).await?;
    assert_eq!((first, again), ((1, NOW), (0, NOW)));
    assert_eq!(stored(&store)?, 1);
    Ok(())
}


#[tokio::test]
async fn without_recovery_a_restart_stores_a_second_alert() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut first_states = RoundStates::default();
    let first = evaluate_round(
        &rules,
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| growing(query),
        &mut first_states,
    )?;
    store_round(&exec, &scope, &first, NOW).await?;
    let mut second_states = RoundStates::default();
    let second = evaluate_round(
        &rules,
        &scope,
        NOW + RESTART,
        &MetricsRetention::default(),
        &|query| growing(query),
        &mut second_states,
    )?;
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
async fn a_threshold_rule_is_never_seeded() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let threshold_rule = threshold();
    let rules = file(vec![threshold_rule.clone(), forecast()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), growing).await?;
    let mut states = RoundStates::default();
    let seeded = recover_states(&exec, &scope, &rules, &mut states).await?;
    assert_eq!(seeded, 1);
    assert!(!states.states.contains_key(&state_key(&threshold_rule)));
    assert_eq!(states.states.get(&state_key(&forecast())), Some(&AlertState::Firing { since: NOW }));
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
    let key = state_key(&forecast());
    states.states.insert(key.clone(), AlertState::Inactive);
    assert_eq!(recover_states(&exec, &scope, &rules, &mut states).await?, 0);
    assert_eq!(recover_states(&exec, &scope, &rules, &mut states).await?, 0);
    assert_eq!(states.states.get(&key), Some(&AlertState::Inactive));
    assert!(states.recovered);
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
        &mut RoundStates::default(),
    )?;
    store_round(&exec, &scope_b, &outcome, NOW).await?;
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope_a, &rules, &mut states).await?, 0);
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
    evaluate_round(&rules, &scope_a, NOW, &MetricsRetention::default(), &|query| growing(query), &mut states)?;
    assert_eq!(states.tenant.as_deref(), Some("a"));
    let refused = evaluate_round(&rules, &scope_b, NOW, &MetricsRetention::default(), &|_| panic_free_fetch(), &mut states);
    assert!(matches!(refused, Err(RoundError::TenantMismatch)));
    let recovery = recover_states(&exec, &scope_b, &rules, &mut states).await;
    assert!(matches!(recovery, Err(RoundError::TenantMismatch)));
    assert!(store.recoveries.lock().map_err(|_| "poisoned")?.is_empty());
    assert_eq!(states.tenant.as_deref(), Some("a"));
    Ok(())
}


fn panic_free_fetch() -> FetchResult {
    Ok(Vec::new())
}


#[tokio::test]
async fn a_failed_read_leaves_recovery_pending() -> TestResult {
    let store = Store {
        fail: true,
        ..Store::default()
    };
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    let failed = recover_states(&exec, &scope, &file(vec![forecast()]), &mut states).await;
    assert!(matches!(failed, Err(RoundError::Store(_))));
    assert!(!states.recovered);
    Ok(())
}


#[test]
fn rows_without_a_readable_identity_are_skipped_and_the_newest_wins() -> TestResult {
    let row = |text: &str| vec![text.to_owned()];
    assert_eq!(
        identity_of(&row(r#"["rule:r","series:abc","since:42"]"#)),
        Some(("abc".to_owned(), SINCE_FIRST))
    );
    assert_eq!(identity_of(&row("not json")), None);
    assert_eq!(identity_of(&row(r#"["series:abc"]"#)), None);
    assert_eq!(identity_of(&row(r#"["since:42"]"#)), None);
    assert_eq!(identity_of(&row(r#"["series:abc","since:-1"]"#)), None);
    assert_eq!(identity_of(&Vec::new()), None);
    let found = since_by_series(&[
        row(r#"["series:abc","since:200"]"#),
        row("garbage"),
        row(r#"["series:abc","since:100"]"#),
        row(r#"["series:def","since:7"]"#),
    ]);
    assert_eq!(found.get("abc"), Some(&SINCE_NEWEST));
    assert_eq!(found.get("def"), Some(&SINCE_OTHER));
    assert_eq!(found.len(), TWO);
    Ok(())
}


#[test]
fn the_statement_is_tenant_scoped_bounded_and_skips_closed_alerts() -> TestResult {
    assert!(RECOVER_SQL.contains("WHERE tenant = $1"));
    assert!(RECOVER_SQL.contains(&format!("'{RULE_ID_PREFIX}%'")));
    assert!(RECOVER_SQL.contains("alert_triage.tenant = alerts.tenant"));
    assert!(RECOVER_SQL.contains("status = 'closed'"));
    assert!(RECOVER_SQL.contains("LIMIT $2"));
    Ok(())
}

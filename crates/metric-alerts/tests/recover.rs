mod common;


use alerts::types::RowFuture;
use common::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::alerting::RULE_ID_PREFIX;
use metric_alerts::fetch::FetchError;
use metric_alerts::model::{Capacity, Condition, Direction, Rule, RuleFile, Severity};
use metric_alerts::query::MetricQuery;
use metric_alerts::recover::{
    candidate_of, candidates_of, fits, held_since, micros, recover_states, recovery_class, since_of, MAX_RECOVERY_ATTEMPTS, MAX_ROWS_PER_RULE,
    RECOVER_SQL,
};
use metric_alerts::round::{evaluate_round, state_key, store_round, RoundError, RoundStates};
use metric_alerts::types::FetchResult;
use serde_json::Value;
use siem_ingest::error::InsertClass;
use siem_schema::metrics::MetricsRetention;
use siem_schema::metrics::MetricsTable;
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


const ABSENCE_WINDOW: u64 = 240;


const MICROS_PER_SECOND: u64 = 1_000_000;


const LONG_AGO: u64 = 300;


const DAILY: u64 = 86_400;


#[derive(Default)]
struct Store {
    rows: Mutex<Vec<(String, String, String, String)>>,
    closed: Mutex<BTreeSet<String>>,
    recoveries: Mutex<Vec<String>>,
    asked: Mutex<Vec<String>>,
    bounds: Mutex<Vec<String>>,
    fail: AtomicBool,
    slow: Mutex<Option<String>>,
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
    let slow = store.slow.lock().map_err(|_poisoned| PgError::InvalidTenant)?.clone();
    let refused = if slow.is_some_and(|name| text.contains(&name)) {
        Err(PgError::StatementTimeout { seconds: 1 })
    } else {
        Ok(())
    };
    refused?;
    let high = params.get(1).ok_or(PgError::InvalidTenant)?.clone();
    store.bounds.lock().map_err(|_poisoned| PgError::InvalidTenant)?.push(high);
    let wanted: Vec<Value> = serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant)?;
    let closed = store.closed.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let lax = store.lax.load(Ordering::SeqCst);
    Ok(wanted
        .iter()
        .filter_map(|entry| {
            let rule_id = entry.get("rule_id").and_then(Value::as_str)?;
            let series = entry.get("series").and_then(Value::as_str)?;
            Some(
                rows.iter()
                    .rev()
                    .filter(|(owner, id, stored_rule, events)| {
                        *owner == tenant && !closed.contains(id) && (lax || (stored_rule == rule_id && events.contains(&format!("\"{series}\""))))
                    })
                    .take(MAX_ROWS_PER_RULE)
                    .map(|(_, _, stored_rule, events)| vec![stored_rule.clone(), events.clone()])
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
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
async fn a_forecast_after_a_restart_raises_a_new_alert() -> TestResult {
    let store = Store::default();
    let rules = file(vec![forecast()]);
    let mut states = RoundStates::default();
    let first = run_round(&store, &rules, NOW, &mut states, growing).await?;
    let refilled = run_round(&store, &rules, NOW + STEP, &mut states, flat).await?;
    let again = run_round(&store, &rules, NOW + RESTART, &mut RoundStates::default(), growing).await?;
    assert_eq!((first, refilled.0, again), ((1, NOW), 0, (1, NOW + RESTART)));
    assert_eq!(stored(&store)?, TWO);
    assert!(store.recoveries.lock().map_err(|_| "poisoned")?.is_empty());
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
async fn a_closed_alert_is_not_recovered() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let id = store.rows.lock().map_err(|_| "poisoned")?.first().ok_or("no row")?.1.clone();
    store.closed.lock().map_err(|_| "poisoned")?.insert(id);
    let again = run_round(&store, &rules, NOW + STEP, &mut RoundStates::default(), nothing).await?;
    assert_eq!(again, (1, NOW + STEP));
    Ok(())
}


#[tokio::test]
async fn only_absence_rules_are_asked_for() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let rules = file(vec![threshold(), forecast(), absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 1);
    assert_eq!(states.candidates.len(), 1);
    assert_eq!(states.candidates.get(&state_key(&absence())), Some(&NOW));
    let asked = store.asked.lock().map_err(|_| "poisoned")?.last().cloned().ok_or("not asked")?;
    assert!(asked.contains("metric.quiet") && !asked.contains("metric.full") && !asked.contains("metric.disk"));
    let mut quiet = RoundStates::default();
    let before = store.recoveries.lock().map_err(|_| "poisoned")?.len();
    assert_eq!(
        recover_states(&exec, &scope, &file(vec![threshold(), forecast()]), NOW, &mut quiet).await?,
        0
    );
    assert_eq!(store.recoveries.lock().map_err(|_| "poisoned")?.len(), before);
    assert!(quiet.recovered);
    Ok(())
}


#[tokio::test]
async fn each_rule_carries_its_own_lower_bound() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let long = rule("long", Condition::Absence { interval: STEP * TWO as u64 });
    let mut states = RoundStates::default();
    recover_states(&exec, &scope, &file(vec![absence(), long]), NOW, &mut states).await?;
    let bounds = store.bounds.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(bounds, vec![(NOW * MICROS_PER_SECOND).to_string(); TWO]);
    let asked = store.asked.lock().map_err(|_| "poisoned")?.clone();
    let froms: Vec<Vec<String>> = asked
        .iter()
        .map(|text| {
            let entries: Vec<Value> = serde_json::from_str(text)?;
            Ok(entries
                .iter()
                .filter_map(|entry| entry.get("from").and_then(Value::as_str))
                .map(str::to_owned)
                .collect())
        })
        .collect::<Result<_, serde_json::Error>>()?;
    let short = (NOW - ABSENCE_WINDOW) * MICROS_PER_SECOND;
    let wide = (NOW - ABSENCE_WINDOW * TWO as u64) * MICROS_PER_SECOND;
    assert_eq!(froms, [vec![short.to_string()], vec![wide.to_string()]]);
    assert_eq!(micros(u64::MAX), alerts::store::MAX_CREATED_MICROS);
    assert_eq!(micros(1), MICROS_PER_SECOND);
    Ok(())
}


#[tokio::test]
async fn a_slow_rule_falls_back_alone() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    run_round(&store, &file(vec![absence()]), NOW, &mut RoundStates::default(), nothing).await?;
    let daily = rule("daily", Condition::Absence { interval: DAILY });
    let rules = file(vec![absence(), daily.clone()]);
    *store.slow.lock().map_err(|_| "poisoned")? = Some("metric.daily".to_owned());
    let before = store.asked.lock().map_err(|_| "poisoned")?.len();
    let mut states = RoundStates::default();
    for _ in 0..MAX_RECOVERY_ATTEMPTS - 1 {
        let failed = recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await;
        assert!(matches!(failed, Err(RoundError::Store(_))));
        assert!(!states.recovered);
        let round = evaluate_round(
            &rules,
            &scope,
            NOW + STEP,
            &MetricsRetention::default(),
            &|query| nothing(query),
            &mut states,
        )?;
        assert_eq!(
            (round.counts.evaluated, round.counts.fetch_failures.get("recovery_pending")),
            (1, Some(&1))
        );
    }
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 0);
    assert!(states.recovered && states.recovered_keys.contains(&state_key(&daily)));
    assert!(states.candidates.is_empty());
    assert_eq!(
        store.asked.lock().map_err(|_| "poisoned")?.len() - before,
        MAX_RECOVERY_ATTEMPTS as usize + 1
    );
    Ok(())
}


#[tokio::test]
async fn a_failing_long_rule_listed_first_never_delays_a_shorter_rule() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    run_round(&store, &file(vec![absence()]), NOW, &mut RoundStates::default(), nothing).await?;
    let daily = rule("daily", Condition::Absence { interval: DAILY });
    let rules = file(vec![daily.clone(), absence()]);
    *store.slow.lock().map_err(|_| "poisoned")? = Some("metric.daily".to_owned());
    let mut states = RoundStates::default();
    for _ in 0..MAX_RECOVERY_ATTEMPTS - 1 {
        assert!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await.is_err());
        assert_eq!(states.candidates.get(&state_key(&absence())), Some(&NOW));
    }
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 0);
    assert_eq!(states.candidates.get(&state_key(&absence())), Some(&NOW));
    assert!(states.recovered_keys.contains(&state_key(&daily)));
    Ok(())
}


#[tokio::test]
async fn a_call_stops_at_the_first_failed_read_and_reads_the_shorter_rule_first() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let rules = file(vec![
        rule("daily-b", Condition::Absence { interval: DAILY }),
        absence(),
        rule("daily-a", Condition::Absence { interval: DAILY }),
    ]);
    store.fail.store(true, Ordering::SeqCst);
    let mut states = RoundStates::default();
    assert!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await.is_err());
    assert!(states.recovery_attempts.get(&state_key(&absence())) == Some(&1));
    assert_eq!(states.recovery_attempts.len(), 1);
    Ok(())
}


async fn statements_of_one_call(store: &Store, rules: &RuleFile, states: &mut RoundStates) -> Result<(usize, bool), Box<dyn std::error::Error>> {
    let scope = tenant_scope("a")?;
    let exec = executor(store);
    let before = store.asked.lock().map_err(|_| "poisoned")?.len();
    let answer = recover_states(&exec, &scope, rules, NOW + STEP, states).await;
    let after = store.asked.lock().map_err(|_| "poisoned")?.len();
    Ok((after - before, answer.is_ok()))
}


#[tokio::test]
async fn two_failing_rules_spend_one_statement_per_call() -> TestResult {
    let store = Store::default();
    let rules = file(vec![
        rule("daily-b", Condition::Absence { interval: DAILY }),
        rule("daily-a", Condition::Absence { interval: DAILY }),
    ]);
    *store.slow.lock().map_err(|_| "poisoned")? = Some("metric.daily".to_owned());
    let mut states = RoundStates::default();
    let mut spent = Vec::new();
    for _ in 0..TWO * MAX_RECOVERY_ATTEMPTS as usize {
        spent.push(statements_of_one_call(&store, &rules, &mut states).await?.0);
    }
    assert_eq!(spent, vec![1; TWO * MAX_RECOVERY_ATTEMPTS as usize]);
    assert!(states.recovered);
    assert_eq!(states.recovered_keys.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn a_reload_with_rules_at_the_last_attempt_still_spends_one_statement_per_call() -> TestResult {
    let store = Store::default();
    let first = rule("daily-a", Condition::Absence { interval: DAILY });
    let second = rule("daily-b", Condition::Absence { interval: DAILY });
    let rules = file(vec![second.clone(), first.clone()]);
    *store.slow.lock().map_err(|_| "poisoned")? = Some("metric.daily".to_owned());
    let mut states = RoundStates::default();
    states.recovery_attempts.insert(state_key(&first), MAX_RECOVERY_ATTEMPTS - 1);
    states.recovery_attempts.insert(state_key(&second), MAX_RECOVERY_ATTEMPTS - 1);
    let (one, one_ok) = statements_of_one_call(&store, &rules, &mut states).await?;
    assert!(one == 1 && one_ok && states.recovered_keys.contains(&state_key(&first)) && !states.recovered_keys.contains(&state_key(&second)));
    let (two, two_ok) = statements_of_one_call(&store, &rules, &mut states).await?;
    assert!(two == 1 && two_ok && states.recovered);
    Ok(())
}


#[tokio::test]
async fn recovery_runs_once() -> TestResult {
    let store = Store::default();
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 1);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 0);
    assert_eq!(states.candidates.len(), 1);
    assert_eq!(store.recoveries.lock().map_err(|_| "poisoned")?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn another_tenants_alert_never_seeds() -> TestResult {
    let store = Store::default();
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let exec = executor(&store);
    let rules = file(vec![absence()]);
    let outcome = evaluate_round(
        &rules,
        &scope_b,
        NOW,
        &MetricsRetention::default(),
        &|query| nothing(query),
        &mut started(),
    )?;
    assert_eq!(store_round(&exec, &scope_b, &outcome, NOW).await?, 1);
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
    let rules = file(vec![absence()]);
    let mut states = RoundStates::default();
    recover_states(&exec, &scope_a, &rules, NOW, &mut states).await?;
    evaluate_round(&rules, &scope_a, NOW, &MetricsRetention::default(), &|query| nothing(query), &mut states)?;
    assert_eq!(states.tenant.as_deref(), Some("a"));
    let refused = evaluate_round(&rules, &scope_b, NOW, &MetricsRetention::default(), &|query| nothing(query), &mut states);
    assert!(matches!(refused, Err(RoundError::TenantMismatch)));
    let recovery = recover_states(&exec, &scope_b, &rules, NOW, &mut states).await;
    assert!(matches!(recovery, Err(RoundError::TenantMismatch)));
    assert_eq!(states.tenant.as_deref(), Some("a"));
    Ok(())
}


#[tokio::test]
async fn a_failing_recovery_holds_only_the_absence_rules_and_then_gives_up() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence(), threshold()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    store.fail.store(true, Ordering::SeqCst);
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    let fetches = Cell::<usize>::default();
    let counting = |query: &MetricQuery| {
        fetches.set(fetches.get() + 1);
        nothing(query)
    };
    let attempts = MAX_RECOVERY_ATTEMPTS - 1;
    for _ in 0..attempts {
        let failed = recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await;
        assert!(matches!(failed, Err(RoundError::Store(_))));
        let pending = evaluate_round(&rules, &scope, NOW + RESTART, &MetricsRetention::default(), &counting, &mut states)?;
        assert_eq!(
            (pending.counts.evaluated, pending.counts.fetch_failures.get("recovery_pending")),
            (1, Some(&1))
        );
        assert!(pending.firings.is_empty());
    }
    assert!(!states.recovered);
    assert_eq!(fetches.get(), attempts as usize);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + RESTART, &mut states).await?, 0);
    assert!(states.recovered && states.candidates.is_empty() && states.recovery_attempts.get(&state_key(&absence())) == Some(&MAX_RECOVERY_ATTEMPTS));
    let outcome = evaluate_round(&rules, &scope, NOW + RESTART, &MetricsRetention::default(), &counting, &mut states)?;
    assert_eq!((outcome.counts.evaluated, outcome.firings.len()), (TWO, 1));
    store.fail.store(false, Ordering::SeqCst);
    assert_eq!(store_round(&exec, &scope, &outcome, NOW + RESTART).await?, 1);
    Ok(())
}


#[tokio::test]
async fn a_recovery_that_succeeds_after_a_failure_seeds() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    store.fail.store(true, Ordering::SeqCst);
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    assert!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await.is_err());
    store.fail.store(false, Ordering::SeqCst);
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 1);
    let outcome = evaluate_round(
        &rules,
        &scope,
        NOW + STEP,
        &MetricsRetention::default(),
        &|query| nothing(query),
        &mut states,
    )?;
    assert_eq!(store_round(&exec, &scope, &outcome, NOW + STEP).await?, 0);
    Ok(())
}


#[test]
fn recovery_failures_have_fixed_class_names() -> TestResult {
    assert_eq!(recovery_class(&PgError::ConnectTimeout { seconds: 1 }), "timeout");
    assert_eq!(recovery_class(&PgError::StatementTimeout { seconds: 1 }), "timeout");
    let server = PgError::Server {
        code: "57P01".to_owned(),
        class: "admin shutdown",
    };
    assert_eq!(recovery_class(&server), "database");
    assert_eq!(recovery_class(&PgError::InvalidTenant), "other");
    Ok(())
}


#[test]
fn a_file_without_absence_rules_needs_no_recovery() -> TestResult {
    let scope = tenant_scope("a")?;
    let mut states = RoundStates::default();
    let outcome = evaluate_round(
        &file(vec![threshold(), forecast()]),
        &scope,
        NOW,
        &MetricsRetention::default(),
        &|query| nothing(query),
        &mut states,
    )?;
    assert_eq!(outcome.counts.evaluated, TWO);
    assert!(!states.recovered);
    Ok(())
}


#[tokio::test]
async fn a_failed_fetch_keeps_the_candidate_for_the_next_round() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let settings = MetricsRetention::default();
    let mut states = RoundStates::default();
    recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?;
    evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| unavailable(query), &mut states)?;
    assert_eq!(states.candidates.len(), 1);
    let outcome = evaluate_round(&rules, &scope, NOW + STEP, &settings, &|query| nothing(query), &mut states)?;
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


#[tokio::test]
async fn a_refused_newest_row_does_not_hide_the_real_one() -> TestResult {
    let store = Store::default();
    let rules = file(vec![absence()]);
    run_round(&store, &rules, NOW, &mut RoundStates::default(), nothing).await?;
    push_row(&store, "metric.quiet", &events_of(&absence(), &FUTURE.to_string()))?;
    let scope = tenant_scope("a")?;
    let exec = executor(&store);
    let mut states = RoundStates::default();
    assert_eq!(recover_states(&exec, &scope, &rules, NOW + STEP, &mut states).await?, 1);
    assert_eq!(states.candidates.get(&state_key(&absence())), Some(&NOW));
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
    assert_eq!(candidate_of(&quiet, &key, NOW, &rows), (Some(SINCE_FIRST), TWO));
    let refused: Vec<Vec<String>> = rows.into_iter().take(TWO).collect();
    assert_eq!(candidate_of(&quiet, &key, NOW, &refused), (None, 1));
    assert!(candidates_of(&file(vec![absence()]), &refused, NOW).is_empty());
    Ok(())
}


#[test]
fn an_absence_must_reach_back_and_still_hold() -> TestResult {
    assert!(held_since(&absence(), MetricsTable::Raw, &[(NOW, SAMPLE)], NOW, NOW + STEP));
    assert!(!held_since(&absence(), MetricsTable::Raw, &[(NOW + 1, SAMPLE)], NOW, NOW + STEP));
    assert!(!held_since(&absence(), MetricsTable::Raw, &[], NOW, NOW + LONG_AGO));
    let edge = NOW + ABSENCE_WINDOW - STEP;
    assert!(held_since(&absence(), MetricsTable::Raw, &[], NOW, edge));
    assert!(!held_since(&absence(), MetricsTable::Raw, &[], NOW, edge + 1));
    assert!(!held_since(&forecast(), MetricsTable::Raw, &[], NOW, NOW));
    assert!(!held_since(&threshold(), MetricsTable::Raw, &[], NOW, NOW));
    assert!(!held_since(&absence(), MetricsTable::Minute, &[], NOW, NOW + STEP));
    assert!(!held_since(&absence(), MetricsTable::Hour, &[], NOW, NOW + STEP));
    Ok(())
}


#[test]
fn the_statement_is_tenant_scoped_time_bounded_and_skips_closed_alerts() -> TestResult {
    assert!(RECOVER_SQL.contains("alerts.tenant = $1"));
    assert!(RECOVER_SQL.contains("alerts.created >= (wanted.from)::bigint"));
    assert!(RECOVER_SQL.contains("alerts.created <= $3::text::bigint"));
    assert!(!RECOVER_SQL.contains("$4"));
    assert!(RECOVER_SQL.contains("alerts.rule_id = wanted.rule_id"));
    assert!(RECOVER_SQL.contains("alerts.event_ids ? wanted.series"));
    assert!(RECOVER_SQL.contains("alert_triage.tenant = alerts.tenant"));
    assert!(RECOVER_SQL.contains("status = 'closed'"));
    assert!(RECOVER_SQL.contains(&format!("LIMIT {MAX_ROWS_PER_RULE})")));
    assert!(!RECOVER_SQL.contains("LIKE"));
    assert!(RULE_ID_PREFIX.ends_with('.'));
    Ok(())
}

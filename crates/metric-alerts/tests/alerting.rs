mod common;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_EVENT_ID_CHARS, MAX_RULE_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use common::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::alerting::{
    alert_of, firing_alerts, is_valid, severity_of, store_firing_alerts, title_of, Firing, MAX_FIRING_LABELS, MAX_LABELS, MICROS_PER_SECOND,
    RULE_ID_PREFIX,
};
use metric_alerts::model::Severity as RuleSeverity;
use metric_alerts::token::{is_token, shown, MAX_TOKEN_CHARS};
use metric_alerts::types::Labels;
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;


const NOW: u64 = 1_700_000_000;


const SINCE: u64 = 1_699_999_000;


const LATER: u64 = 1_800_000_000;


const DIGEST_LEN: usize = 13;


const HUGE: usize = 100_000;


const TWO: usize = 2;


const TEN: usize = 10;


const EXTRA_FIRINGS: usize = 3;


const EVENT_ID_COUNT: usize = 3;


const INDEX_WIDTH: usize = 2;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
}


pub fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
}


pub fn firing_of(tenant: &TenantScope, rule: &str, pairs: &[(&str, &str)], since: u64) -> Firing {
    Firing {
        tenant: tenant.clone(),
        rule_id: rule.to_owned(),
        labels: labels(pairs),
        severity: RuleSeverity::High,
        since,
    }
}


pub fn firing(tenant: &TenantScope, rule: &str, pairs: &[(&str, &str)], since: u64) -> Firing {
    firing_of(tenant, rule, pairs, since)
}


pub fn run(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let mut calls = store.calls.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    calls.push(docs.len());
    let tenant = tenant_of(scope).to_owned();
    let new = docs
        .iter()
        .filter_map(|doc| doc.get("id").and_then(Value::as_str))
        .filter(|id| rows.insert((tenant.clone(), (*id).to_owned())))
        .count();
    Ok(vec![vec![new.to_string()]])
}


pub fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, _sql, params| -> RowFuture<'a> {
        if store.fail {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            Box::pin(ready(run(store, &scope, &params)))
        }
    }
}


#[test]
fn firing_maps_to_an_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = firing(&scope, "disk-full", &[("asset", "web-1"), ("mount", "data")], SINCE);
    let alerts = firing_alerts(&scope, std::slice::from_ref(&item), NOW);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_id, format!("{RULE_ID_PREFIX}disk-full"));
    assert_eq!(alert.tenant, "acme");
    assert_eq!(alert.rule_title, "Metric alert disk-full asset=web-1 mount=data");
    assert_eq!(alert.host_name.as_deref(), Some("web-1"));
    assert_eq!(alert.severity, Severity::High);
    assert_eq!(alert.created_micros, NOW * MICROS_PER_SECOND);
    assert_eq!(alert.event_time, (SINCE * MICROS_PER_SECOND).to_string());
    assert_eq!(alert.event_ids.len(), EVENT_ID_COUNT);
    assert_eq!(alert.id, alert_id("acme", &alert.rule_id, &alert.event_ids));
    assert!(alert.summary.text.contains("\"since\":1699999000"));
    Ok(())
}


#[test]
fn no_asset_label_means_no_host() -> TestResult {
    let scope = tenant_scope("acme")?;
    let alert = alert_of(&scope, &firing(&scope, "r", &[], SINCE), NOW).ok_or("no alert")?;
    assert!(alert.host_name.is_none());
    Ok(())
}


#[test]
fn severities_map() -> TestResult {
    assert_eq!(severity_of(RuleSeverity::Low), Severity::Low);
    assert_eq!(severity_of(RuleSeverity::Medium), Severity::Medium);
    assert_eq!(severity_of(RuleSeverity::High), Severity::High);
    assert_eq!(severity_of(RuleSeverity::Critical), Severity::Critical);
    Ok(())
}


#[test]
fn one_period_one_id_and_a_new_period_a_new_id() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = firing_alerts(&scope, &[firing(&scope, "r", &[("a", "b")], SINCE)], NOW);
    let again = firing_alerts(&scope, &[firing(&scope, "r", &[("a", "b")], SINCE)], LATER);
    let next_period = firing_alerts(&scope, &[firing(&scope, "r", &[("a", "b")], SINCE + 1)], NOW);
    let other_series = firing_alerts(&scope, &[firing(&scope, "r", &[("a", "c")], SINCE)], NOW);
    let id = |alerts: &[alerts::model::Alert]| alerts.first().map(|alert| alert.id.clone());
    assert_eq!(id(&first), id(&again));
    assert_ne!(id(&first), id(&next_period));
    assert_ne!(id(&first), id(&other_series));
    Ok(())
}


#[test]
fn token_grammar() -> TestResult {
    assert!(is_token("disk-full"));
    assert!(is_token("@scope/pkg"));
    assert!(!is_token(""));
    assert!(!is_token("-rf"));
    assert!(!is_token("a b"));
    assert!(!is_token("a\nb"));
    assert!(!is_token("a\0b"));
    assert!(!is_token("a\u{e9}"));
    assert!(is_token(&"a".repeat(MAX_TOKEN_CHARS)));
    assert!(!is_token(&"a".repeat(MAX_TOKEN_CHARS + 1)));
    Ok(())
}


#[test]
fn bad_rule_ids_and_times_are_dropped() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let hostile = [
        firing(&scope, "r\nINJECT", &[], SINCE),
        firing(&scope, "-rf", &[], SINCE),
        firing(&scope, "r\0", &[], SINCE),
        firing(&scope, "Disk usage > 90%", &[], SINCE),
        firing(&scope, &huge, &[], SINCE),
        firing(&scope, "r", &[], u64::MAX),
        firing(&scope, "r", &[], MAX_CREATED_MICROS / MICROS_PER_SECOND + 1),
    ];
    assert!(firing_alerts(&scope, &hostile, NOW).is_empty());
    assert!(hostile.iter().all(|item| !is_valid(item)));
    assert!(alert_of(&scope, &firing(&scope, "r", &[], SINCE), NOW).is_some());
    Ok(())
}


#[test]
fn hostile_label_values_are_shown_as_digests() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let values = ["Ethernet 2", "C:\\", "web\u{202e}1", "web\n1", "web\0", "-web", huge.as_str()];
    let firings: Vec<Firing> = values.iter().map(|value| firing(&scope, "r", &[("asset", value)], SINCE)).collect();
    let alerts = firing_alerts(&scope, &firings, NOW);
    assert_eq!(alerts.len(), values.len());
    assert!(alerts
        .iter()
        .all(|alert| alert.rule_title.is_ascii() && alert.rule_title.chars().all(|character| !character.is_control())));
    assert!(alerts.iter().all(|alert| alert.rule_title.contains("asset=#")));
    assert!(alerts.iter().all(|alert| alert
        .host_name
        .as_deref()
        .is_some_and(|host| host.starts_with('#') && host.len() == DIGEST_LEN)));
    assert!(alerts.iter().all(|alert| !alert.rule_title.contains("Ethernet")));
    let again = firing_alerts(&scope, &firings, LATER);
    assert_eq!(
        alerts.iter().map(|alert| &alert.id).collect::<Vec<_>>(),
        again.iter().map(|alert| &alert.id).collect::<Vec<_>>()
    );
    let ethernet = alert_of(&scope, &firing(&scope, "r", &[("asset", "Ethernet 2")], SINCE), NOW).ok_or("no alert")?;
    assert!(ethernet.summary.text.contains("Ethernet 2"));
    let escaped = alert_of(&scope, &firing(&scope, "r", &[("asset", "a\nb")], SINCE), NOW).ok_or("no alert")?;
    assert!(escaped.summary.text.contains("a\\nb"));
    Ok(())
}


#[test]
fn a_label_name_outside_the_grammar_is_shown_as_a_digest() -> TestResult {
    let title = title_of("r", &labels(&[("bad name", "v"), ("good", "w")]));
    assert!(title.starts_with("Metric alert r #"));
    assert!(title.ends_with("=v good=w"));
    assert!(!title.contains("bad name"));
    assert_eq!(shown("ok"), "ok");
    assert_eq!(shown("not ok"), shown("not ok"));
    assert_ne!(shown("not ok"), shown("not  ok"));
    assert_eq!(shown("not ok").len(), DIGEST_LEN);
    Ok(())
}


#[test]
fn too_many_labels_are_listed_then_counted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let many: Vec<(String, String)> = (0..=MAX_LABELS).map(|index| (format!("k{index:02}"), "v".to_owned())).collect();
    let pairs: Vec<(&str, &str)> = many.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let alert = alert_of(&scope, &firing(&scope, "r", &pairs, SINCE), NOW).ok_or("no alert")?;
    assert!(alert.rule_title.ends_with("k15=v (+1 more)"));
    assert!(!alert.rule_title.contains("k16"));
    Ok(())
}


#[test]
fn texts_stay_within_the_store_bounds() -> TestResult {
    let scope = tenant_scope("acme")?;
    let name = "p".repeat(MAX_TOKEN_CHARS);
    let short = "p".repeat(MAX_TOKEN_CHARS - INDEX_WIDTH);
    let many: Vec<(String, String)> = (0..MAX_LABELS).map(|index| (format!("{index:02}{short}"), name.clone())).collect();
    let pairs: Vec<(&str, &str)> = many.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    let alert = alert_of(&scope, &firing(&scope, &name, &pairs, SINCE), NOW).ok_or("no alert")?;
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
    assert!(alert.rule_title.ends_with("more)"));
    assert!(alert.rule_id.chars().count() <= MAX_RULE_ID_CHARS);
    assert!(alert.event_ids.iter().all(|event| event.chars().count() <= MAX_EVENT_ID_CHARS));
    assert!(title_of("r", &labels(&[("a", "b")])).ends_with("a=b"));
    Ok(())
}


#[test]
fn created_time_is_clamped() -> TestResult {
    let scope = tenant_scope("acme")?;
    let alert = alert_of(&scope, &firing(&scope, "r", &[], SINCE), u64::MAX).ok_or("no alert")?;
    assert_eq!(alert.created_micros, MAX_CREATED_MICROS);
    Ok(())
}


#[test]
fn duplicates_merge_and_ids_are_sorted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = firing(&scope, "r", &[("asset", "web-1")], SINCE);
    let second = firing(&scope, "r", &[("asset", "web-2")], SINCE);
    let alerts = firing_alerts(&scope, &[first.clone(), second, first], NOW);
    assert_eq!(alerts.len(), TWO);
    assert!(alerts
        .windows(TWO)
        .all(|pair| pair.first().map(|alert| &alert.id) < pair.get(1).map(|alert| &alert.id)));
    Ok(())
}


#[tokio::test]
async fn rerun_inserts_nothing_new() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let firings = [
        firing(&scope, "r", &[("asset", "web-1")], SINCE),
        firing(&scope, "r", &[("asset", "web-2")], SINCE),
    ];
    let first = store_firing_alerts(&exec, &scope, &firing_alerts(&scope, &firings, NOW)).await?;
    let second = store_firing_alerts(&exec, &scope, &firing_alerts(&scope, &firings, LATER)).await?;
    assert_eq!((first, second), (TWO, 0));
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn tenants_are_isolated() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let acme_alerts = firing_alerts(&acme, &[firing(&acme, "r", &[("asset", "web-1")], SINCE)], NOW);
    let other_alerts = firing_alerts(&other, &[firing_of(&other, "r", &[("asset", "web-1")], SINCE)], NOW);
    assert_ne!(acme_alerts.first().map(|alert| &alert.id), other_alerts.first().map(|alert| &alert.id));
    assert!(acme_alerts.iter().all(|alert| alert.tenant == "acme"));
    let refused = store_firing_alerts(&exec, &other, &acme_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_firing_alerts(&exec, &acme, &acme_alerts).await?, 1);
    assert_eq!(store_firing_alerts(&exec, &other, &other_alerts).await?, 1);
    let rows = store.rows.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(rows.iter().filter(|(tenant, _id)| tenant == "acme").count(), 1);
    assert_eq!(rows.iter().filter(|(tenant, _id)| tenant == "other").count(), 1);
    Ok(())
}


#[tokio::test]
async fn large_sets_go_in_batches() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let firings: Vec<Firing> = (0..MAX_ALERTS_PER_INSERT + EXTRA_FIRINGS)
        .map(|index| firing(&scope, "r", &[("asset", &format!("host-{index}"))], SINCE))
        .collect();
    let inserted = store_firing_alerts(&exec, &scope, &firing_alerts(&scope, &firings, NOW)).await?;
    assert_eq!(inserted, MAX_ALERTS_PER_INSERT + EXTRA_FIRINGS);
    assert_eq!(
        *store.calls.lock().map_err(|_poisoned| "poisoned")?,
        vec![MAX_ALERTS_PER_INSERT, EXTRA_FIRINGS]
    );
    Ok(())
}


#[tokio::test]
async fn executor_failure_is_propagated() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store {
        fail: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let alerts = firing_alerts(&scope, &[firing(&scope, "r", &[], SINCE)], NOW);
    assert!(matches!(store_firing_alerts(&exec, &scope, &alerts).await, Err(StoreError::Pg(_))));
    Ok(())
}


#[test]
fn a_firing_of_another_tenant_raises_no_alert() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let foreign = firing_of(&other, "r", &[("asset", "web-1")], SINCE);
    let own = firing(&acme, "r", &[("asset", "web-2")], SINCE);
    assert!(firing_alerts(&acme, std::slice::from_ref(&foreign), NOW).is_empty());
    let mixed = firing_alerts(&acme, &[foreign, own], NOW);
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed.first().and_then(|alert| alert.host_name.as_deref()), Some("web-2"));
    assert!(mixed.iter().all(|alert| alert.tenant == "acme"));
    Ok(())
}


#[test]
fn the_largest_since_is_kept() -> TestResult {
    let scope = tenant_scope("acme")?;
    let last = MAX_CREATED_MICROS / MICROS_PER_SECOND;
    assert_eq!(firing_alerts(&scope, &[firing(&scope, "r", &[], last)], NOW).len(), 1);
    Ok(())
}


#[tokio::test]
async fn five_hundred_and_three_firings_rerun_inserts_nothing() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let firings: Vec<Firing> = (0..MAX_ALERTS_PER_INSERT + EXTRA_FIRINGS)
        .map(|index| firing(&scope, "r", &[("asset", &format!("host-{index}"))], SINCE))
        .collect();
    store_firing_alerts(&exec, &scope, &firing_alerts(&scope, &firings, NOW)).await?;
    assert_eq!(store_firing_alerts(&exec, &scope, &firing_alerts(&scope, &firings, LATER)).await?, 0);
    Ok(())
}


#[test]
fn a_foreign_firing_never_becomes_an_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    assert!(alert_of(&scope, &firing(&other, "r", &[], SINCE), NOW).is_none());
    assert!(alert_of(&other, &firing(&other, "r", &[], SINCE), NOW).is_some());
    assert!(firing_alerts(&scope, &[firing(&other, "r", &[], SINCE)], NOW).is_empty());
    Ok(())
}


#[test]
fn the_label_count_is_bounded_and_the_title_always_fits() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = build_labels(MAX_FIRING_LABELS * TEN);
    let huge_pairs: Vec<(&str, &str)> = huge.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let dropped = firing(&scope, "r", &huge_pairs, SINCE);
    assert!(!is_valid(&dropped));
    assert!(alert_of(&scope, &dropped, NOW).is_none());
    assert!(firing_alerts(&scope, &[dropped], NOW).is_empty());
    let limit = build_labels(MAX_FIRING_LABELS);
    let limit_pairs: Vec<(&str, &str)> = limit.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let alert = alert_of(&scope, &firing(&scope, "r", &limit_pairs, SINCE), NOW).ok_or("no alert")?;
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
    assert!(alert.rule_title.ends_with("more)"));
    let long_value = "p".repeat(MAX_TOKEN_CHARS);
    let wide: Vec<(String, String)> = (0..MAX_FIRING_LABELS).map(|index| (format!("k{index:04}"), long_value.clone())).collect();
    let wide_pairs: Vec<(&str, &str)> = wide.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    assert!(title_of("r", &labels(&wide_pairs)).chars().count() <= MAX_TITLE_CHARS);
    Ok(())
}


pub fn build_labels(count: usize) -> Vec<(String, String)> {
    (0..count).map(|index| (format!("k{index:05}"), "v".to_owned())).collect()
}

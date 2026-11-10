#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_EVENT_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;
use types::TestResult;
use vuln_match::alerting::{
    alert_of, is_cve_id, is_token, kev_alerts, kev_cves_of, severity_of, store_kev_alerts, CRITICAL_FROM_PRIORITY, HIGH_FROM_PRIORITY, KEV_RULE_ID,
    MAX_TOKEN_CHARS,
};
use vuln_match::model::{AssetFinding, Criticality, Finding, ScoredFinding};
use vuln_match::priority::priority_of;


const NOW: u64 = 1_700_000_000_000_000;


const LATER: u64 = 1_800_000_000_000_000;


const HUGE: usize = 100_000;


const TWO: usize = 2;


const EVENT_ID_COUNT: usize = 4;


const CVSS: f64 = 9.0;


const EPSS: f64 = 0.5;


const EXTRA_FINDINGS: usize = 3;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
}


pub fn finding(asset: &str, package: &str, record: &str, aliases: &[&str]) -> AssetFinding {
    AssetFinding {
        asset: asset.to_owned(),
        scored: ScoredFinding {
            finding: Finding {
                package: package.to_owned(),
                installed_version: "1.0-1".to_owned(),
                ecosystem: "Debian:12".to_owned(),
                record_id: record.to_owned(),
                cve_aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
                fixed_version: Some("1.2".to_owned()),
            },
            cvss: CVSS,
            epss: EPSS,
            kev: true,
            criticality: Criticality::High,
        },
    }
}


pub fn kev(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}


pub fn all_kev_alerts(scope: &TenantScope, findings: &[AssetFinding], now: u64) -> Vec<alerts::model::Alert> {
    let ids: BTreeSet<String> = findings
        .iter()
        .flat_map(|item| std::iter::once(item.scored.finding.record_id.clone()).chain(item.scored.finding.cve_aliases.clone()))
        .collect();
    kev_alerts(scope, findings, &ids, now)
}


pub fn run(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let mut calls = store.calls.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    calls.push(docs.len());
    let tenant = core_pg::scope::tenant_of(scope).to_owned();
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
fn alert_maps_the_finding() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("web-1", "openssl", "DSA-1", &["CVE-2024-1234"]);
    let alerts = all_kev_alerts(&scope, std::slice::from_ref(&item), NOW);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_id, KEV_RULE_ID);
    assert_eq!(alert.tenant, "acme");
    assert_eq!(alert.rule_title, "Known exploited vulnerability CVE-2024-1234 in openssl");
    assert_eq!(alert.host_name.as_deref(), Some("web-1"));
    assert_eq!(alert.severity, severity_of(priority_of(&item.scored)));
    assert_eq!(alert.created_micros, NOW);
    assert_eq!(alert.event_ids.len(), EVENT_ID_COUNT);
    assert_eq!(alert.id, alert_id("acme", KEV_RULE_ID, &alert.event_ids));
    assert!(alert.summary.text.contains("\"fixed_version\":\"1.2\""));
    Ok(())
}


#[test]
fn severity_table() -> TestResult {
    assert_eq!(severity_of(CRITICAL_FROM_PRIORITY), Severity::Critical);
    assert_eq!(severity_of(CRITICAL_FROM_PRIORITY - 1), Severity::High);
    assert_eq!(severity_of(HIGH_FROM_PRIORITY), Severity::High);
    assert_eq!(severity_of(HIGH_FROM_PRIORITY - 1), Severity::Medium);
    Ok(())
}


#[test]
fn non_kev_is_not_an_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut item = finding("web-1", "openssl", "CVE-2024-1234", &[]);
    item.scored.kev = false;
    assert!(all_kev_alerts(&scope, &[item], NOW).is_empty());
    Ok(())
}


#[test]
fn only_kev_cves_name_the_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("web-1", "openssl", "DSA-1", &["CVE-2024-9999", "CVE-2020-0001"]);
    let alerts = kev_alerts(&scope, std::slice::from_ref(&item), &kev(&["CVE-2024-9999"]), NOW);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_title, "Known exploited vulnerability CVE-2024-9999 in openssl");
    assert!(alert.event_ids.contains(&"cve:CVE-2024-9999".to_owned()));
    let both = kev_alerts(&scope, std::slice::from_ref(&item), &kev(&["CVE-2024-9999", "CVE-2020-0001"]), NOW);
    assert_eq!(both.len(), TWO);
    assert!(kev_alerts(&scope, &[item], &kev(&["CVE-2021-0002"]), NOW).is_empty());
    Ok(())
}


#[test]
fn kev_cves_are_sorted_and_distinct() -> TestResult {
    let item = finding("a", "p", "CVE-2024-9999", &["CVE-2024-9999", "CVE-2023-1111", "nonsense"]);
    let ids = kev(&["CVE-2024-9999", "CVE-2023-1111", "nonsense"]);
    assert_eq!(kev_cves_of(&item, &ids), vec!["CVE-2023-1111", "CVE-2024-9999"]);
    Ok(())
}


#[test]
fn cve_grammar() -> TestResult {
    assert!(is_cve_id("CVE-2024-1234"));
    assert!(is_cve_id("CVE-2024-1234567"));
    assert!(!is_cve_id("cve-2024-1234"));
    assert!(!is_cve_id("CVE-0000-1234"));
    assert!(!is_cve_id("CVE-2024"));
    assert!(!is_cve_id("CVE-24-1234"));
    assert!(!is_cve_id("CVE-20x4-1234"));
    assert!(!is_cve_id("CVE-2024-123"));
    assert!(!is_cve_id("CVE-2024-12345678901234567890"));
    assert!(!is_cve_id("CVE-2024-12a4"));
    assert!(!is_cve_id("CVE-2024-1234\n"));
    assert!(!is_cve_id(""));
    Ok(())
}


#[test]
fn token_grammar() -> TestResult {
    assert!(is_token("libssl3"));
    assert!(is_token("1:2.3~rc1+dfsg-1"));
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
fn hostile_record_does_not_reach_the_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let hostile = [
        finding("web-1", "openssl", "CVE-2024-1234\nINJECT", &[]),
        finding("web-1", "openssl", &huge, &[&huge, "CVE-2024-12"]),
        finding("web-1", "open\nssl", "CVE-2024-1234", &[]),
        finding("web-1", "-rf", "CVE-2024-1234", &[]),
        finding("web\0-1", "openssl", "CVE-2024-1234", &[]),
        finding("", "openssl", "CVE-2024-1234", &[]),
    ];
    assert!(all_kev_alerts(&scope, &hostile, NOW).is_empty());
    let mut bad_version = finding("web-1", "openssl", "CVE-2024-1234", &[]);
    bad_version.scored.finding.installed_version = "1 2".to_owned();
    assert!(alert_of(&scope, &bad_version, "CVE-2024-1234", NOW).is_none());
    Ok(())
}


#[test]
fn bad_fixed_version_is_left_out_of_the_summary() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut item = finding("web-1", "openssl", "CVE-2024-1234", &[]);
    item.scored.finding.fixed_version = Some("1\n2".to_owned());
    let alert = alert_of(&scope, &item, "CVE-2024-1234", NOW).ok_or("no alert")?;
    assert!(alert.summary.text.contains("\"fixed_version\":null"));
    assert!(!alert.summary.truncated);
    Ok(())
}


#[test]
fn texts_stay_within_the_store_bounds() -> TestResult {
    let scope = tenant_scope("acme")?;
    let name = "p".repeat(MAX_TOKEN_CHARS);
    let item = finding(&name, &name, "CVE-2024-1234567890123456789", &[]);
    let alert = alert_of(&scope, &item, "CVE-2024-1234", NOW).ok_or("no alert")?;
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
    assert!(alert.event_ids.iter().all(|event| event.chars().count() <= MAX_EVENT_ID_CHARS));
    Ok(())
}


#[test]
fn duplicates_merge_and_ids_are_sorted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = finding("web-1", "openssl", "CVE-2024-1234", &[]);
    let second = finding("web-2", "openssl", "CVE-2024-1234", &[]);
    let alerts = all_kev_alerts(&scope, &[first.clone(), second, first], NOW);
    assert_eq!(alerts.len(), TWO);
    assert!(alerts
        .windows(TWO)
        .all(|pair| pair.first().map(|alert| &alert.id) < pair.get(1).map(|alert| &alert.id)));
    Ok(())
}


#[tokio::test]
async fn rerun_inserts_nothing_new_and_a_fix_keeps_history() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let findings = [
        finding("web-1", "openssl", "CVE-2024-1234", &[]),
        finding("web-2", "curl", "GHSA-1", &["CVE-2024-5555"]),
    ];
    let first = store_kev_alerts(&exec, &scope, &all_kev_alerts(&scope, &findings, NOW)).await?;
    let second = store_kev_alerts(&exec, &scope, &all_kev_alerts(&scope, &findings, LATER)).await?;
    assert_eq!((first, second), (TWO, 0));
    let fixed = store_kev_alerts(&exec, &scope, &all_kev_alerts(&scope, &[], LATER)).await?;
    assert_eq!(fixed, 0);
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn tenants_are_isolated() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let findings = [finding("web-1", "openssl", "CVE-2024-1234", &[])];
    let acme_alerts = all_kev_alerts(&acme, &findings, NOW);
    let other_alerts = all_kev_alerts(&other, &findings, NOW);
    assert_ne!(acme_alerts.first().map(|alert| &alert.id), other_alerts.first().map(|alert| &alert.id));
    assert!(acme_alerts.iter().all(|alert| alert.tenant == "acme"));
    let refused = store_kev_alerts(&exec, &other, &acme_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_kev_alerts(&exec, &acme, &acme_alerts).await?, 1);
    assert_eq!(store_kev_alerts(&exec, &other, &other_alerts).await?, 1);
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
    let findings: Vec<AssetFinding> = (0..MAX_ALERTS_PER_INSERT + EXTRA_FINDINGS)
        .map(|index| finding(&format!("host-{index}"), "openssl", "CVE-2024-1234", &[]))
        .collect();
    let inserted = store_kev_alerts(&exec, &scope, &all_kev_alerts(&scope, &findings, NOW)).await?;
    assert_eq!(inserted, MAX_ALERTS_PER_INSERT + EXTRA_FINDINGS);
    assert_eq!(
        *store.calls.lock().map_err(|_poisoned| "poisoned")?,
        vec![MAX_ALERTS_PER_INSERT, EXTRA_FINDINGS]
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
    let alerts = all_kev_alerts(&scope, &[finding("web-1", "openssl", "CVE-2024-1234", &[])], NOW);
    assert!(matches!(store_kev_alerts(&exec, &scope, &alerts).await, Err(StoreError::Pg(_))));
    Ok(())
}

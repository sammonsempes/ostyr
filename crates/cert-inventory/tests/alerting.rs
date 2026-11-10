#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_EVENT_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use cert_inventory::alerting::{
    alert_of, cn_of, date_of, expiry_alerts, is_dns_name, is_fingerprint, is_label, micros_of, store_expiry_alerts, EXPIRY_RULE_ID,
    MAX_CREATED_MICROS, MAX_DNS_NAME_BYTES, MAX_LABEL_BYTES, NEAR_DAYS,
};
use cert_inventory::expiry::SECONDS_PER_DAY;
use cert_inventory::model::CertRecord;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use record::record_with;
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const NOW_MICROS: u64 = 1_700_000_000_000_000;


const LATER: i64 = 1_800_000_000;


const HUGE: usize = 100_000;


const TWO: usize = 2;


const EXPECTED_ALERTS: usize = 3;


const HALF: i64 = 2;


const EXTRA: usize = 3;


const HEX_LENGTH: usize = 64;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
}


pub fn cert(fingerprint_digit: char, subject: &str, not_after: i64) -> CertRecord {
    let mut record = record_with(&[], not_after);
    record.fingerprint_sha256 = fingerprint_digit.to_string().repeat(HEX_LENGTH);
    record.subject = subject.to_owned();
    record
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
fn mapping_expired_near_and_ok() -> TestResult {
    let scope = tenant_scope("acme")?;
    let expired = cert('a', "O=Org, CN=old.example.com", NOW - 1);
    let near = cert('b', "CN=soon.example.com", NOW + SECONDS_PER_DAY);
    let edge = cert('c', "CN=edge.example.com", NOW + i64::from(NEAR_DAYS) * SECONDS_PER_DAY);
    let fine = cert('d', "CN=fine.example.com", NOW + i64::from(NEAR_DAYS) * SECONDS_PER_DAY + 1);
    let alerts = expiry_alerts(&scope, &[expired.clone(), near.clone(), edge, fine.clone()], NOW);
    assert_eq!(alerts.len(), EXPECTED_ALERTS);
    assert!(alert_of(&scope, &fine, NOW).is_none());
    let high = alert_of(&scope, &expired, NOW).ok_or("no alert")?;
    assert_eq!(high.severity, Severity::High);
    assert_eq!(high.rule_id, EXPIRY_RULE_ID);
    assert_eq!(high.tenant, "acme");
    assert_eq!(high.rule_title, "Certificate old.example.com expired on 2023-11-14");
    assert_eq!(high.host_name.as_deref(), Some("old.example.com"));
    assert_eq!(high.created_micros, NOW_MICROS);
    assert_eq!(high.event_time, NOW_MICROS.to_string());
    assert_eq!(high.id, alert_id("acme", EXPIRY_RULE_ID, &high.event_ids));
    assert!(high.summary.text.contains("\"state\":\"expired\""));
    let medium = alert_of(&scope, &near, NOW).ok_or("no alert")?;
    assert_eq!(medium.severity, Severity::Medium);
    assert_eq!(medium.rule_title, "Certificate soon.example.com expires on 2023-11-15");
    Ok(())
}


#[test]
fn state_change_raises_a_new_alert_once() -> TestResult {
    let scope = tenant_scope("acme")?;
    let record = cert('a', "CN=a.example.com", NOW + SECONDS_PER_DAY);
    let near = alert_of(&scope, &record, NOW).ok_or("no alert")?;
    let near_later = alert_of(&scope, &record, NOW + SECONDS_PER_DAY / HALF).ok_or("no alert")?;
    let expired = alert_of(&scope, &record, NOW + SECONDS_PER_DAY).ok_or("no alert")?;
    assert_eq!(near.id, near_later.id);
    assert_ne!(near.id, expired.id);
    Ok(())
}


#[test]
fn fallback_label_when_cn_is_missing_or_unusable() -> TestResult {
    let scope = tenant_scope("acme")?;
    let record = cert('e', "O=Org", NOW - 1);
    let alert = alert_of(&scope, &record, NOW).ok_or("no alert")?;
    assert_eq!(alert.rule_title, "Certificate eeeeeeeeeeee expired on 2023-11-14");
    assert!(alert.host_name.is_none());
    assert!(alert.summary.text.contains("\"subject_cn\":null"));
    let ambiguous = cert('e', "CN=a.example.com, O=x, CN=b.example.com", NOW - 1);
    assert!(alert_of(&scope, &ambiguous, NOW).ok_or("no alert")?.host_name.is_none());
    Ok(())
}


#[test]
fn grammar() -> TestResult {
    assert!(is_dns_name("example.com"));
    assert!(is_dns_name("*.example.com"));
    assert!(is_dns_name("a_b-c.example"));
    assert!(!is_dns_name(""));
    assert!(!is_dns_name("-rf.com"));
    assert!(!is_dns_name("a-.com"));
    assert!(!is_dns_name("a..com"));
    assert!(!is_dns_name("example.com."));
    assert!(!is_dns_name("a b.com"));
    assert!(!is_dns_name("a\nb.com"));
    assert!(!is_dns_name("a\0b.com"));
    assert!(!is_dns_name("caf\u{e9}.com"));
    assert!(is_label(&"a".repeat(MAX_LABEL_BYTES)));
    assert!(!is_label(&"a".repeat(MAX_LABEL_BYTES + 1)));
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(MAX_LABEL_BYTES),
        "b".repeat(MAX_LABEL_BYTES),
        "c".repeat(MAX_LABEL_BYTES),
        "d".repeat(MAX_LABEL_BYTES)
    );
    assert!(long.len() <= MAX_DNS_NAME_BYTES + MAX_LABEL_BYTES);
    assert!(!is_dns_name(&format!("{long}.{}", "e".repeat(MAX_LABEL_BYTES))));
    assert!(is_fingerprint(&"a".repeat(HEX_LENGTH)));
    assert!(!is_fingerprint(&"A".repeat(HEX_LENGTH)));
    assert!(!is_fingerprint("abc"));
    assert_eq!(cn_of("CN=a.example.com"), Some("a.example.com"));
    assert_eq!(cn_of("CN=a.example.com, CN=b.example.com"), None);
    assert_eq!(cn_of("O=x"), None);
    assert_eq!(cn_of("CN=bad name"), None);
    Ok(())
}


#[test]
fn dates_and_micros_are_bounded() -> TestResult {
    assert!(date_of(i64::MAX).is_none());
    assert!(date_of(0).is_some());
    assert_eq!(micros_of(-1), 0);
    assert_eq!(micros_of(i64::MAX), MAX_CREATED_MICROS);
    let scope = tenant_scope("acme")?;
    assert!(alert_of(&scope, &cert('a', "CN=a.example.com", i64::MIN), i64::MIN + 1).is_none());
    Ok(())
}


#[test]
fn hostile_records_do_not_reach_the_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let mut bad_fingerprint = cert('a', "CN=a.example.com", NOW - 1);
    bad_fingerprint.fingerprint_sha256 = format!("{}\nINJECT", "a".repeat(HEX_LENGTH));
    let mut huge_fingerprint = cert('a', "CN=a.example.com", NOW - 1);
    huge_fingerprint.fingerprint_sha256 = huge.clone();
    let mut empty_fingerprint = cert('a', "CN=a.example.com", NOW - 1);
    empty_fingerprint.fingerprint_sha256 = String::new();
    let hostile = [
        bad_fingerprint,
        huge_fingerprint,
        empty_fingerprint,
        cert('a', "CN=a.example.com", i64::MAX),
    ];
    assert!(expiry_alerts(&scope, &hostile, i64::MAX - 1).is_empty());
    let texts = [
        format!("CN={huge}"),
        "CN=a.example.com\nINJECT".to_owned(),
        "CN=a\0.example.com".to_owned(),
        "CN=-rf.example.com".to_owned(),
        "O=Org\nCN=x".to_owned(),
    ];
    texts.iter().try_for_each(|subject| -> TestResult {
        let alert = alert_of(&scope, &cert('a', subject, NOW - 1), NOW).ok_or("no alert")?;
        assert!(alert.host_name.is_none());
        assert_eq!(alert.rule_title, "Certificate aaaaaaaaaaaa expired on 2023-11-14");
        assert!(!alert.summary.text.contains("INJECT"));
        Ok(())
    })?;
    let long_cn = format!(
        "CN={}",
        ["a".repeat(MAX_LABEL_BYTES), "b".repeat(MAX_LABEL_BYTES), "c".repeat(MAX_LABEL_BYTES)].join(".")
    );
    let alert = alert_of(&scope, &cert('a', &long_cn, NOW - 1), NOW).ok_or("no alert")?;
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
    assert!(alert.event_ids.iter().all(|event| event.chars().count() <= MAX_EVENT_ID_CHARS));
    Ok(())
}


#[test]
fn duplicates_merge_and_ids_are_sorted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = cert('a', "CN=a.example.com", NOW - 1);
    let second = cert('b', "CN=b.example.com", NOW - 1);
    let alerts = expiry_alerts(&scope, &[first.clone(), second, first], NOW);
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
    let records = [
        cert('a', "CN=a.example.com", NOW - 1),
        cert('b', "CN=b.example.com", NOW + SECONDS_PER_DAY),
    ];
    let first = store_expiry_alerts(&exec, &scope, &expiry_alerts(&scope, &records, NOW)).await?;
    let second = store_expiry_alerts(&exec, &scope, &expiry_alerts(&scope, &records, NOW + 1)).await?;
    assert_eq!((first, second), (TWO, 0));
    let expired_later = store_expiry_alerts(&exec, &scope, &expiry_alerts(&scope, &records, LATER)).await?;
    assert_eq!(expired_later, 1);
    Ok(())
}


#[tokio::test]
async fn tenants_are_isolated() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let records = [cert('a', "CN=a.example.com", NOW - 1)];
    let acme_alerts = expiry_alerts(&acme, &records, NOW);
    let other_alerts = expiry_alerts(&other, &records, NOW);
    assert_ne!(acme_alerts.first().map(|alert| &alert.id), other_alerts.first().map(|alert| &alert.id));
    assert!(acme_alerts.iter().all(|alert| alert.tenant == "acme"));
    let refused = store_expiry_alerts(&exec, &other, &acme_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_expiry_alerts(&exec, &acme, &acme_alerts).await?, 1);
    assert_eq!(store_expiry_alerts(&exec, &other, &other_alerts).await?, 1);
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
    let records: Vec<CertRecord> = (0..MAX_ALERTS_PER_INSERT + EXTRA)
        .map(|index| cert('a', "CN=a.example.com", NOW - 1 - i64::try_from(index).unwrap_or(0)))
        .enumerate()
        .map(|(index, mut record)| {
            record.fingerprint_sha256 = format!("{index:0>width$x}", width = HEX_LENGTH);
            record
        })
        .collect();
    let inserted = store_expiry_alerts(&exec, &scope, &expiry_alerts(&scope, &records, NOW)).await?;
    assert_eq!(inserted, MAX_ALERTS_PER_INSERT + EXTRA);
    assert_eq!(*store.calls.lock().map_err(|_poisoned| "poisoned")?, vec![MAX_ALERTS_PER_INSERT, EXTRA]);
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
    let alerts = expiry_alerts(&scope, &[cert('a', "CN=a.example.com", NOW - 1)], NOW);
    assert!(matches!(store_expiry_alerts(&exec, &scope, &alerts).await, Err(StoreError::Pg(_))));
    Ok(())
}

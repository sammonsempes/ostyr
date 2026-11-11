#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_EVENT_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use synthetic_checks::alerting::{
    alert_of, identity_of, kind_name, outage_alerts, since_micros, store_outage_alerts, title_of, Outage, MICROS_PER_SECOND,
};
use synthetic_checks::model::{CheckKind, MAX_LOCATIONS};
use types::TestResult;


const NOW: u64 = 1_700_000_000;


const SINCE: u64 = 1_699_999_000;


const HUGE: usize = 10_000;


const MANY: usize = 1_000;


const EXTRA: usize = 3;


const TWO: usize = 2;


const QUARTER: usize = 4;


const DIGEST_LEN: usize = 13;


const FULL_DIGEST_LEN: usize = 64;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
}


pub fn outage(tenant: &str, check: &str, locations: &[&str], since: u64) -> Outage {
    Outage {
        tenant: tenant.to_owned(),
        check: check.to_owned(),
        kind: CheckKind::Http,
        failing_locations: locations.iter().map(|location| (*location).to_owned()).collect(),
        since,
    }
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
fn one_outage_one_alert_with_the_expected_ids() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = outage("acme", "web-front", &["paris", "oslo"], SINCE);
    let alerts = outage_alerts(&scope, std::slice::from_ref(&item), NOW);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_id, "synthetic.http");
    assert_eq!(alert.tenant, "acme");
    assert_eq!(alert.event_ids, vec!["check:web-front".to_owned(), format!("since:{SINCE}")]);
    assert_eq!(alert.id, alert_id("acme", &alert.rule_id, &alert.event_ids));
    assert_eq!(alert.rule_title, "Synthetic check web-front failing at 2 locations: paris, oslo");
    assert_eq!(alert.severity, Severity::High);
    assert_eq!(alert.created_micros, NOW * MICROS_PER_SECOND);
    assert_eq!(alert.event_time, (SINCE * MICROS_PER_SECOND).to_string());
    assert!(alert.host_name.is_none() && alert.user_name.is_none());
    assert!(alert.summary.text.contains("\"since\":1699999000"));
    Ok(())
}


#[test]
fn kinds_name_their_rule() -> TestResult {
    let names: Vec<&str> = [CheckKind::Http, CheckKind::Tcp, CheckKind::Icmp, CheckKind::Dns, CheckKind::Tls]
        .into_iter()
        .map(kind_name)
        .collect();
    assert_eq!(names, ["http", "tcp", "icmp", "dns", "tls"]);
    let scope = tenant_scope("acme")?;
    let mut tls = outage("acme", "c", &[], SINCE);
    tls.kind = CheckKind::Tls;
    let alert = alert_of(&scope, &tls, NOW).ok_or("no alert")?;
    assert_eq!(alert.rule_id, "synthetic.tls");
    assert_eq!(alert.rule_title, "Synthetic check c failing at 0 locations");
    Ok(())
}


#[tokio::test]
async fn same_outage_twice_is_one_row_and_a_later_since_a_second() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let item = outage("acme", "web", &["a"], SINCE);
    let doubled = outage_alerts(&scope, &[item.clone(), item.clone()], NOW);
    assert_eq!(doubled.len(), 1);
    assert_eq!(store_outage_alerts(&exec, &scope, &doubled).await?, 1);
    let rerun = outage_alerts(&scope, std::slice::from_ref(&item), NOW + 1);
    assert_eq!(store_outage_alerts(&exec, &scope, &rerun).await?, 0);
    let later = outage_alerts(&scope, &[outage("acme", "web", &["a"], SINCE + 1)], NOW);
    assert_eq!(store_outage_alerts(&exec, &scope, &later).await?, 1);
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn batches_and_failures() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let outages: Vec<Outage> = (0..MAX_ALERTS_PER_INSERT + EXTRA)
        .map(|index| outage("acme", &format!("c{index}"), &[], SINCE))
        .collect();
    let alerts = outage_alerts(&scope, &outages, NOW);
    assert_eq!(store_outage_alerts(&exec, &scope, &alerts).await?, MAX_ALERTS_PER_INSERT + EXTRA);
    assert_eq!(*store.calls.lock().map_err(|_poisoned| "poisoned")?, vec![MAX_ALERTS_PER_INSERT, EXTRA]);
    let failing = Store {
        fail: true,
        ..Store::default()
    };
    let result = store_outage_alerts(&executor(&failing), &scope, &alerts).await;
    assert!(matches!(result, Err(StoreError::Pg(_))));
    Ok(())
}


#[tokio::test]
async fn tenants_are_isolated() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let first = outage_alerts(&acme, &[outage("acme", "web", &["a"], SINCE)], NOW);
    let second = outage_alerts(&other, &[outage("other", "web", &["a"], SINCE)], NOW);
    assert_ne!(first.first().map(|alert| &alert.id), second.first().map(|alert| &alert.id));
    assert!(matches!(
        store_outage_alerts(&exec, &other, &first).await,
        Err(StoreError::TenantMismatch)
    ));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_outage_alerts(&exec, &acme, &first).await?, 1);
    assert_eq!(store_outage_alerts(&exec, &other, &second).await?, 1);
    Ok(())
}


#[test]
fn a_foreign_outage_is_dropped_counted_and_its_tenant_never_logged() -> TestResult {
    let anchor = tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish());
    let capture = Arc::new(tempfile::tempfile()?);
    let writer = Arc::clone(&capture);
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Arc::clone(&writer))
            .finish(),
    );
    let acme = tenant_scope("acme")?;
    let lone = outage("secretco", "web", &["a"], SINCE);
    let foreign = [lone.clone(), outage("secretco", "db", &["a"], SINCE)];
    let alerts = tracing::dispatcher::with_default(&dispatch, || outage_alerts(&acme, &foreign, NOW));
    drop(anchor);
    assert!(alerts.is_empty());
    let mut text = String::new();
    let mut file: &std::fs::File = &capture;
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut text)?;
    assert!(text.contains("foreign=2"), "{text}");
    assert!(!text.contains("secretco") && !text.contains("acme"), "{text}");
    assert!(alert_of(&acme, &lone, NOW).is_none());
    let mixed = outage_alerts(&acme, &[lone, outage("acme", "web", &["a"], SINCE)], NOW);
    assert_eq!(mixed.len(), 1);
    Ok(())
}


#[test]
fn hostile_names_are_shown_as_digests_and_escaped_in_the_summary() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let names = ["a\nb", "a\u{202e}b", "a\0b", "-rf", "two words", huge.as_str()];
    names.iter().try_for_each(|name| -> TestResult {
        let item = outage("acme", name, &[name], SINCE);
        let alert = alert_of(&scope, &item, NOW).ok_or("no alert")?;
        assert!(alert.rule_title.is_ascii() && alert.rule_title.chars().all(|character| !character.is_control()));
        assert!(alert.rule_title.contains(" #"), "{}", alert.rule_title);
        assert!(alert
            .event_ids
            .iter()
            .all(|event| event.is_ascii() && event.chars().count() <= MAX_EVENT_ID_CHARS));
        assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
        assert!(!alert.summary.text.contains('\n'));
        Ok(())
    })?;
    let newline = alert_of(&scope, &outage("acme", "a\nb", &[], SINCE), NOW).ok_or("no alert")?;
    assert!(newline.summary.text.contains("a\\nb"));
    let injection = "'); DROP TABLE alerts; --";
    let sql = alert_of(&scope, &outage("acme", injection, &[], SINCE), NOW).ok_or("no alert")?;
    assert!(sql.summary.text.contains(injection));
    assert!(!sql.rule_title.contains("DROP"));
    assert_eq!(title_of("ok", &["not ok".to_owned()]).split(": ").nth(1).map(str::len), Some(DIGEST_LEN));
    Ok(())
}


#[test]
fn many_locations_are_listed_then_counted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let names: Vec<String> = (0..MANY).map(|index| format!("loc{index:04}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let alert = alert_of(&scope, &outage("acme", "web", &refs, SINCE), NOW).ok_or("no alert")?;
    let expected_omitted = MANY - MAX_LOCATIONS;
    assert!(alert.rule_title.contains("failing at 1000 locations: loc0000, loc0001"));
    assert!(alert
        .rule_title
        .contains(&format!("loc{:04} (+{expected_omitted} more)", MAX_LOCATIONS - 1)));
    assert!(!alert.rule_title.contains(&format!("loc{:04}", MAX_LOCATIONS)));
    assert!(alert.summary.text.contains(&format!("\"locations_omitted\":{expected_omitted}")));
    Ok(())
}


#[test]
fn long_locations_stay_within_the_title_bound() -> TestResult {
    let long = "l".repeat(MAX_TITLE_CHARS / QUARTER);
    let locations: Vec<String> = (0..MAX_LOCATIONS).map(|index| format!("{index:02}{long}")).collect();
    let title = title_of("web", &locations);
    assert!(title.chars().count() <= MAX_TITLE_CHARS);
    assert!(title.ends_with("more)"));
    Ok(())
}


#[test]
fn a_huge_since_is_dropped_never_clamped() -> TestResult {
    let scope = tenant_scope("acme")?;
    let last = MAX_CREATED_MICROS / MICROS_PER_SECOND;
    assert!(alert_of(&scope, &outage("acme", "web", &[], u64::MAX), NOW).is_none());
    assert!(alert_of(&scope, &outage("acme", "web", &[], last + 1), NOW).is_none());
    let capture = Arc::new(tempfile::tempfile()?);
    let writer = Arc::clone(&capture);
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Arc::clone(&writer))
            .finish(),
    );
    let dropped = tracing::dispatcher::with_default(&dispatch, || outage_alerts(&scope, &[outage("acme", "web", &[], u64::MAX)], NOW));
    assert!(dropped.is_empty());
    let mut text = String::new();
    let mut file: &std::fs::File = &capture;
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut text)?;
    assert!(text.contains("rejected=1"), "{text}");
    assert_eq!(outage_alerts(&scope, &[outage("acme", "web", &[], last)], NOW).len(), 1);
    assert_eq!(since_micros(last), Some(last * MICROS_PER_SECOND));
    assert_eq!(since_micros(u64::MAX), None);
    let clamped = alert_of(&scope, &outage("acme", "web", &[], SINCE), u64::MAX).ok_or("no alert")?;
    assert_eq!(clamped.created_micros, MAX_CREATED_MICROS);
    Ok(())
}


#[test]
fn the_identity_keeps_the_full_digest_while_the_title_keeps_the_short_form() -> TestResult {
    let scope = tenant_scope("acme")?;
    let token = alert_of(&scope, &outage("acme", "web", &[], SINCE), NOW).ok_or("no alert")?;
    assert_eq!(token.event_ids.first().map(String::as_str), Some("check:web"));
    assert_eq!(identity_of("web"), "web");
    let hostile = alert_of(&scope, &outage("acme", "a\nb", &[], SINCE), NOW).ok_or("no alert")?;
    let event = hostile.event_ids.first().ok_or("no event id")?;
    let full = identity_of("a\nb");
    assert_eq!(event, &format!("check:{full}"));
    assert_eq!(full.chars().count(), 1 + FULL_DIGEST_LEN);
    assert!(full.starts_with('#') && full.chars().skip(1).all(|character| character.is_ascii_hexdigit()));
    assert!(event.chars().count() <= MAX_EVENT_ID_CHARS);
    let short = full.chars().take(DIGEST_LEN).collect::<String>();
    assert!(
        hostile.rule_title.contains(&short) && !hostile.rule_title.contains(&full),
        "{}",
        hostile.rule_title
    );
    assert_ne!(identity_of("a\nb"), identity_of("a\nc"));
    Ok(())
}

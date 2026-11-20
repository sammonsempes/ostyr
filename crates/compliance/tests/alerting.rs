#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_EVENT_ID_CHARS, MAX_RULE_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use compliance::alerting::{
    alert_failure_category, alert_of, drift_alerts, failed_total, is_grammar, is_id, raise_state_full, report_run, severity_of, state_full_alert,
    store_drift_alerts, ASSET_PUNCTUATION, MAX_ASSET_CHARS, MAX_ID_CHARS, MAX_TITLE_CHARS as MAX_SHORT_TITLE_CHARS, RULE_PREFIX, STATE_FULL_RULE,
    TITLE_PUNCTUATION,
};
use compliance::error::ReportError;
use compliance::model::{DriftFinding, FailedAt, RecordOutcome, Severity as ControlSeverity, Verdict};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use types::TestResult;


const NOW: u64 = 1_700_000_000_000_000;


const LATER: u64 = 1_800_000_000_000_000;


const FIRST_FAILED: u64 = 1_600_000_000_000_000;


const DAY: u64 = 86_400_000_000;


const THREE: usize = 3;


const STEP_FAILED_LINE: usize = 40;


const STEP_SUMMARY: usize = 70;


const STEP_NOT_RAISED: usize = 120;


const NINE: usize = 9;


const FIVE: usize = 5;


const HUGE: usize = 100_000;


const TWO: usize = 2;


const EVENT_ID_COUNT: usize = 4;


const EXTRA_FINDINGS: usize = 3;


const TOTAL: usize = 7;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
}


pub fn finding(baseline: &str, control: &str, asset: &str) -> DriftFinding {
    DriftFinding {
        tenant: "acme".to_owned(),
        baseline: baseline.to_owned(),
        control: control.to_owned(),
        title: "SSH root login disabled".to_owned(),
        severity: ControlSeverity::High,
        asset: asset.to_owned(),
        first_failed_micros: FIRST_FAILED,
        verdict: Verdict::Fail {
            offending: Vec::new(),
            total: TOTAL,
        },
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
fn alert_maps_the_failure() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("anssi", "ssh-01", "web-1");
    let alerts = drift_alerts(&scope, std::slice::from_ref(&item), NOW);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_id, format!("{RULE_PREFIX}anssi:ssh-01"));
    assert_eq!(alert.tenant, "acme");
    assert_eq!(alert.rule_title, "Control ssh-01 failed: SSH root login disabled");
    assert_eq!(alert.host_name.as_deref(), Some("web-1"));
    assert_eq!(alert.severity, Severity::High);
    assert_eq!(alert.created_micros, NOW);
    assert_eq!(alert.event_time, FIRST_FAILED.to_string());
    assert_eq!(alert.event_ids.len(), EVENT_ID_COUNT);
    assert_eq!(alert.id, alert_id("acme", &alert.rule_id, &alert.event_ids));
    assert!(alert.summary.text.contains("\"offending_rows\":7"));
    Ok(())
}


#[test]
fn severity_table() -> TestResult {
    assert_eq!(severity_of(ControlSeverity::Low), Severity::Low);
    assert_eq!(severity_of(ControlSeverity::Medium), Severity::Medium);
    assert_eq!(severity_of(ControlSeverity::High), Severity::High);
    assert_eq!(severity_of(ControlSeverity::Critical), Severity::Critical);
    Ok(())
}


#[test]
fn only_a_failure_raises_an_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let verdicts = [
        Verdict::Pass,
        Verdict::Error { reason: "boom".to_owned() },
        Verdict::Excepted {
            owner: "ops".to_owned(),
            reason: "legacy".to_owned(),
        },
    ];
    verdicts.iter().for_each(|verdict| {
        let mut item = finding("anssi", "ssh-01", "web-1");
        item.verdict = verdict.clone();
        assert!(failed_total(verdict).is_none());
        assert!(alert_of(&scope, &item, NOW).is_none());
    });
    assert_eq!(
        failed_total(&Verdict::Fail {
            offending: Vec::new(),
            total: 1
        }),
        Some(1)
    );
    Ok(())
}


#[test]
fn a_new_failure_after_a_pass_is_a_new_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = finding("anssi", "ssh-01", "web-1");
    let mut again = first.clone();
    again.first_failed_micros = LATER;
    let alerts = drift_alerts(&scope, &[first, again], NOW);
    assert_eq!(alerts.len(), TWO);
    Ok(())
}


#[test]
fn id_is_stable_across_runs_and_ignores_the_run_time() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("anssi", "ssh-01", "web-1");
    let first = drift_alerts(&scope, std::slice::from_ref(&item), NOW);
    let second = drift_alerts(&scope, std::slice::from_ref(&item), LATER);
    assert_eq!(first.first().map(|alert| &alert.id), second.first().map(|alert| &alert.id));
    Ok(())
}


#[test]
fn grammar() -> TestResult {
    assert!(is_id("ssh-01.a_b"));
    assert!(!is_id(""));
    assert!(!is_id("-rf"));
    assert!(!is_id("a b"));
    assert!(!is_id("a\nb"));
    assert!(!is_id("a\0b"));
    assert!(!is_id("a.b\u{e9}"));
    assert!(is_id(&"a".repeat(MAX_ID_CHARS)));
    assert!(!is_id(&"a".repeat(MAX_ID_CHARS + 1)));
    assert!(is_grammar("web-1:x@y", MAX_ASSET_CHARS, ASSET_PUNCTUATION));
    assert!(is_grammar("Root login (ssh)", MAX_SHORT_TITLE_CHARS, TITLE_PUNCTUATION));
    assert!(!is_grammar(" lead", MAX_SHORT_TITLE_CHARS, TITLE_PUNCTUATION));
    Ok(())
}


#[test]
fn hostile_text_does_not_reach_the_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let huge = "x".repeat(HUGE);
    let mut bad_title = finding("anssi", "ssh-01", "web-1");
    bad_title.title = "ok\nINJECT".to_owned();
    let mut nul_title = finding("anssi", "ssh-01", "web-1");
    nul_title.title = "ok\0".to_owned();
    let mut huge_title = finding("anssi", "ssh-01", "web-1");
    huge_title.title = huge.clone();
    let hostile = [
        finding("anssi\n", "ssh-01", "web-1"),
        finding("anssi", "ssh 01", "web-1"),
        finding("anssi", "-rf", "web-1"),
        finding(&huge, "ssh-01", "web-1"),
        finding("anssi", &huge, "web-1"),
        finding("anssi", "ssh-01", "web\0-1"),
        finding("anssi", "ssh-01", &huge),
        finding("anssi", "ssh-01", ""),
        bad_title,
        nul_title,
        huge_title,
    ];
    assert!(drift_alerts(&scope, &hostile, NOW).is_empty());
    Ok(())
}


#[test]
fn texts_stay_within_the_store_bounds() -> TestResult {
    let scope = tenant_scope("acme")?;
    let id = "p".repeat(MAX_ID_CHARS);
    let mut item = finding(&id, &id, &"h".repeat(MAX_ASSET_CHARS));
    item.title = "t".repeat(MAX_SHORT_TITLE_CHARS);
    let alert = alert_of(&scope, &item, NOW).ok_or("no alert")?;
    assert!(alert.rule_id.chars().count() <= MAX_RULE_ID_CHARS);
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS);
    assert!(alert.event_ids.iter().all(|event| event.chars().count() <= MAX_EVENT_ID_CHARS));
    Ok(())
}


#[test]
fn duplicates_merge_and_ids_are_sorted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let first = finding("anssi", "ssh-01", "web-1");
    let second = finding("anssi", "ssh-01", "web-2");
    let alerts = drift_alerts(&scope, &[first.clone(), second, first], NOW);
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
    let findings = [finding("anssi", "ssh-01", "web-1"), finding("anssi", "ssh-02", "web-1")];
    let first = store_drift_alerts(&exec, &scope, &drift_alerts(&scope, &findings, NOW)).await?;
    let second = store_drift_alerts(&exec, &scope, &drift_alerts(&scope, &findings, LATER)).await?;
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
    let findings = [finding("anssi", "ssh-01", "web-1")];
    let acme_alerts = drift_alerts(&acme, &findings, NOW);
    let mut other_finding = finding("anssi", "ssh-01", "web-1");
    other_finding.tenant = "other".to_owned();
    let other_alerts = drift_alerts(&other, &[other_finding], NOW);
    assert_ne!(acme_alerts.first().map(|alert| &alert.id), other_alerts.first().map(|alert| &alert.id));
    assert!(acme_alerts.iter().all(|alert| alert.tenant == "acme"));
    let refused = store_drift_alerts(&exec, &other, &acme_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_drift_alerts(&exec, &acme, &acme_alerts).await?, 1);
    assert_eq!(store_drift_alerts(&exec, &other, &other_alerts).await?, 1);
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
    let findings: Vec<DriftFinding> = (0..MAX_ALERTS_PER_INSERT + EXTRA_FINDINGS)
        .map(|index| finding("anssi", "ssh-01", &format!("host-{index}")))
        .collect();
    let inserted = store_drift_alerts(&exec, &scope, &drift_alerts(&scope, &findings, NOW)).await?;
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
    let alerts = drift_alerts(&scope, &[finding("anssi", "ssh-01", "web-1")], NOW);
    assert!(matches!(store_drift_alerts(&exec, &scope, &alerts).await, Err(StoreError::Pg(_))));
    Ok(())
}


#[test]
fn a_foreign_tenant_finding_raises_no_alert() -> TestResult {
    let acme = tenant_scope("acme")?;
    let mut foreign = finding("anssi", "ssh-01", "web-1");
    foreign.tenant = "other".to_owned();
    assert!(alert_of(&acme, &foreign, NOW).is_none());
    assert!(drift_alerts(&acme, std::slice::from_ref(&foreign), NOW).is_empty());
    Ok(())
}


#[test]
fn a_mixed_batch_keeps_only_the_scope_tenant() -> TestResult {
    let acme = tenant_scope("acme")?;
    let mut foreign = finding("anssi", "ssh-01", "web-1");
    foreign.tenant = "other".to_owned();
    let mut foreign_other = finding("anssi", "ssh-02", "web-2");
    foreign_other.tenant = "other".to_owned();
    let mut bad_text = finding("anssi", "ssh-03", "web-3");
    bad_text.title = "bad\n".to_owned();
    let mut passing = finding("anssi", "ssh-04", "web-4");
    passing.verdict = Verdict::Pass;
    let own = finding("anssi", "ssh-05", "web-5");
    let alerts = drift_alerts(&acme, &[foreign, own, foreign_other, bad_text, passing], NOW);
    assert_eq!(alerts.len(), 1);
    assert!(alerts.iter().all(|alert| alert.tenant == "acme" && alert.rule_id.ends_with("ssh-05")));
    Ok(())
}


#[test]
fn an_empty_or_invalid_tenant_is_dropped() -> TestResult {
    let acme = tenant_scope("acme")?;
    let tenants = ["", "-x", "acme\n", "ACME"];
    tenants.iter().for_each(|tenant| {
        let mut item = finding("anssi", "ssh-01", "web-1");
        item.tenant = (*tenant).to_owned();
        assert!(drift_alerts(&acme, &[item], NOW).is_empty());
    });
    Ok(())
}


#[test]
fn colliding_baseline_control_pairs_give_different_rule_ids() -> TestResult {
    let acme = tenant_scope("acme")?;
    let first = alert_of(&acme, &finding("a.b", "c", "web-1"), NOW).ok_or("first")?;
    let second = alert_of(&acme, &finding("a", "b.c", "web-1"), NOW).ok_or("second")?;
    assert_ne!(first.rule_id, second.rule_id);
    assert_eq!(first.rule_id, format!("{RULE_PREFIX}a.b:c"));
    Ok(())
}


#[test]
fn the_warning_holds_both_counts_and_no_tenant_name() -> TestResult {
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
    let mut foreign = finding("anssi", "ssh-01", "web-1");
    foreign.tenant = "secretco".to_owned();
    let bad_text = finding("-x", "ssh-02", "web-2");
    let findings = [foreign, bad_text];
    let alerts = tracing::dispatcher::with_default(&dispatch, || drift_alerts(&acme, &findings, NOW));
    drop(anchor);
    assert!(alerts.is_empty());
    let mut text = String::new();
    let mut file: &std::fs::File = &capture;
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut text)?;
    assert!(text.contains("rejected=1"), "{text}");
    assert!(text.contains("foreign_tenant=1"), "{text}");
    assert!(!text.contains("secretco") && !text.contains("acme"), "{text}");
    Ok(())
}


#[test]
fn the_state_full_alert_is_one_per_tenant_and_day_with_counts_only() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let first = state_full_alert(&acme, THREE, NOW);
    let later_same_day = state_full_alert(&acme, NINE, NOW + 1);
    let next_day = state_full_alert(&acme, THREE, NOW + DAY);
    assert_eq!(first.id, later_same_day.id);
    assert_ne!(first.id, next_day.id);
    assert_ne!(first.id, state_full_alert(&other, THREE, NOW).id);
    assert_eq!(first.rule_id, STATE_FULL_RULE);
    assert_eq!(first.summary.text, "{\"refused\":3}");
    assert_eq!(first.host_name, None);
    Ok(())
}


#[tokio::test]
async fn the_state_full_alert_is_raised_only_when_entries_were_refused_and_once_a_day() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    assert_eq!(raise_state_full(&exec, &scope, 0, NOW).await?, 0);
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(raise_state_full(&exec, &scope, TWO, NOW).await?, 1);
    assert_eq!(raise_state_full(&exec, &scope, FIVE, NOW + 1).await?, 0);
    assert_eq!(raise_state_full(&exec, &scope, FIVE, NOW + DAY).await?, 1);
    let failing = Store {
        fail: true,
        ..Store::default()
    };
    assert!(raise_state_full(&executor(&failing), &scope, 1, NOW).await.is_err());
    Ok(())
}


pub struct Budget {
    pub left: usize,
    pub text: Vec<u8>,
}


impl Write for Budget {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.left {
            Err(std::io::Error::other("full"))
        } else {
            self.left -= buffer.len();
            self.text.extend_from_slice(buffer);
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


pub fn stored_outcome() -> RecordOutcome {
    RecordOutcome {
        failed: vec![FailedAt {
            baseline: "anssi".to_owned(),
            control: "ssh-01".to_owned(),
            asset: "web-1".to_owned(),
            first_failed_micros: FIRST_FAILED,
        }],
        skipped_invalid: 1,
        refused_no_room: TWO,
    }
}


#[tokio::test]
async fn a_failed_state_full_alert_keeps_the_stored_outcome_and_is_returned() -> TestResult {
    let scope = tenant_scope("acme")?;
    let failing = Store {
        fail: true,
        ..Store::default()
    };
    let mut out = Budget {
        left: usize::MAX,
        text: Vec::new(),
    };
    let result = report_run(&executor(&failing), &scope, &stored_outcome(), NOW, &mut out).await;
    let text = String::from_utf8(out.text)?;
    assert!(matches!(result, Err(ReportError::AlertFailed { category: "database", .. })), "{result:?}");
    assert!(text.contains("failed anssi:ssh-01:web-1 first=1600000000000000"), "{text}");
    assert!(text.contains("skipped_invalid=1 refused_no_room=2 state_full_alerts=0"), "{text}");
    assert!(text.ends_with("state_full alert not raised\n"), "{text}");
    assert_eq!(
        result.map_err(|error| error.to_string()),
        Err("state_full alert not raised: database".to_owned())
    );
    Ok(())
}


#[tokio::test]
async fn a_working_alert_executor_leaves_the_report_unchanged() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let mut out = Budget {
        left: usize::MAX,
        text: Vec::new(),
    };
    report_run(&executor(&store), &scope, &stored_outcome(), NOW, &mut out).await?;
    let text = String::from_utf8(out.text)?;
    assert!(text.ends_with("state_full_alerts=1\n"), "{text}");
    assert!(!text.contains("not raised"), "{text}");
    Ok(())
}


#[tokio::test]
async fn a_failed_write_is_returned_at_each_step() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let failing = Store {
        fail: true,
        ..Store::default()
    };
    let steps = [
        (0, &store),
        (STEP_FAILED_LINE, &store),
        (STEP_SUMMARY, &store),
        (STEP_NOT_RAISED, &failing),
    ];
    for (left, target) in steps {
        let mut out = Budget { left, text: Vec::new() };
        let result = report_run(&executor(target), &scope, &stored_outcome(), NOW, &mut out).await;
        assert!(matches!(result, Err(ReportError::Write(_))), "{left}: {result:?}");
    }
    Ok(())
}


#[test]
fn the_category_is_fixed_text() -> TestResult {
    assert_eq!(alert_failure_category(&StoreError::TenantMismatch), "rejected");
    assert_eq!(alert_failure_category(&StoreError::Pg(PgError::InvalidTenant)), "database");
    Ok(())
}

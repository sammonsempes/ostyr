#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::model::Severity;
use alerts::store::{MAX_ALERTS_PER_INSERT, MAX_EVENT_ID_CHARS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use secret_scan::alerting::{
    alert_of, commit_label, is_commit, is_path, is_token, path_digest, secret_alerts, short_digest, shown_path, store_secret_alerts, title_of,
    COMMIT_HEX_CHARS, DIGEST_CHARS, MAX_PATH_CHARS, MAX_TOKEN_CHARS, NO_COMMIT,
};
use secret_scan::error::ReportError;
use secret_scan::model::{Finding, Limits, Report, ScanScope};
use secret_scan::report::parse_report;
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;
use types::TestResult;


const LINE: u64 = 12;


const SHA256_HEX_CHARS: usize = 64;


const NOW_MICROS: u64 = 1_700_000_000_000_000;


const MARKER: &str = "ZZ-SECRET-MARKER-9f3a1c7e";


const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";


const HUGE: usize = 10_000;


const TWO: usize = 2;


const EXTRA: usize = 3;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub calls: Mutex<Vec<usize>>,
    pub fail: bool,
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


fn finding(file: &str, line: u64, commit: Option<&str>, rule: &str) -> Finding {
    Finding {
        file: file.to_owned(),
        file_digest: path_digest(file),
        start_line: line,
        end_line: line.saturating_add(1),
        commit: commit.map(str::to_owned),
        rule_id: rule.to_owned(),
        excerpt: format!("{MARKER}****"),
    }
}


fn report(tenant: &str, findings: Vec<Finding>) -> Report {
    Report {
        tenant: tenant.to_owned(),
        scope_id: "repo-main".to_owned(),
        findings,
        malformed: 0,
        skipped: 0,
    }
}


#[test]
fn mapping_and_identity() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("src/config.rs", LINE, Some(COMMIT), "aws-access-token");
    let alerts = secret_alerts(&scope, &report("acme", vec![item.clone()]), NOW_MICROS);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alert.rule_id, "secret.aws-access-token");
    assert_eq!(alert.severity, Severity::High);
    assert_eq!(alert.rule_title, "Secret aws-access-token in src/config.rs:12");
    assert_eq!(alert.tenant, "acme");
    assert!(alert.host_name.is_none());
    assert_eq!(alert.created_micros, NOW_MICROS);
    assert!(alert.summary.text.contains("repo-main"));
    assert!(alert.summary.text.contains(COMMIT));
    assert!(alert.summary.text.contains("\"end_line\":13"));
    assert!(alert.event_ids.iter().all(|event| event.chars().count() <= MAX_EVENT_ID_CHARS));
    let rerun = secret_alerts(&scope, &report("acme", vec![item.clone()]), NOW_MICROS + 1);
    assert_eq!(rerun.first().map(|next| &next.id), Some(&alert.id));
    let other_commit = finding("src/config.rs", LINE, Some(&"f".repeat(COMMIT_HEX_CHARS)), "aws-access-token");
    let other = secret_alerts(&scope, &report("acme", vec![other_commit]), NOW_MICROS);
    assert_ne!(other.first().map(|next| &next.id), Some(&alert.id));
    let moved = secret_alerts(
        &scope,
        &report("acme", vec![finding("src/config.rs", LINE + 1, Some(COMMIT), "aws-access-token")]),
        NOW_MICROS,
    );
    assert_ne!(moved.first().map(|next| &next.id), Some(&alert.id));
    Ok(())
}


#[test]
fn no_commit_is_allowed_and_duplicates_merge() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding("a.txt", 1, None, "generic-api-key");
    assert_eq!(commit_label(&item), Some(NO_COMMIT));
    let alerts = secret_alerts(
        &scope,
        &report("acme", vec![item.clone(), item, finding("b.txt", 1, None, "generic-api-key")]),
        NOW_MICROS,
    );
    assert_eq!(alerts.len(), TWO);
    assert!(alerts
        .windows(TWO)
        .all(|pair| pair.first().map(|next| &next.id) < pair.get(1).map(|next| &next.id)));
    Ok(())
}


#[test]
fn marker_never_reaches_the_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let body = format!(
        r#"[{{"File":"a.env","StartLine":1,"EndLine":1,"Commit":"{COMMIT}","RuleID":"generic-api-key","Match":"key={MARKER}","Secret":"{MARKER}"}}]"#
    );
    let parsed = parse_report(body.as_bytes(), &Limits::default(), "acme", "repo-main", &ScanScope::default())?;
    let alerts = secret_alerts(&scope, &parsed, NOW_MICROS);
    assert_eq!(alerts.len(), 1);
    let rendered = format!("{alerts:?}");
    assert!(!rendered.contains(MARKER));
    let direct = secret_alerts(
        &scope,
        &report("acme", vec![finding("a.env", 1, Some(COMMIT), "generic-api-key")]),
        NOW_MICROS,
    );
    assert!(!format!("{direct:?}").contains(MARKER));
    assert!(!serde_json::to_string(&direct)?.contains(MARKER));
    Ok(())
}


#[test]
fn hostile_rule_ids_and_scope_ids_are_dropped() -> TestResult {
    let scope = tenant_scope("acme")?;
    let hostile = [
        "bad\nrule".to_owned(),
        "bad\0rule".to_owned(),
        "bad\u{202e}rule".to_owned(),
        "-rf".to_owned(),
        String::new(),
        "x".repeat(HUGE),
        "x".repeat(MAX_TOKEN_CHARS + 1),
    ];
    let findings: Vec<Finding> = hostile.iter().map(|rule| finding("a.txt", 1, None, rule)).collect();
    assert!(secret_alerts(&scope, &report("acme", findings), NOW_MICROS).is_empty());
    let mut bad_scope = report("acme", vec![finding("a.txt", 1, None, "rule")]);
    bad_scope.scope_id = "-x".to_owned();
    assert!(secret_alerts(&scope, &bad_scope, NOW_MICROS).is_empty());
    assert!(is_token(&"x".repeat(MAX_TOKEN_CHARS)));
    assert!(is_token("a._-b"));
    Ok(())
}


#[test]
fn hostile_commits_are_refused() -> TestResult {
    let scope = tenant_scope("acme")?;
    let upper = COMMIT.to_uppercase();
    let hostile = [
        String::new(),
        "abc".to_owned(),
        upper,
        format!("{COMMIT}\nx"),
        "g".repeat(COMMIT_HEX_CHARS),
    ];
    hostile.iter().try_for_each(|commit| -> TestResult {
        let item = finding("a.txt", 1, Some(commit), "rule");
        assert!(alert_of(&scope, &report("acme", vec![]), &item, NOW_MICROS).is_none());
        Ok(())
    })?;
    assert!(is_commit(COMMIT));
    Ok(())
}


#[test]
fn hostile_paths_are_shown_as_a_digest() -> TestResult {
    let scope = tenant_scope("acme")?;
    let long = "a".repeat(HUGE);
    let hostile = [
        "bad\nname",
        "bad\0name",
        "bad\u{202e}name",
        "-rf",
        "caf\u{e9}",
        "",
        long.as_str(),
        &"a".repeat(MAX_PATH_CHARS + 1),
    ];
    hostile.iter().try_for_each(|path| -> TestResult {
        let item = finding(path, LINE, None, "rule");
        let alerts = secret_alerts(&scope, &report("acme", vec![item.clone()]), NOW_MICROS);
        let alert = alerts.first().ok_or("no alert")?;
        let digest = short_digest(&path_digest(path));
        assert_eq!(digest.chars().count(), DIGEST_CHARS + 1);
        assert_eq!(alert.rule_title, format!("Secret rule in {digest}:{LINE}"));
        assert!(alert.summary.text.contains(&digest));
        assert!(!alert.summary.text.contains('\u{202e}'));
        assert!(!alert.rule_title.contains('\n'));
        assert_eq!(shown_path(path, &path_digest(path)), digest);
        Ok(())
    })?;
    assert!(is_path("dir/with space/file.txt"));
    assert!(is_path(&"a".repeat(MAX_PATH_CHARS)));
    assert_eq!(path_digest("a.txt").len(), SHA256_HEX_CHARS);
    Ok(())
}


#[test]
fn a_long_title_falls_back_to_the_digest() -> TestResult {
    let scope = tenant_scope("acme")?;
    let item = finding(&"p".repeat(MAX_PATH_CHARS), u64::MAX, None, &"r".repeat(MAX_TOKEN_CHARS));
    assert!(format!("Secret {} in {}:{}", item.rule_id, item.file, item.start_line).chars().count() > MAX_TITLE_CHARS);
    let title = title_of(&item);
    assert!(title.chars().count() <= MAX_TITLE_CHARS);
    assert!(title.contains(&short_digest(&item.file_digest)));
    let alerts = secret_alerts(&scope, &report("acme", vec![item]), NOW_MICROS);
    assert_eq!(alerts.len(), 1);
    Ok(())
}


#[tokio::test]
async fn foreign_tenant_report_raises_nothing() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let foreign = report("other", vec![finding("a.txt", 1, None, "rule")]);
    let alerts = secret_alerts(&scope, &foreign, NOW_MICROS);
    assert!(alerts.is_empty());
    assert_eq!(store_secret_alerts(&exec, &scope, &alerts).await?, 0);
    assert!(alert_of(&scope, &foreign, &finding("a.txt", 1, None, "rule"), NOW_MICROS).is_none());
    Ok(())
}


#[tokio::test]
async fn tenants_are_isolated_and_reruns_insert_nothing() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let findings = vec![finding("a.txt", 1, Some(COMMIT), "rule")];
    let acme_alerts = secret_alerts(&acme, &report("acme", findings.clone()), NOW_MICROS);
    let other_alerts = secret_alerts(&other, &report("other", findings), NOW_MICROS);
    assert_ne!(acme_alerts.first().map(|next| &next.id), other_alerts.first().map(|next| &next.id));
    let refused = store_secret_alerts(&exec, &other, &acme_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.calls.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_secret_alerts(&exec, &acme, &acme_alerts).await?, 1);
    assert_eq!(store_secret_alerts(&exec, &acme, &acme_alerts).await?, 0);
    assert_eq!(store_secret_alerts(&exec, &other, &other_alerts).await?, 1);
    Ok(())
}


#[tokio::test]
async fn large_sets_go_in_batches() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let findings: Vec<Finding> = (0..(MAX_ALERTS_PER_INSERT + EXTRA) as u64)
        .map(|line| finding("a.txt", line, None, "rule"))
        .collect();
    let alerts = secret_alerts(&scope, &report("acme", findings), NOW_MICROS);
    assert_eq!(store_secret_alerts(&exec, &scope, &alerts).await?, MAX_ALERTS_PER_INSERT + EXTRA);
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
    let alerts = secret_alerts(&scope, &report("acme", vec![finding("a.txt", 1, None, "rule")]), NOW_MICROS);
    assert!(matches!(store_secret_alerts(&exec, &scope, &alerts).await, Err(StoreError::Pg(_))));
    Ok(())
}


#[test]
fn created_is_clamped_and_run_failure_helpers_work() -> TestResult {
    let scope = tenant_scope("acme")?;
    let alerts = secret_alerts(&scope, &report("acme", vec![finding("a.txt", 1, None, "rule")]), u64::MAX);
    assert_eq!(alerts.first().map(|next| next.created_micros), Some(i64::MAX as u64));
    let store = Store::default();
    assert!(run(&store, &scope, &[]).is_err());
    assert!(run(&store, &scope, &["not json".to_owned()]).is_err());
    Ok(())
}


#[test]
fn parse_report_refuses_a_bad_tenant() -> TestResult {
    ["-x", "", "a b", "a\nb"].iter().try_for_each(|tenant| -> TestResult {
        let result = parse_report(b"[]".as_slice(), &Limits::default(), tenant, "s", &ScanScope::default());
        assert!(matches!(result, Err(ReportError::InvalidTenant(_))));
        Ok(())
    })?;
    let error = parse_report(b"[]".as_slice(), &Limits::default(), "-x", "s", &ScanScope::default())
        .err()
        .ok_or("no error")?;
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}

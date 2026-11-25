mod common;


use alerts::types::RowFuture;
use common::types::TestResult;
use core_audit::log::open_file_log;
use core_config::reload::{current_config, reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use metric_alerts::model::{Condition, Direction, Rule, RuleFile, Severity};
use metric_alerts::query::MetricQuery;
use metric_alerts::round::RoundStates;
use metric_alerts::serve::{boxed_reload_audit, exit_code, seconds_since_epoch, ServeError};
use metric_alerts::service::{
    load_settings, next_now, open_rules, open_service_settings_from, run_pass, serve, tenant_round, tenants_of, Live, PassReport, ServeEnd,
    ServiceSettings, MAX_TENANTS,
};
use metric_alerts::types::{FetchResult, PassFuture, TenantStates, Timestamp};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::future::ready;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;


const NOW: u64 = 1_700_000_000;


const THRESHOLD: f64 = 90.0;


const BREACH: f64 = 95.0;


const QUIET: f64 = 10.0;


const ROUND_SECONDS: u64 = 60;


const OTHER_ROUND_SECONDS: u64 = 120;


const TOO_SHORT: u64 = 29;


const TOO_LONG: u64 = 3601;


const OVER_MAX_TENANTS: usize = MAX_TENANTS + 1;


const FOUR_ROUNDS: u64 = 4;


const FIRST_READING: u64 = 100;


const LATER_READING: u64 = 200;


const EARLIER_READING: u64 = 50;


const TWO: usize = 2;


const FIRST_INDEX: usize = 0;


const GOOD_RULES: &str = "rules:\n  - id: disk\n    metric: disk.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n";


const MORE_RULES: &str = "rules:\n  - id: disk\n    metric: disk.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n  - id: second\n    metric: cpu.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n";


const DUPLICATE_RULES: &str = "rules:\n  - id: disk\n    metric: disk.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n  - id: disk\n    metric: cpu.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n";


fn settings_text(round_seconds: u64, max_tenants: usize, tenants: &str, audit: &str, pg: &str) -> String {
    format!(
        "fetch_settings: /f.yaml\nrules_file: /r.yaml\npg_settings: {pg}\ntenants: {tenants}\nround_seconds: {round_seconds}\nmax_tenants: {max_tenants}\naudit_file: {audit}\n"
    )
}


fn settings_of(tenants: &[&str]) -> ServiceSettings {
    ServiceSettings {
        fetch_settings: "/f.yaml".into(),
        rules_file: "/r.yaml".into(),
        pg_settings: "/p.yaml".into(),
        tenants: tenants.iter().map(|name| (*name).to_owned()).collect(),
        round_seconds: ROUND_SECONDS,
        max_tenants: MAX_TENANTS,
        audit_file: "/a.log".into(),
    }
}


fn threshold_rule() -> Rule {
    Rule {
        id: "disk".to_owned(),
        metric: "disk.used".to_owned(),
        selector: BTreeMap::new(),
        condition: Condition::Threshold {
            direction: Direction::Above,
            threshold: THRESHOLD,
            clear: None,
        },
        hold_for: 0,
        close_after: ROUND_SECONDS,
        severity: Severity::High,
        labels: BTreeMap::new(),
        runbook: "https://r.example.org".to_owned(),
    }
}


fn absence_rule() -> Rule {
    Rule {
        id: "silent".to_owned(),
        metric: "heartbeat".to_owned(),
        condition: Condition::Absence { interval: ROUND_SECONDS },
        ..threshold_rule()
    }
}


fn live_of(tenants: &[&str], rules: Vec<Rule>) -> Live {
    Live {
        settings: Arc::new(settings_of(tenants)),
        rules: Arc::new(RuleFile { rules }),
        stop: Arc::new(AtomicBool::new(false)),
    }
}


fn tenant_param(query: &MetricQuery) -> String {
    query
        .params
        .iter()
        .find(|(key, _)| key == "tenant")
        .map_or_else(String::new, |(_, value)| value.clone())
}


fn breaching_tenant_a(query: &MetricQuery) -> FetchResult {
    let value = if tenant_param(query) == "a" { BREACH } else { QUIET };
    Ok(vec![(NOW, value)])
}


#[derive(Default)]
struct Store {
    stored: Mutex<Vec<(String, String)>>,
    recoveries: Mutex<Vec<String>>,
    failing_insert: Mutex<Option<String>>,
    failing_recovery: Mutex<Option<String>>,
}


fn fault() -> PgError {
    PgError::StatementTimeout { seconds: 1 }
}


fn answer(store: &Store, scope: &TenantScope, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let recovery = sql.contains("series");
    let failing = if recovery { &store.failing_recovery } else { &store.failing_insert };
    let refused = failing.lock().map_err(|_poisoned| fault())?.as_deref() == Some(tenant.as_str());
    if refused {
        Err(fault())
    } else if recovery {
        store.recoveries.lock().map_err(|_poisoned| fault())?.push(tenant);
        Ok(Vec::new())
    } else {
        let docs: Vec<Value> = serde_json::from_str(params.first().ok_or_else(fault)?).map_err(|_bad| fault())?;
        let mut stored = store.stored.lock().map_err(|_poisoned| fault())?;
        docs.iter()
            .filter_map(|doc| doc.get("rule_id").and_then(Value::as_str))
            .for_each(|rule_id| stored.push((tenant.clone(), rule_id.to_owned())));
        Ok(vec![vec![docs.len().to_string()]])
    }
}


fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(answer(store, &scope, sql, &params))) }
}


fn stored_by(store: &Store) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    Ok(store.stored.lock().map_err(|_poisoned| "poisoned")?.clone())
}


fn put(dir: &Path, name: &str, text: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(&path, text)?;
    Ok(path)
}


#[test]
fn the_documented_settings_file_loads() -> TestResult {
    let dir = tempdir()?;
    let file = put(
        dir.path(),
        "s.yaml",
        &settings_text(ROUND_SECONDS, MAX_TENANTS, "[a, b]", "/a.log", "/p.yaml"),
    )?;
    let settings = load_settings(&file)?;
    assert_eq!(settings.tenants, vec!["a", "b"]);
    assert_eq!(settings.round_seconds, ROUND_SECONDS);
    Ok(())
}


#[test]
fn a_settings_file_outside_its_bounds_is_refused() -> TestResult {
    let dir = tempdir()?;
    let refused = [
        (settings_text(TOO_SHORT, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"), "round_seconds"),
        (settings_text(TOO_LONG, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"), "round_seconds"),
        (settings_text(ROUND_SECONDS, 0, "[a]", "/a.log", "/p.yaml"), "max_tenants"),
        (settings_text(ROUND_SECONDS, OVER_MAX_TENANTS, "[a]", "/a.log", "/p.yaml"), "max_tenants"),
        (settings_text(ROUND_SECONDS, MAX_TENANTS, "[]", "/a.log", "/p.yaml"), "tenants"),
        (settings_text(ROUND_SECONDS, 1, "[a, b]", "/a.log", "/p.yaml"), "tenants"),
        (settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "relative.log", "/p.yaml"), "audit_file"),
        (
            format!("{}extra: 1\n", settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/p.yaml")),
            "unknown field",
        ),
    ];
    for (text, field) in &refused {
        let error = load_settings(&put(dir.path(), "bad.yaml", text)?).err().ok_or("expected a refusal")?;
        assert!(error.to_string().contains(field), "{error}");
    }
    Ok(())
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused() -> TestResult {
    let dir = tempdir()?;
    let file = put(
        dir.path(),
        "s.yaml",
        "fetch_settings: /f\nrules_file: /r\npg_settings: /p\ntenants: [a]\nround_seconds: 60\nmax_tenants: 5\n",
    )?;
    let error = load_settings(&file).err().ok_or("expected a refusal")?;
    assert!(error.to_string().contains("audit_file"), "{error}");
    Ok(())
}


#[test]
fn a_live_settings_change_is_applied_and_audited() -> TestResult {
    let dir = tempdir()?;
    let audit_path = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit_path)?);
    let file = put(
        dir.path(),
        "s.yaml",
        &settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"),
    )?;
    let engine = open_service_settings_from(&file, load_settings(&file)?, boxed_reload_audit(&log))?;
    fs::write(&file, settings_text(OTHER_ROUND_SECONDS, MAX_TENANTS, "[a, b]", "/a.log", "/p.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).round_seconds, OTHER_ROUND_SECONDS);
    assert_eq!(current_config(&engine).tenants.len(), TWO);
    let audit = fs::read_to_string(&audit_path)?;
    assert!(audit.contains("round_seconds"));
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    assert!(!audit.contains("\"tenant\":\"platform\""), "{audit}");
    Ok(())
}


#[test]
fn the_engine_baseline_is_the_snapshot_the_caller_read_not_a_second_read() -> TestResult {
    let dir = tempdir()?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let file = put(
        dir.path(),
        "s.yaml",
        &settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"),
    )?;
    let snapshot = load_settings(&file)?;
    fs::write(&file, settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/swapped.yaml"))?;
    let error = open_service_settings_from(&file, snapshot, boxed_reload_audit(&log))
        .err()
        .ok_or("expected a refusal")?;
    assert!(error.to_string().contains("start-only"), "{error}");
    Ok(())
}


#[test]
fn a_start_only_or_invalid_settings_change_is_refused_audited_and_the_old_file_kept() -> TestResult {
    let dir = tempdir()?;
    let audit_path = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit_path)?);
    let file = put(
        dir.path(),
        "s.yaml",
        &settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"),
    )?;
    let engine = open_service_settings_from(&file, load_settings(&file)?, boxed_reload_audit(&log))?;
    fs::write(&file, settings_text(ROUND_SECONDS, MAX_TENANTS, "[a]", "/a.log", "/other.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&file, settings_text(1, MAX_TENANTS, "[a]", "/a.log", "/p.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).round_seconds, ROUND_SECONDS);
    assert_eq!(current_config(&engine).pg_settings, Path::new("/p.yaml"));
    let audit = fs::read_to_string(&audit_path)?;
    assert_eq!(audit.lines().count(), TWO, "{audit}");
    assert_eq!(audit.matches("\"outcome\":\"denied\"").count(), TWO, "{audit}");
    Ok(())
}


#[test]
fn a_rules_edit_is_reloaded_and_audited_and_a_bad_edit_keeps_the_old_rules() -> TestResult {
    let dir = tempdir()?;
    let audit_path = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit_path)?);
    let file = put(dir.path(), "rules.yaml", GOOD_RULES)?;
    let engine = open_rules(&file, boxed_reload_audit(&log))?;
    fs::write(&file, MORE_RULES)?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Applied { keys } if keys.iter().any(|key| key.contains("rule.second"))),
        "{outcome:?}"
    );
    assert_eq!(current_config(&engine).rules.len(), TWO);
    fs::write(&file, DUPLICATE_RULES)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&file, "rules: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).rules.len(), TWO);
    assert_eq!(fs::read_to_string(&audit_path)?.lines().count(), TWO + 1);
    Ok(())
}


#[test]
fn a_missing_rules_file_fails_the_open() -> TestResult {
    let dir = tempdir()?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    assert!(open_rules(&dir.path().join("absent.yaml"), boxed_reload_audit(&log)).is_err());
    Ok(())
}


#[test]
fn a_refused_tenant_is_skipped_counted_and_the_duplicates_run_once() -> TestResult {
    let (scopes, refused) = tenants_of(&settings_of(&["a", "-x", "a", "b"]));
    let names: Vec<&str> = scopes.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(refused, 1);
    Ok(())
}


#[test]
fn the_clock_must_advance_and_a_zero_reading_never_runs() -> TestResult {
    assert_eq!(next_now(None, FIRST_READING), Some(FIRST_READING));
    assert_eq!(next_now(Some(FIRST_READING), LATER_READING), Some(LATER_READING));
    assert_eq!(next_now(Some(FIRST_READING), FIRST_READING), None);
    assert_eq!(next_now(Some(FIRST_READING), EARLIER_READING), None);
    assert_eq!(next_now(None, 0), None);
    Ok(())
}


#[test]
fn a_clock_before_the_epoch_reads_zero() -> TestResult {
    let before = UNIX_EPOCH.duration_since(SystemTime::now());
    assert!(before.is_err());
    assert_eq!(seconds_since_epoch(before), 0);
    assert_eq!(seconds_since_epoch(Ok(Duration::from_secs(FIRST_READING))), FIRST_READING);
    Ok(())
}


#[test]
fn the_exit_code_names_the_round_cap() -> TestResult {
    let cap = format!("{:?}", exit_code(&Err(ServeError::RoundCap)));
    let usage = format!("{:?}", exit_code(&Err(ServeError::Usage)));
    let success = format!("{:?}", exit_code(&Ok(())));
    assert!(cap.contains('3'), "{cap}");
    assert!(usage.contains('1'), "{usage}");
    assert_ne!(cap, usage);
    assert_ne!(success, usage);
    assert_ne!(success, cap);
    Ok(())
}


#[tokio::test]
async fn a_firing_for_one_tenant_is_stored_for_that_tenant_only_with_states_kept_apart() -> TestResult {
    let store = Store::default();
    let exec = executor(&store);
    let mut states = TenantStates::new();
    let live = live_of(&["a", "b"], vec![threshold_rule()]);
    let report = run_pass(&exec, &breaching_tenant_a, &live, NOW, &mut states).await;
    assert_eq!(
        report,
        PassReport {
            tenants: TWO,
            refused: 0,
            failed: 0,
            unavailable: 0
        }
    );
    assert_eq!(stored_by(&store)?, vec![("a".to_owned(), "metric.disk".to_owned())]);
    assert_eq!(states.keys().map(String::as_str).collect::<Vec<_>>(), vec!["a", "b"]);
    assert_eq!(states.get("a").and_then(|each| each.tenant.as_deref()), Some("a"));
    assert_eq!(states.get("b").and_then(|each| each.tenant.as_deref()), Some("b"));
    let firing_keys = |name: &str| states.get(name).map(|each| each.states.len());
    assert_eq!(firing_keys("a"), Some(1));
    assert_eq!(firing_keys("b"), Some(1));
    assert_ne!(states.get("a"), states.get("b"));
    Ok(())
}


#[tokio::test]
async fn a_tenant_that_leaves_the_list_leaves_the_states_and_a_refused_one_stops_nobody() -> TestResult {
    let store = Store::default();
    let exec = executor(&store);
    let mut states = TenantStates::new();
    run_pass(
        &exec,
        &breaching_tenant_a,
        &live_of(&["a", "b"], vec![threshold_rule()]),
        NOW,
        &mut states,
    )
    .await;
    let report = run_pass(
        &exec,
        &breaching_tenant_a,
        &live_of(&["-x", "b"], vec![threshold_rule()]),
        NOW,
        &mut states,
    )
    .await;
    assert_eq!((report.tenants, report.refused, report.failed), (1, 1, 0));
    assert_eq!(states.keys().map(String::as_str).collect::<Vec<_>>(), vec!["b"]);
    Ok(())
}


#[tokio::test]
async fn a_tenant_whose_states_belong_to_another_fails_alone() -> TestResult {
    let store = Store::default();
    let exec = executor(&store);
    let mut states = TenantStates::new();
    states.insert(
        "a".to_owned(),
        RoundStates {
            tenant: Some("b".to_owned()),
            ..RoundStates::default()
        },
    );
    let live = live_of(&["a", "b"], vec![threshold_rule()]);
    let report = run_pass(&exec, &|_query: &MetricQuery| Ok(vec![(NOW, BREACH)]), &live, NOW, &mut states).await;
    assert_eq!((report.tenants, report.failed), (TWO, 1));
    assert_eq!(stored_by(&store)?, vec![("b".to_owned(), "metric.disk".to_owned())]);
    Ok(())
}


#[tokio::test]
async fn a_store_fault_for_one_tenant_fails_that_tenant_and_the_other_still_stores() -> TestResult {
    let store = Store::default();
    *store.failing_insert.lock().map_err(|_poisoned| "poisoned")? = Some("a".to_owned());
    let exec = executor(&store);
    let mut states = TenantStates::new();
    let live = live_of(&["a", "b"], vec![threshold_rule()]);
    let report = run_pass(&exec, &|_query: &MetricQuery| Ok(vec![(NOW, BREACH)]), &live, NOW, &mut states).await;
    assert_eq!((report.tenants, report.failed), (TWO, 1));
    assert_eq!(stored_by(&store)?, vec![("b".to_owned(), "metric.disk".to_owned())]);
    Ok(())
}


#[tokio::test]
async fn a_recovery_fault_is_retried_next_round_and_the_evaluation_still_runs() -> TestResult {
    let store = Store::default();
    *store.failing_recovery.lock().map_err(|_poisoned| "poisoned")? = Some("a".to_owned());
    let exec = executor(&store);
    let mut states = RoundStates::default();
    let scope = tenant_scope("a")?;
    let rules = RuleFile {
        rules: vec![threshold_rule(), absence_rule()],
    };
    let fetch = |_query: &MetricQuery| -> FetchResult { Ok(vec![(NOW, BREACH)]) };
    let ok = tenant_round(&exec, &fetch, &AtomicBool::new(false), &scope, &rules, NOW, &mut states).await;
    assert!(ok);
    assert!(!states.recovered);
    assert_eq!(stored_by(&store)?, vec![("a".to_owned(), "metric.disk".to_owned())]);
    *store.failing_recovery.lock().map_err(|_poisoned| "poisoned")? = None;
    assert!(tenant_round(&exec, &fetch, &AtomicBool::new(false), &scope, &rules, NOW, &mut states).await);
    assert!(states.recovered);
    assert_eq!(store.recoveries.lock().map_err(|_poisoned| "poisoned")?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_clock_step_backwards_runs_nothing_that_round_and_each_round_pauses() -> TestResult {
    let readings = [FIRST_READING, FIRST_READING, EARLIER_READING, LATER_READING];
    let index = Cell::new(FIRST_INDEX);
    let now = || {
        let reading = readings.get(index.get()).copied().unwrap_or(0);
        index.set(index.get() + 1);
        reading
    };
    let passes: RefCell<Vec<Timestamp>> = RefCell::new(Vec::new());
    let mut pass = |_live: Live, at: Timestamp| -> PassFuture {
        passes.borrow_mut().push(at);
        Box::pin(ready(PassReport::default()))
    };
    let pauses: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
    let wait = |duration: Duration| -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
        pauses.borrow_mut().push(duration);
        Box::pin(ready(()))
    };
    let live = || live_of(&["a"], vec![threshold_rule()]);
    let end = serve(FOUR_ROUNDS, &live, &now, &mut pass, &wait).await;
    assert_eq!(
        end,
        ServeEnd {
            rounds: FOUR_ROUNDS,
            clock_skips: TWO as u64
        }
    );
    assert_eq!(*passes.borrow(), vec![FIRST_READING, LATER_READING]);
    assert_eq!(*pauses.borrow(), vec![Duration::from_secs(ROUND_SECONDS); FOUR_ROUNDS as usize]);
    Ok(())
}


const NO_CALLS: usize = 0;


const RULES_PER_TENANT: usize = 4;


fn four_rules() -> Vec<Rule> {
    (0..RULES_PER_TENANT)
        .map(|index| Rule {
            id: format!("disk{index}"),
            ..threshold_rule()
        })
        .collect()
}


#[tokio::test]
async fn a_stop_set_inside_a_fetch_ends_the_pass_before_the_next_fetch_and_stores_nothing() -> TestResult {
    let store = Store::default();
    let exec = executor(&store);
    let mut states = TenantStates::new();
    let live = live_of(&["a", "b"], four_rules());
    let calls = Cell::new(NO_CALLS);
    let fetch = |_query: &MetricQuery| -> FetchResult {
        calls.set(calls.get() + 1);
        live.stop.store(true, Ordering::SeqCst);
        Ok(vec![(NOW, BREACH)])
    };
    let report = run_pass(&exec, &fetch, &live, NOW, &mut states).await;
    assert_eq!(calls.get(), 1);
    assert_eq!(report.failed, 1);
    assert!(stored_by(&store)?.is_empty());
    assert_eq!(states.keys().map(String::as_str).collect::<Vec<_>>(), vec!["a"]);
    Ok(())
}


#[tokio::test]
async fn a_stop_already_set_runs_no_tenant_and_sends_no_query() -> TestResult {
    let store = Store::default();
    let exec = executor(&store);
    let mut states = TenantStates::new();
    let live = live_of(&["a", "b"], four_rules());
    live.stop.store(true, Ordering::SeqCst);
    let calls = Cell::new(NO_CALLS);
    let fetch = |_query: &MetricQuery| -> FetchResult {
        calls.set(calls.get() + 1);
        Ok(vec![(NOW, BREACH)])
    };
    run_pass(&exec, &fetch, &live, NOW, &mut states).await;
    assert_eq!(calls.get(), NO_CALLS);
    assert!(states.is_empty());
    assert!(stored_by(&store)?.is_empty());
    Ok(())
}

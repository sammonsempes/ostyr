#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log};
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use response_playbooks::batch::{
    dry_run_batch, foreign_tenant, is_token, read_alerts, refusal, request_id, DryRunLimits, DryRunReport, SkipReason, MAX_ALERT_DEPTH,
    MAX_ALERT_NODES, MAX_ALERT_TEXT_BYTES, MAX_LINE_BYTES,
};
use response_playbooks::bundle::{load_bundle, Bundle};
use response_playbooks::render::{escape_controls, render_dry_run, render_trace};
use serde_json::{json, Map, Value};
use std::error::Error;
use std::fs;
use std::io::{self, BufReader, Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const ALERTS: &str = include_str!("../fixtures/alerts_hostile.jsonl");


const START: i64 = 1_800_000_000;


const ROOMY: usize = 1_000;


const SMALL_BUDGET: usize = 5;


const CONFIDENCE: f64 = 0.9;


const TWO: usize = 2;


const THREE: usize = 3;


const HUGE_KEYS: usize = 100_000;


const OVERLONG_TAIL: usize = 10;


const LONG_TOKEN: usize = 65;


const TOKEN_ALERT_ID: &str = "id-1.a_b";


const ROOMY_LIMITS: DryRunLimits = DryRunLimits {
    max_alerts: ROOMY,
    max_matches_per_alert: ROOMY,
    max_trace_events: ROOMY,
};


pub struct Harness {
    pub dir: TempDir,
    pub breakers: Breakers,
}


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read refused"))
    }
}


pub struct OnceThenFail {
    pub sent: bool,
}


impl Read for OnceThenFail {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.sent {
            Err(io::Error::other("read refused"))
        } else {
            self.sent = true;
            let line = b"{}\n";
            buffer
                .get_mut(..line.len())
                .ok_or_else(|| io::Error::other("small"))?
                .copy_from_slice(line);
            Ok(line.len())
        }
    }
}


fn harness() -> Result<Harness, Box<dyn Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("limits.yaml"), "limits: {}\n")?;
    let log = Arc::new(genesis_log(io::sink()));
    let breakers = open_breakers(BreakerSettings {
        config_path: dir.path().join("limits.yaml"),
        store_path: dir.path().join("counters.json"),
        sync: sync_path,
        audit: Arc::new(move |entry| append(&log, entry)),
        clock: Box::new(|| OffsetDateTime::from_unix_timestamp(START).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
    })?;
    Ok(Harness { dir, breakers })
}


fn bundle() -> Result<Bundle, Box<dyn Error>> {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    Ok(load_bundle(
        &fixtures.join("catalogue.yaml"),
        &fixtures.join("inventory.yaml"),
        &[fixtures.join("c2.yaml"), fixtures.join("notify_c2.yaml")],
    )?)
}


fn alert_lines() -> Result<Vec<Value>, Box<dyn Error>> {
    Ok(read_alerts(&mut BufReader::new(ALERTS.as_bytes()), ROOMY)?.alerts)
}


fn c2_alert() -> Value {
    json!({"id": "a", "verdict": "malicious", "category": "command_and_control", "confidence": CONFIDENCE, "domain": "c2.evil.example", "host": {"value": "ws-0042"}})
}


fn with_field(key: &str, value: Value) -> Value {
    let mut alert = c2_alert();
    alert.as_object_mut().into_iter().for_each(|map| {
        map.insert(key.to_owned(), value.clone());
    });
    alert
}


fn batch(tenant: &str, alerts: &[Value], limits: DryRunLimits) -> Result<DryRunReport, Box<dyn Error>> {
    let current = harness()?;
    let report = dry_run_batch(&bundle()?, &current.breakers, tenant, alerts, limits);
    assert!(current.dir.path().exists());
    Ok(report)
}


fn nested(depth: usize) -> Value {
    (0..depth).fold(json!(1), |inner, _| json!({ "k": inner }))
}


#[test]
fn the_fixture_batch_is_a_snapshot() -> TestResult {
    let report = batch("acme", &alert_lines()?, ROOMY_LIMITS)?;
    let expected = fs::read_to_string(format!("{}/tests/snapshots/dry_run_hostile.txt", env!("CARGO_MANIFEST_DIR")))?;
    assert_eq!(render_dry_run(&report), expected);
    Ok(())
}


#[test]
fn a_field_matching_two_triggers_runs_both_playbooks_in_bundle_order() -> TestResult {
    let report = batch("acme", &[c2_alert()], ROOMY_LIMITS)?;
    let names: Vec<&str> = report
        .alerts
        .first()
        .ok_or("no run")?
        .traces
        .iter()
        .map(|trace| trace.playbook.as_str())
        .collect();
    assert_eq!(names, ["Block confirmed C2", "Notify on C2"]);
    Ok(())
}


#[test]
fn template_syntax_in_alert_fields_is_data_and_never_evaluated() -> TestResult {
    let alert = with_field("domain", json!("{{ range(10**9) }}{% for i in x %}{{ self.__init__ }}{% endfor %}"));
    let report = batch("acme", &[alert], ROOMY_LIMITS)?;
    let text = render_trace(report.alerts.first().ok_or("no run")?.traces.last().ok_or("no trace")?);
    assert!(text.contains("C2 seen: {{ range(10**9) }}{% for i in x %}{{ self.__init__ }}{% endfor %}"));
    Ok(())
}


#[test]
fn a_newline_in_an_alert_value_never_forges_a_line() -> TestResult {
    let alert = with_field("domain", json!("x\nalert 99 forged\u{1b}[2J"));
    let report = batch("acme", &[alert], ROOMY_LIMITS)?;
    let text = render_dry_run(&report);
    assert!(!text.lines().any(|line| line.starts_with("alert 99")));
    assert!(text.contains("\\nalert 99 forged"));
    assert_eq!(escape_controls("a\nb\u{1b}c"), "a\\u{a}b\\u{1b}c");
    assert_eq!(escape_controls("plain é"), "plain é");
    Ok(())
}


#[test]
fn a_one_megabyte_string_is_skipped_alone() -> TestResult {
    let big = with_field("blob", json!("a".repeat(MAX_LINE_BYTES as usize)));
    let report = batch("acme", &[big, c2_alert()], ROOMY_LIMITS)?;
    assert_eq!(report.alerts.first().ok_or("no run")?.skipped, Some(SkipReason::TooMuchText));
    assert!(report.alerts.get(1).ok_or("no second")?.skipped.is_none());
    assert!(!report.alerts.get(1).ok_or("no second")?.traces.is_empty());
    Ok(())
}


#[test]
fn a_hundred_thousand_keys_are_skipped_alone() -> TestResult {
    let keys: Map<String, Value> = (0..HUGE_KEYS).map(|key| (format!("k{key}"), json!(1))).collect();
    let many = with_field("extra", Value::Object(keys));
    let report = batch("acme", &[many, c2_alert()], ROOMY_LIMITS)?;
    assert_eq!(report.alerts.first().ok_or("no run")?.skipped, Some(SkipReason::TooMuchText));
    assert!(report.alerts.get(1).ok_or("no second")?.skipped.is_none());
    Ok(())
}


#[test]
fn depth_text_and_node_bounds_are_exact() -> TestResult {
    assert_eq!(refusal(&nested(MAX_ALERT_DEPTH)), None);
    assert_eq!(refusal(&nested(MAX_ALERT_DEPTH + 1)), Some(SkipReason::TooDeep));
    assert_eq!(refusal(&json!({"k": "a".repeat(MAX_ALERT_TEXT_BYTES)})), Some(SkipReason::TooMuchText));
    let nodes: Vec<Value> = (0..MAX_ALERT_NODES).map(|_| json!(1)).collect();
    assert_eq!(refusal(&json!({"k": nodes})), Some(SkipReason::TooManyNodes));
    assert_eq!(refusal(&json!([1])), Some(SkipReason::NotObject));
    assert_eq!(refusal(&json!(null)), Some(SkipReason::NotObject));
    Ok(())
}


#[test]
fn another_tenants_alert_is_skipped_and_never_simulated() -> TestResult {
    let foreign = with_field("tenant", json!("other"));
    let numeric = with_field("tenant", json!(1));
    let own = with_field("tenant", json!("acme"));
    let report = batch("acme", &[foreign, numeric, own, c2_alert()], ROOMY_LIMITS)?;
    let skipped: Vec<Option<SkipReason>> = report.alerts.iter().map(|run| run.skipped).collect();
    assert_eq!(skipped, [Some(SkipReason::OtherTenant), Some(SkipReason::OtherTenant), None, None]);
    assert!(report.alerts.iter().take(TWO).all(|run| run.traces.is_empty()));
    assert!(foreign_tenant(&json!({"tenant": "x"}), "acme"));
    assert!(!foreign_tenant(&json!({}), "acme"));
    Ok(())
}


#[test]
fn an_invalid_batch_tenant_runs_nothing() -> TestResult {
    let alerts = [c2_alert(), c2_alert()];
    let report = batch("-x", &alerts, ROOMY_LIMITS)?;
    assert!(report.tenant_refused);
    assert!(report.alerts.is_empty());
    assert_eq!(report.alerts_not_run, TWO);
    assert!(render_dry_run(&report).starts_with("dry run refused"));
    assert!(batch("", &alerts, ROOMY_LIMITS)?.tenant_refused);
    assert!(!batch("acme", &alerts, ROOMY_LIMITS)?.tenant_refused);
    Ok(())
}


#[test]
fn the_alert_bound_counts_the_rest() -> TestResult {
    let alerts = [c2_alert(), c2_alert(), c2_alert()];
    let report = batch(
        "acme",
        &alerts,
        DryRunLimits {
            max_alerts: 1,
            ..ROOMY_LIMITS
        },
    )?;
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts_not_run, TWO);
    assert!(render_dry_run(&report).contains("2 alert(s) not run (alert bound)"));
    Ok(())
}


#[test]
fn the_match_bound_counts_the_playbooks_past_it() -> TestResult {
    let report = batch(
        "acme",
        &[c2_alert()],
        DryRunLimits {
            max_matches_per_alert: 1,
            ..ROOMY_LIMITS
        },
    )?;
    let run = report.alerts.first().ok_or("no run")?;
    assert_eq!((run.traces.len(), run.matches_over_bound), (1, 1));
    assert!(render_dry_run(&report).contains("matching playbooks not run (per-alert bound): 1"));
    Ok(())
}


#[test]
fn the_trace_budget_cuts_events_and_later_simulations_and_says_so() -> TestResult {
    let alerts = [c2_alert(), c2_alert()];
    let full = batch("acme", &alerts, ROOMY_LIMITS)?;
    let first_full = full.alerts.first().ok_or("no run")?.traces.first().ok_or("no trace")?.events.len();
    let report = batch(
        "acme",
        &alerts,
        DryRunLimits {
            max_trace_events: SMALL_BUDGET,
            ..ROOMY_LIMITS
        },
    )?;
    assert_eq!(report.trace_events, SMALL_BUDGET);
    let first = report.alerts.first().ok_or("no run")?;
    assert_eq!(first.events_omitted, first_full - SMALL_BUDGET);
    assert_eq!(first.matches_over_budget, 1);
    assert_eq!(report.alerts.get(1).ok_or("no second")?.matches_over_budget, TWO);
    let total: usize = report
        .alerts
        .iter()
        .flat_map(|run| run.traces.iter())
        .map(|trace| trace.events.len())
        .sum();
    assert_eq!(total, SMALL_BUDGET);
    let text = render_dry_run(&report);
    assert!(text.contains("trace events omitted (trace budget)"));
    assert!(text.contains("matching playbooks not run (trace budget): 2"));
    Ok(())
}


#[test]
fn request_ids_use_the_position_and_a_bounded_token() -> TestResult {
    assert_eq!(request_id(THREE, &json!({"id": TOKEN_ALERT_ID})), "dry-run-3-id-1.a_b");
    assert_eq!(request_id(THREE, &json!({})), "dry-run-3");
    assert_eq!(request_id(THREE, &json!({"id": 1})), "dry-run-3");
    assert!(!is_token(""));
    assert!(!is_token("-x"));
    assert!(!is_token("a b"));
    assert!(!is_token("é"));
    assert!(!is_token(&"a".repeat(LONG_TOKEN)));
    assert!(is_token("a"));
    Ok(())
}


#[test]
fn skip_reasons_read_in_full() -> TestResult {
    let texts: Vec<String> = [
        SkipReason::NotObject,
        SkipReason::TooDeep,
        SkipReason::TooManyNodes,
        SkipReason::TooMuchText,
        SkipReason::OtherTenant,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert!(texts.iter().all(|text| !text.is_empty()));
    assert_eq!(texts.iter().collect::<std::collections::BTreeSet<_>>().len(), texts.len());
    Ok(())
}


#[test]
fn alert_lines_are_read_bounded_and_unparsable_ones_are_null() -> TestResult {
    let file = read_alerts(&mut Cursor::new(b"{}\n\nnope\n[1]\n".to_vec()), ROOMY)?;
    assert_eq!(file.alerts, [json!({}), Value::Null, Value::Null, json!([1])]);
    assert!(!file.truncated);
    assert_eq!(file.unreadable, TWO);
    let cut = read_alerts(&mut Cursor::new(b"{}\n{}\n{}\n".to_vec()), TWO)?;
    assert_eq!((cut.alerts.len(), cut.truncated), (TWO, true));
    let long = read_alerts(&mut Cursor::new(vec![b'a'; MAX_LINE_BYTES as usize + OVERLONG_TAIL]), ROOMY)?;
    assert_eq!(long.alerts, [Value::Null, Value::Null]);
    assert!(read_alerts(&mut BufReader::new(FailingReader), ROOMY).is_err());
    assert!(read_alerts(&mut BufReader::new(OnceThenFail { sent: false }), 1).is_err());
    Ok(())
}


#[test]
fn the_batch_path_never_reaches_the_real_runner_or_an_executor() -> TestResult {
    let source = fs::read_to_string(format!("{}/src/batch.rs", env!("CARGO_MANIFEST_DIR")))?;
    ["run::", "Executor", "trace_for", "ConnectorFn", "ConnectorCall"]
        .iter()
        .for_each(|forbidden| assert!(!source.contains(forbidden), "batch.rs names {forbidden}"));
    assert!(source.contains("simulate(&loaded.playbook"));
    Ok(())
}

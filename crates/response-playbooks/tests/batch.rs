#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log};
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::check::check;
use response_breakers::model::{ActionKind, ProposedAction, Target};
use response_breakers::store::sync_path;
use response_playbooks::batch::{
    dry_run_batch, foreign_tenant, is_token, raw_keys, read_alerts, refusal, request_id, shape_refusal, value_keys, DryRunLimits, DryRunReport, Line,
    SkipReason, MAX_ALERT_BYTES, MAX_ALERT_DEPTH, MAX_ALERT_NODES, MAX_ALERT_TEXT_BYTES,
};
use response_playbooks::bundle::{load_bundle, Bundle};
use response_playbooks::error::DryRunError;
use response_playbooks::render::{escape_controls, quoted, render_dry_run, render_trace, write_dry_run};
use serde_json::{json, Map, Value};
use std::error::Error;
use std::fs;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const ALERTS: &str = include_str!("../fixtures/alerts_hostile.jsonl");


const START: i64 = 1_800_000_000;


const ROOMY: usize = 1_000;


const SMALL_BUDGET: usize = 5;


const CONFIDENCE: f64 = 0.9;


const FRAME_BYTES: usize = 8;


const TWO: usize = 2;


const THREE: usize = 3;


const HUGE_KEYS: usize = 100_000;


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


pub struct LongThenFail {
    pub sent: bool,
}


impl Read for LongThenFail {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.sent {
            Err(io::Error::other("read refused"))
        } else {
            self.sent = true;
            buffer.iter_mut().for_each(|byte| *byte = b'a');
            Ok(buffer.len())
        }
    }
}


pub struct EofThenFail {
    pub eof_sent: bool,
}


impl Read for EofThenFail {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        if self.eof_sent {
            Err(io::Error::other("read refused"))
        } else {
            self.eof_sent = true;
            Ok(0)
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


fn alert_lines() -> Result<Vec<Line>, Box<dyn Error>> {
    Ok(read(ALERTS.as_bytes(), ROOMY, ROOMY)?.alerts)
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


fn lines(alerts: &[Value]) -> Vec<Line> {
    alerts.iter().cloned().map(Line::Alert).collect()
}


fn batch_lines(tenant: &str, alerts: &[Line], limits: DryRunLimits) -> Result<DryRunReport, Box<dyn Error>> {
    let current = harness()?;
    Ok(dry_run_batch(
        &bundle()?,
        &current.dir.path().join("limits.yaml"),
        current.dir.path(),
        tenant,
        alerts,
        limits,
    )?)
}


fn batch(tenant: &str, alerts: &[Value], limits: DryRunLimits) -> Result<DryRunReport, Box<dyn Error>> {
    batch_lines(tenant, &lines(alerts), limits)
}


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct FailOnSecond {
    pub written: bool,
}


impl Write for FailOnSecond {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.written {
            Err(io::Error::other("write refused"))
        } else {
            self.written = true;
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn read(bytes: &[u8], max_alerts: usize, max_scan: usize) -> io::Result<response_playbooks::batch::AlertFile> {
    read_alerts(&mut BufReader::new(Cursor::new(bytes.to_vec())), max_alerts, max_scan)
}


fn isolate() -> ProposedAction {
    ProposedAction {
        tenant: "acme".to_owned(),
        request_id: "live".to_owned(),
        kind: ActionKind::IsolateEndpoint {
            fleet_size: ROOMY as u64,
            isolated_now: 0,
        },
        target: Target {
            id: "ws-1".to_owned(),
            tags: Vec::new(),
        },
    }
}


fn nested(depth: usize) -> Value {
    (0..depth).fold(json!(1), |inner, _| json!({ "k": inner }))
}


#[test]
fn the_fixture_batch_is_a_snapshot() -> TestResult {
    let report = batch_lines("acme", &alert_lines()?, ROOMY_LIMITS)?;
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
    let big = with_field("blob", json!("a".repeat(MAX_ALERT_BYTES * TWO)));
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
fn alert_lines_are_read_bounded_and_unusable_ones_keep_their_cause() -> TestResult {
    let file = read(b"{}\n\nnope\n[1]\n{\"a\":", ROOMY, ROOMY)?;
    assert_eq!(
        file.alerts,
        [
            Line::Alert(json!({})),
            Line::Skipped(SkipReason::NotObject),
            Line::Skipped(SkipReason::NotObject),
            Line::Skipped(SkipReason::NotObject),
            Line::Skipped(SkipReason::Unreadable)
        ]
    );
    assert_eq!((file.refused, file.unreadable, file.too_long, file.unread), (THREE, 1, 0, 0));
    assert!(!file.unread_more);
    assert!(read(b"", ROOMY, ROOMY)?.alerts.is_empty());
    assert!(read_alerts(&mut BufReader::new(FailingReader), ROOMY, ROOMY).is_err());
    assert!(read_alerts(&mut BufReader::new(OnceThenFail { sent: false }), 1, ROOMY).is_err());
    assert!(read_alerts(&mut BufReader::new(EofThenFail { eof_sent: false }), 0, ROOMY).is_err());
    Ok(())
}


#[test]
fn the_reader_stops_at_the_alert_bound_and_counts_the_rest_unread() -> TestResult {
    let cut = read(b"{}\n{}\n{}\n{}\n", TWO, ROOMY)?;
    assert_eq!((cut.alerts.len(), cut.unread, cut.unread_more), (TWO, TWO, false));
    let scanned = read(b"{}\n{}\n{}\n{}\n", 1, TWO)?;
    assert_eq!((scanned.alerts.len(), scanned.unread, scanned.unread_more), (1, TWO, true));
    Ok(())
}


#[test]
fn an_overlong_line_is_discarded_to_its_newline_and_its_tail_is_never_an_alert() -> TestResult {
    let tail = br#"{"k":1}"#;
    let mut bytes = vec![b'a'; MAX_ALERT_BYTES - 1];
    bytes.extend_from_slice(b"  ");
    bytes.extend_from_slice(tail);
    bytes.extend_from_slice(b"\n{}\n");
    let file = read(&bytes, ROOMY, ROOMY)?;
    assert_eq!(file.alerts, [Line::Skipped(SkipReason::TooLong), Line::Alert(json!({}))]);
    assert_eq!((file.too_long, file.refused, file.unreadable), (1, 0, 0));
    let exact = [b"{\"k\":\"".as_slice(), &vec![b'a'; MAX_ALERT_BYTES - FRAME_BYTES], b"\"}\n"].concat();
    assert_eq!(exact.len(), MAX_ALERT_BYTES + 1);
    let fits = read(&exact, ROOMY, ROOMY)?;
    assert_eq!((fits.too_long, fits.alerts.len()), (0, 1));
    assert!(matches!(fits.alerts.first(), Some(Line::Alert(alert)) if alert.is_object()));
    let unterminated = read(&vec![b'a'; MAX_ALERT_BYTES + 1], ROOMY, ROOMY)?;
    assert_eq!((unterminated.too_long, unterminated.alerts.len()), (1, 1));
    assert!(read_alerts(&mut BufReader::new(LongThenFail { sent: false }), ROOMY, ROOMY).is_err());
    Ok(())
}


#[test]
fn the_shape_pre_pass_refuses_raw_bytes_before_any_value_is_built() -> TestResult {
    let deep = format!("{}1{}", "[".repeat(MAX_ALERT_DEPTH + 1), "]".repeat(MAX_ALERT_DEPTH + 1));
    assert_eq!(shape_refusal(format!("{{\"k\":{deep}}}").as_bytes()), Some(SkipReason::TooDeep));
    let items = vec!["1"; MAX_ALERT_NODES].join(",");
    assert_eq!(shape_refusal(format!("{{\"k\":[{items}]}}").as_bytes()), Some(SkipReason::TooManyNodes));
    let keys = (0..MAX_ALERT_NODES).map(|key| format!("\"{key}\":1")).collect::<Vec<_>>().join(",");
    assert_eq!(shape_refusal(format!("{{{keys}}}").as_bytes()), Some(SkipReason::TooManyNodes));
    let text = "a".repeat(MAX_ALERT_TEXT_BYTES);
    assert_eq!(shape_refusal(format!("{{\"k\":\"{text}\"}}").as_bytes()), Some(SkipReason::TooMuchText));
    assert_eq!(shape_refusal(b"  [1]"), Some(SkipReason::NotObject));
    assert_eq!(shape_refusal(b""), Some(SkipReason::NotObject));
    assert_eq!(shape_refusal(br#" {"a":"x\"[[[[[[[[[[[[[[[[[[[[","b":"\\","c":[1,2]}"#), None);
    let file = read(format!("{{\"k\":[{items}]}}\n{{}}\n").as_bytes(), ROOMY, ROOMY)?;
    assert_eq!((file.refused, file.alerts.get(1).cloned()), (1, Some(Line::Alert(json!({})))));
    Ok(())
}


#[test]
fn the_render_escapes_every_invisible_character_and_is_injective() -> TestResult {
    assert_eq!(escape_controls("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
    assert_eq!(escape_controls("\u{202e}x\u{202c}\u{2066}"), "\\u{202e}x\\u{202c}\\u{2066}");
    assert_eq!(escape_controls("\u{a}"), "\\u{a}");
    assert_eq!(escape_controls("\\u{a}"), "\\\\u{a}");
    assert_ne!(escape_controls("\u{a}"), escape_controls("\\u{a}"));
    assert_eq!(escape_controls("é\u{200d}"), "é\\u{200d}");
    let alert = with_field("domain", json!("x\u{202e}\u{2028}y\u{2066}"));
    let text = render_dry_run(&batch("acme", &[alert], ROOMY_LIMITS)?);
    assert!(!text.contains(['\u{202e}', '\u{2028}', '\u{2066}']));
    assert!(text.contains("\\u{202e}"));
    Ok(())
}


#[test]
fn a_batch_never_touches_the_live_counters() -> TestResult {
    let live = harness()?;
    check(&live.breakers, &isolate());
    let counters = live.dir.path().join("counters.json");
    let before = fs::read(&counters)?;
    let limits_file = live.dir.path().join("limits.yaml");
    let spent = [c2_alert(), c2_alert()];
    let loaded = bundle()?;
    (0..TWO).try_for_each(|_| dry_run_batch(&loaded, &limits_file, live.dir.path(), "acme", &lines(&spent), ROOMY_LIMITS).map(|_| ()))?;
    assert_eq!(fs::read(&counters)?, before);
    Ok(())
}


#[test]
fn a_missing_or_invalid_limits_file_is_an_error_and_a_refused_tenant_reads_none() -> TestResult {
    let live = harness()?;
    let missing = dry_run_batch(&bundle()?, &live.dir.path().join("none.yaml"), live.dir.path(), "acme", &[], ROOMY_LIMITS);
    assert!(matches!(missing, Err(DryRunError::Scratch(_))));
    let absent = live.dir.path().join("absent");
    let no_parent = dry_run_batch(&bundle()?, &live.dir.path().join("limits.yaml"), &absent, "acme", &[], ROOMY_LIMITS);
    assert!(matches!(no_parent, Err(DryRunError::Scratch(_))));
    fs::write(live.dir.path().join("bad.yaml"), "limits: [")?;
    let bad = dry_run_batch(&bundle()?, &live.dir.path().join("bad.yaml"), live.dir.path(), "acme", &[], ROOMY_LIMITS);
    assert!(matches!(bad, Err(DryRunError::Breakers(_))));
    assert!(!bad.map_or_else(|error| error.to_string(), |_| String::new()).is_empty());
    let refused = dry_run_batch(
        &bundle()?,
        Path::new("/nonexistent/limits.yaml"),
        Path::new("/nonexistent"),
        "-x",
        &lines(&[c2_alert()]),
        ROOMY_LIMITS,
    )?;
    assert!(refused.tenant_refused);
    Ok(())
}


#[test]
fn the_batch_path_never_reaches_the_real_runner_or_an_executor() -> TestResult {
    let source = fs::read_to_string(format!("{}/src/batch.rs", env!("CARGO_MANIFEST_DIR")))?;
    ["run::", "trace_for", "ConnectorFn", "ConnectorCall"]
        .iter()
        .for_each(|forbidden| assert!(!source.contains(forbidden), "batch.rs names {forbidden}"));
    assert!(source.contains("simulate(&loaded.playbook"));
    Ok(())
}


#[test]
fn a_breaker_stop_in_the_scratch_state_is_traced() -> TestResult {
    let live = harness()?;
    let strict = live.dir.path().join("strict.yaml");
    fs::write(&strict, "limits:\n  isolations_per_hour: 0\n")?;
    let report = dry_run_batch(&bundle()?, &strict, live.dir.path(), "acme", &lines(&[c2_alert()]), ROOMY_LIMITS)?;
    assert!(render_dry_run(&report).contains("waiting for approval"));
    Ok(())
}


#[test]
fn a_line_that_is_not_an_alert_keeps_its_cause_to_the_per_alert_line() -> TestResult {
    let long = [vec![b'a'; MAX_ALERT_BYTES + 1], b"\n".to_vec()].concat();
    let deep = format!("{{\"k\":{}1{}}}\n", "[".repeat(MAX_ALERT_DEPTH + 1), "]".repeat(MAX_ALERT_DEPTH + 1));
    let bytes = [
        long,
        b"[1]\n{\"a\":\n".to_vec(),
        deep.into_bytes(),
        b"{\"id\":\"x\",\"id\":\"y\"}\n{}\n".to_vec(),
    ]
    .concat();
    let file = read(&bytes, ROOMY, ROOMY)?;
    let report = batch_lines("acme", &file.alerts, ROOMY_LIMITS)?;
    let reasons: Vec<Option<SkipReason>> = report.alerts.iter().map(|run| run.skipped).collect();
    assert_eq!(
        reasons,
        [
            Some(SkipReason::TooLong),
            Some(SkipReason::NotObject),
            Some(SkipReason::Unreadable),
            Some(SkipReason::TooDeep),
            Some(SkipReason::DuplicateKey),
            None
        ]
    );
    let text = render_dry_run(&report);
    assert!(text.contains("skipped: line longer than 65536 bytes"));
    assert!(text.contains("skipped: line is not JSON"));
    assert!(text.contains("skipped: duplicate_key"));
    assert_eq!((file.too_long, file.unreadable, file.refused), (1, 1, THREE));
    Ok(())
}


#[test]
fn a_repeated_key_at_any_level_is_refused_alone() -> TestResult {
    let tenant_twice = br#"{"tenant":"other","tenant":"acme","id":"a"}"#;
    let nested_twice = br#"{"a":{"b":[{"c":1,"c":2}]}}"#;
    let escaped_twice = br#"{"a":1,"\u0061":2}"#;
    let same_in_two_objects = br#"{"a":{"k":1},"b":{"k":2},"c":["k",{"k":3}],"d":"a:b" ,"e":"x"}"#;
    let file = read(
        &[
            tenant_twice.as_slice(),
            b"\n",
            nested_twice,
            b"\n",
            escaped_twice,
            b"\n",
            same_in_two_objects,
            b"\n",
        ]
        .concat(),
        ROOMY,
        ROOMY,
    )?;
    let causes: Vec<bool> = file
        .alerts
        .iter()
        .map(|line| matches!(line, Line::Skipped(SkipReason::DuplicateKey)))
        .collect();
    assert_eq!(causes, [true, true, true, false]);
    assert_eq!(file.refused, THREE);
    let report = batch_lines("acme", &file.alerts, ROOMY_LIMITS)?;
    assert!(report
        .alerts
        .iter()
        .take(THREE)
        .all(|run| run.traces.is_empty() && run.skipped == Some(SkipReason::DuplicateKey)));
    assert_eq!(raw_keys(tenant_twice), THREE);
    assert_eq!(value_keys(&serde_json::from_slice(tenant_twice)?), TWO);
    assert_eq!(raw_keys(b"{\"a\" : 1,\"b\"\t:\n2, \"c\":\"d\"}"), THREE);
    assert_eq!(raw_keys(br#"["a","b:c",{"k":"v:w"}]"#), 1);
    Ok(())
}


#[test]
fn the_dry_run_is_written_to_an_injected_writer_and_a_failed_write_is_an_error() -> TestResult {
    let report = batch("acme", &[c2_alert()], ROOMY_LIMITS)?;
    let mut out = Vec::new();
    write_dry_run(&mut out, &report)?;
    assert_eq!(String::from_utf8(out)?, render_dry_run(&report));
    assert!(write_dry_run(&mut FailingWriter, &report).is_err());
    assert!(write_dry_run(&mut FailOnSecond { written: false }, &report).is_err());
    Ok(())
}


#[test]
fn an_unknown_asset_id_is_quoted_and_escaped() -> TestResult {
    assert_eq!(quoted("ws-1"), "\"ws-1\"");
    assert_eq!(quoted("a\" b \\"), "\"a\\\" b \\\\\"");
    assert_ne!(quoted("a\" b"), quoted("a\\\" b"));
    let ghost = with_field("host", json!({"value": "x\" y\nalert 9"}));
    let text = render_dry_run(&batch("acme", &[ghost], ROOMY_LIMITS)?);
    assert!(text.contains("unknown asset steps.2.then.0 \"x\\\\\" y"), "{text}");
    assert!(!text.lines().any(|line| line.starts_with("alert 9")));
    Ok(())
}

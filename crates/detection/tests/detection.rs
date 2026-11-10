mod common;
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;


use common::types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use detection::detect::{
    checkpoint_if_dirty, checkpoint_path, collect_alerts, detect_batch, detection_sink, engine_for, identity_of, new_detector, record_of,
    restore_state, save_all, valid_tenant,
};
use detection::error::{DetectionError, SinkError};
use detection::id::{alert_id, event_identity, payload_hash, MAX_EVENT_ID_CHARS};
use detection::model::{AlertRecord, AlertStore, Detector, MAX_ALERTS_PER_BATCH};
use detection::run::{detection_pipeline, run_detection, run_service};
use detection::settings::{load_detection_file, open_ingest, open_rules_engine};
use detection::store::{file_commit, line_id, load_seen, new_store, open_alert_store};
use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued, Stub};
use serde_json::Value;
use siem_ingest::model::{Document, Pipeline, Wiring};
use siem_ingest::pipeline::run_cycle;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stream_correlation::engine::{process_event, snapshot};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const HEX_LEN: usize = 64;


const RETRIES: usize = 200;


const SMALL_LINE: usize = 16;


const LARGE_LINE: usize = 4096;


const SMALL_IDS: usize = 1;


const HALF: usize = 2;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const WHOAMI: &str = "title: Whoami
id: whoami
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
";


const SEEN_ONCE: &str = "title: Whoami seen
id: whoami-seen
correlation:
  type: event_count
  rules:
    - whoami
  timespan: 5m
  condition:
    gte: 1
";


const SEEN_TWICE: &str = "title: Whoami twice
id: whoami-twice
correlation:
  type: event_count
  rules:
    - whoami
  timespan: 5m
  condition:
    gte: 2
";


const NOT_WHOAMI: &str = "title: Id
id: id-tool
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /id
  condition: selection
";


const ID_SEEN: &str = "title: Id seen
id: id-seen
correlation:
  type: event_count
  rules:
    - id-tool
  timespan: 5m
  condition:
    gte: 1
";


#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);


impl Write for Shared {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Flaky {
    fail: Arc<AtomicBool>,
    torn: bool,
    shared: Shared,
}


impl Write for Flaky {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::SeqCst) {
            if self.torn {
                let half = buffer.get(..buffer.len() / HALF).unwrap_or_default();
                self.shared.write_all(half)?;
            }
            Err(io::Error::other("disk full"))
        } else {
            self.shared.write(buffer)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


fn text_of(shared: &Shared) -> Result<String, Box<dyn Error + Send + Sync>> {
    let bytes = shared.0.lock().map_err(|_| "poisoned")?.clone();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}


fn parse_records(text: &str) -> Result<Vec<AlertRecord>, Box<dyn Error + Send + Sync>> {
    Ok(text.lines().flat_map(serde_json::from_str::<AlertRecord>).collect())
}


fn records_of(shared: &Shared) -> Result<Vec<AlertRecord>, Box<dyn Error + Send + Sync>> {
    parse_records(&text_of(shared)?)
}


fn event_text(id: &str, executable: &str, second: usize, extra: &str) -> String {
    format!(
        r#"{{"@timestamp":"2026-11-10T10:00:{second:02}Z","ecs":{{"version":"8.11"}},"event":{{"id":"{id}","kind":"event","category":["process"]}},"process":{{"executable":"{executable}"}},"host":{{"name":"h1"}}{extra}}}"#
    )
}


fn whoami(id: &str, second: usize) -> String {
    event_text(id, "/usr/bin/whoami", second, "")
}


fn document(payload: &str) -> Document {
    Document {
        payload: payload.as_bytes().to_vec(),
        timestamp: OffsetDateTime::UNIX_EPOCH,
    }
}


fn documents(payloads: &[String]) -> Vec<Document> {
    payloads.iter().map(|payload| document(payload)).collect()
}


fn fixed_clock() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}


fn no_sleep(_delay: Duration) {}


fn refusing_commit(_store: &AlertStore, _tenant: &str, _records: &[AlertRecord]) -> Result<usize, SinkError> {
    Err(SinkError::Write(io::Error::other("store down")))
}


struct Bench {
    dir: TempDir,
    path: PathBuf,
    rules: Arc<ReloadEngine<stream_correlation::ruleset::RuleSet>>,
    audit: Shared,
}


fn audit_fn(audit: &Shared) -> Box<core_config::types::SharedAuditFn> {
    let log = genesis_log(audit.clone());
    Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) })
}


fn context(path: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "all".to_owned(),
        module: "detection".to_owned(),
        target: path.display().to_string(),
        request_id: "test-reload".to_owned(),
    }
}


fn detection_yaml(dir: &Path, port: u16, extra: &str) -> String {
    let base = dir.display();
    format!(
        "audit_file: {base}/audit.log\ncheckpoint_dir: {base}/checkpoints\nalerts_file: {base}/alerts.jsonl\nmapping_file: {base}/mapping.yaml\nrule_files:\n  - {base}/rules.yaml\ningest:\n  nats_url: \"nats://127.0.0.1:{port}\"\n  nats_fetch_deadline_ms: 200\n  nats_request_timeout_ms: 5000\n  max_batch_messages: 1\n  retry_attempts: 1\n  nats_consumer: detection\n{extra}"
    )
}


fn write_bench(rules: &[&str], port: u16, extra: &str) -> Result<(TempDir, PathBuf), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let path = dir.path().join("detection.yaml");
    fs::write(dir.path().join("mapping.yaml"), MAPPING)?;
    fs::write(dir.path().join("rules.yaml"), rules.join("\n---\n"))?;
    fs::write(&path, detection_yaml(dir.path(), port, extra))?;
    Ok((dir, path))
}


fn bench(rules: &[&str]) -> Result<Bench, Box<dyn Error + Send + Sync>> {
    let (dir, path) = write_bench(rules, 1, "")?;
    let audit = Shared::default();
    let engine = open_rules_engine(path.clone(), audit_fn(&audit), context(&path))?;
    Ok(Bench {
        dir,
        path,
        rules: Arc::new(engine),
        audit,
    })
}


fn memory_store(writer: Flaky, fail_sync: Arc<AtomicBool>) -> Arc<AlertStore> {
    Arc::new(new_store(
        Box::new(writer),
        Box::new(move || {
            if fail_sync.load(Ordering::SeqCst) {
                Err(io::Error::other("sync failed"))
            } else {
                Ok(())
            }
        }),
        HashSet::new(),
        false,
    ))
}


struct Gear {
    detector: Detector,
    output: Shared,
    fail: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
}


fn gear(bench: &Bench, limits: (usize, usize)) -> Gear {
    let output = Shared::default();
    let fail = Arc::new(AtomicBool::new(false));
    let fail_sync = Arc::new(AtomicBool::new(false));
    let writer = Flaky {
        fail: Arc::clone(&fail),
        torn: false,
        shared: output.clone(),
    };
    let detector = new_detector(
        Arc::clone(&bench.rules),
        memory_store(writer, Arc::clone(&fail_sync)),
        file_commit,
        limits,
        bench.dir.path().join("checkpoints"),
    );
    Gear {
        detector,
        output,
        fail,
        fail_sync,
    }
}


fn default_gear(bench: &Bench) -> Gear {
    gear(bench, (MAX_ALERTS_PER_BATCH, THREE))
}


#[test]
fn the_alert_id_is_stable_and_order_independent() -> TestResult {
    let first = vec!["e1".to_owned(), "e2".to_owned()];
    let reversed = vec!["e2".to_owned(), "e1".to_owned()];
    let id = alert_id("a", "rule", &first);
    assert_eq!(id, alert_id("a", "rule", &reversed));
    assert_eq!(id.len(), HEX_LEN);
    assert!(id.chars().all(|digit| digit.is_ascii_hexdigit()));
    Ok(())
}


#[test]
fn the_alert_id_changes_with_tenant_rule_and_events() -> TestResult {
    let events = vec!["e1".to_owned()];
    let id = alert_id("a", "rule", &events);
    assert_ne!(id, alert_id("b", "rule", &events));
    assert_ne!(id, alert_id("a", "other", &events));
    assert_ne!(id, alert_id("a", "rule", &["e2".to_owned()]));
    assert_ne!(id, alert_id("a", "rule", &["e1".to_owned(), "e1".to_owned()]));
    Ok(())
}


#[test]
fn the_alert_id_is_length_prefixed() -> TestResult {
    assert_ne!(alert_id("ab", "c", &[]), alert_id("a", "bc", &[]));
    assert_ne!(alert_id("a", "b", &["c".to_owned()]), alert_id("a", "bc", &[]));
    Ok(())
}


#[test]
fn an_event_identity_carries_the_id_and_the_payload_hash() -> TestResult {
    let hash = payload_hash(b"payload");
    assert_eq!(event_identity(Some("e1"), b"payload"), format!("e1:{hash}"));
    assert_eq!(event_identity(None, b"payload"), hash);
    let long = "x".repeat(MAX_EVENT_ID_CHARS + THREE);
    let identity = event_identity(Some(&long), b"payload");
    assert_eq!(identity.len(), MAX_EVENT_ID_CHARS + 1 + hash.len());
    Ok(())
}


#[test]
fn the_same_event_id_with_another_payload_gets_another_identity() -> TestResult {
    let first: Value = serde_json::from_str(&whoami("same", 0))?;
    let second: Value = serde_json::from_str(&whoami("same", 1))?;
    assert_ne!(
        identity_of(&first, whoami("same", 0).as_bytes()),
        identity_of(&second, whoami("same", 1).as_bytes())
    );
    let anonymous: Value = serde_json::from_str("{}")?;
    assert_eq!(identity_of(&anonymous, b"{}"), payload_hash(b"{}"));
    Ok(())
}


#[test]
fn a_matching_event_produces_one_stored_alert_under_the_batch_tenant() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    let records = records_of(&gear.output)?;
    assert_eq!(records.len(), 1);
    let record = records.first().ok_or("no record")?;
    assert_eq!((record.tenant.as_str(), record.rule_id.as_str()), ("a", "whoami-seen"));
    assert!(record.event_ids.first().ok_or("no event")?.starts_with("e1:"));
    assert_eq!(record.id, alert_id("a", "whoami-seen", &record.event_ids));
    assert!(gear.detector.dirty.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn a_payload_that_claims_another_tenant_is_stored_under_the_subject_tenant() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    let claim = event_text("e1", "/bin/whoami", 0, r#","tenant":"b","organization":{"id":"b"}"#);
    detect_batch(&gear.detector, "a", &documents(&[claim]))?;
    let records = records_of(&gear.output)?;
    assert_eq!(records.iter().map(|record| record.tenant.as_str()).collect::<Vec<_>>(), ["a"]);
    assert!(!text_of(&gear.output)?.contains("\"tenant\":\"b\""));
    Ok(())
}


#[test]
fn windows_never_mix_tenants() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("a1", 0)]))?;
    detect_batch(&gear.detector, "b", &documents(&[whoami("b1", 1)]))?;
    assert!(records_of(&gear.output)?.is_empty());
    detect_batch(&gear.detector, "a", &documents(&[whoami("a2", TWO)]))?;
    let records = records_of(&gear.output)?;
    assert_eq!(records.len(), 1);
    let record = records.first().ok_or("no record")?;
    assert_eq!(record.tenant, "a");
    assert!(record.event_ids.iter().all(|event| event.starts_with('a')));
    Ok(())
}


#[test]
fn the_alerts_of_one_batch_are_capped_and_the_excess_is_counted() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = gear(&bench, (TWO, THREE));
    let payloads: Vec<String> = (0..FIVE).map(|second| whoami(&format!("e{second}"), second)).collect();
    detect_batch(&gear.detector, "a", &documents(&payloads))?;
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    assert_eq!(gear.detector.refused.load(Ordering::SeqCst), THREE as u64);
    Ok(())
}


#[test]
fn a_store_failure_fails_the_batch_and_the_redelivery_yields_one_alert() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    let gear = default_gear(&bench);
    let first = documents(&[whoami("e1", 0)]);
    let second = documents(&[whoami("e2", 1)]);
    detect_batch(&gear.detector, "a", &first)?;
    gear.fail.store(true, Ordering::SeqCst);
    assert!(detect_batch(&gear.detector, "a", &second).is_err());
    assert!(detect_batch(&gear.detector, "a", &second).is_err());
    gear.fail.store(false, Ordering::SeqCst);
    detect_batch(&gear.detector, "a", &second)?;
    detect_batch(&gear.detector, "a", &second)?;
    let records = records_of(&gear.output)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records.first().ok_or("no record")?.event_ids.len(), TWO);
    Ok(())
}


#[test]
fn a_failed_batch_restores_the_windows() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    let mut gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    let engine = engine_for(&gear.detector, "a")?;
    let before = snapshot(&engine);
    gear.detector.commit = refusing_commit;
    assert!(detect_batch(&gear.detector, "a", &documents(&[whoami("e2", 1)])).is_err());
    assert_eq!(snapshot(&engine), before);
    let sink = detection_sink(Arc::new(gear.detector));
    assert!(sink("a", &documents(&[whoami("e2", 1)])).is_err());
    Ok(())
}


#[test]
fn a_payload_that_is_not_json_is_counted_and_skipped() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    let engine = engine_for(&gear.detector, "a")?;
    let invalid = AtomicU64::new(0);
    let alerts = collect_alerts(&engine, &documents(&["not json".to_owned(), whoami("e1", 0)]), &invalid);
    assert_eq!((alerts.len(), invalid.load(Ordering::SeqCst)), (1, 1));
    let record = record_of("a", alerts.into_iter().next().ok_or("no alert")?);
    assert_eq!(record.tenant, "a");
    Ok(())
}


#[test]
fn only_a_plain_tenant_gets_an_engine_and_their_number_is_capped() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = gear(&bench, (MAX_ALERTS_PER_BATCH, TWO));
    assert!(valid_tenant("tenant-1_a"));
    assert!(!valid_tenant(""));
    assert!(!valid_tenant("../x"));
    assert!(matches!(engine_for(&gear.detector, "../x"), Err(DetectionError::InvalidTenant)));
    assert!(matches!(engine_for(&gear.detector, ""), Err(DetectionError::InvalidTenant)));
    engine_for(&gear.detector, "a")?;
    engine_for(&gear.detector, "b")?;
    engine_for(&gear.detector, "a")?;
    assert!(matches!(
        engine_for(&gear.detector, "c"),
        Err(DetectionError::TooManyTenants { max: TWO })
    ));
    Ok(())
}


#[test]
fn the_windows_survive_a_restart_through_the_checkpoint() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    fs::create_dir_all(bench.dir.path().join("checkpoints"))?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("a1", 0)]))?;
    assert_eq!(save_all(&gear.detector)?, 1);
    let restarted = default_gear(&bench);
    detect_batch(&restarted.detector, "a", &documents(&[whoami("a2", 1)]))?;
    assert_eq!(records_of(&restarted.output)?.len(), 1);
    Ok(())
}


#[test]
fn a_corrupt_checkpoint_refuses_the_tenant_and_a_failed_save_stays_dirty() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("a1", 0)]))?;
    assert!(save_all(&gear.detector).is_err());
    checkpoint_if_dirty(&gear.detector);
    assert!(gear.detector.dirty.load(Ordering::SeqCst));
    fs::create_dir_all(bench.dir.path().join("checkpoints"))?;
    checkpoint_if_dirty(&gear.detector);
    assert!(!gear.detector.dirty.load(Ordering::SeqCst));
    checkpoint_if_dirty(&gear.detector);
    fs::write(checkpoint_path(&bench.dir.path().join("checkpoints"), "z"), "not a checkpoint")?;
    assert!(matches!(engine_for(&gear.detector, "z"), Err(DetectionError::Correlation(_))));
    Ok(())
}


#[test]
fn restoring_a_saved_state_puts_the_windows_back() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    let gear = default_gear(&bench);
    let engine = engine_for(&gear.detector, "a")?;
    let empty = snapshot(&engine);
    let event: Value = serde_json::from_str(&whoami("e1", 0))?;
    process_event(&engine, "e1", &event);
    assert_ne!(snapshot(&engine), empty);
    restore_state(&engine, empty.clone());
    assert_eq!(snapshot(&engine), empty);
    Ok(())
}


#[test]
fn the_rules_reload_live_and_an_invalid_file_keeps_the_old_ones() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    let rules_file = bench.dir.path().join("rules.yaml");
    fs::write(&rules_file, "title: broken\ncorrelation:\n  type: sequence\n")?;
    assert!(matches!(reload(&bench.rules), ReloadOutcome::Refused { .. }));
    detect_batch(&gear.detector, "a", &documents(&[whoami("e2", 1)]))?;
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    assert!(text_of(&bench.audit)?.contains("refused"));
    fs::write(&rules_file, [NOT_WHOAMI, ID_SEEN].join("\n---\n"))?;
    assert!(matches!(reload(&bench.rules), ReloadOutcome::Applied { .. }));
    detect_batch(&gear.detector, "a", &documents(&[whoami("e3", THREE)]))?;
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    detect_batch(&gear.detector, "a", &documents(&[event_text("e4", "/usr/bin/id", FIVE, "")]))?;
    assert_eq!(records_of(&gear.output)?.len(), THREE);
    Ok(())
}


#[test]
fn a_change_of_the_rule_file_list_applies_through_the_service_file() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let other = bench.dir.path().join("more.yaml");
    fs::write(&other, [NOT_WHOAMI, ID_SEEN].join("\n---\n"))?;
    fs::write(
        &bench.path,
        detection_yaml(bench.dir.path(), 1, "").replace("rules.yaml\n", &format!("rules.yaml\n  - {}\n", other.display())),
    )?;
    assert!(matches!(reload(&bench.rules), ReloadOutcome::Applied { .. }));
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[event_text("e1", "/usr/bin/id", 0, "")]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    Ok(())
}


#[test]
fn the_ingest_settings_take_the_detection_consumer_and_refuse_a_bad_change() -> TestResult {
    let (dir, path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "")?;
    let audit = Shared::default();
    let engine = open_ingest(path.clone(), audit_fn(&audit), context(&path))?;
    assert_eq!(current_config(&engine).nats_consumer, "detection");
    fs::write(
        &path,
        detection_yaml(dir.path(), 1, "").replace("nats_consumer: detection", "nats_consumer: siem-ingest"),
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).nats_consumer, "detection");
    assert!(matches!(
        open_ingest(path.clone(), audit_fn(&audit), context(&path)),
        Err(DetectionError::Ingest(_))
    ));
    fs::write(&path, detection_yaml(dir.path(), 1, "  max_batch_messages: 0\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).max_batch_messages, 1);
    assert!(text_of(&audit)?.contains("refused"));
    fs::write(
        &path,
        detection_yaml(dir.path(), 1, "").replace("nats_consumer: detection", "nats_consumer: other"),
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).nats_consumer, "other");
    Ok(())
}


#[test]
fn first_settings_must_be_valid_and_known() -> TestResult {
    let (dir, path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "  max_batch_messages: 0\n")?;
    let audit = Shared::default();
    let invalid = open_ingest(path.clone(), audit_fn(&audit), context(&path));
    assert!(matches!(invalid, Err(DetectionError::Config(_) | DetectionError::Ingest(_))));
    fs::write(&path, detection_yaml(dir.path(), 1, "").replace("ingest:", "unknown: 1\ningest:"))?;
    assert!(load_detection_file(&path).is_err());
    assert!(open_rules_engine(path.clone(), audit_fn(&audit), context(&path)).is_err());
    fs::write(&path, detection_yaml(dir.path(), 1, "  nats_user: someone\n"))?;
    assert!(matches!(
        open_ingest(path.clone(), audit_fn(&audit), context(&path)),
        Err(DetectionError::Ingest(_))
    ));
    Ok(())
}


fn record(id: &str, tenant: &str) -> AlertRecord {
    AlertRecord {
        id: id.to_owned(),
        tenant: tenant.to_owned(),
        rule_id: "rule".to_owned(),
        rule_title: "Rule".to_owned(),
        group: Default::default(),
        first_ms: 0,
        last_ms: 1,
        event_ids: vec!["e1".to_owned()],
    }
}


fn line_of(id: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    Ok(serde_json::to_string(&record(id, "a"))?)
}


#[test]
fn the_file_sink_stores_each_alert_once_and_counts_the_new_ones() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    let store = &gear.detector.store;
    let batch = vec![record("x1", "a"), record("x2", "a"), record("x1", "a")];
    assert_eq!(file_commit(store, "a", &batch)?, TWO);
    assert_eq!(file_commit(store, "a", &batch)?, 0);
    assert_eq!(file_commit(store, "a", &[])?, 0);
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    assert!(matches!(file_commit(store, "a", &[record("x3", "b")]), Err(SinkError::TenantMismatch)));
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    Ok(())
}


#[test]
fn a_failed_write_is_an_error_and_the_retry_starts_on_a_new_line() -> TestResult {
    let output = Shared::default();
    let fail = Arc::new(AtomicBool::new(true));
    let writer = Flaky {
        fail: Arc::clone(&fail),
        torn: true,
        shared: output.clone(),
    };
    let store = memory_store(writer, Arc::new(AtomicBool::new(false)));
    let batch = vec![record("x1", "a"), record("x2", "a")];
    assert!(matches!(file_commit(&store, "a", &batch), Err(SinkError::Write(_))));
    fail.store(false, Ordering::SeqCst);
    assert_eq!(file_commit(&store, "a", &batch)?, TWO);
    let text = text_of(&output)?;
    assert_eq!(parse_records(&text)?.len(), TWO);
    assert!(text.contains("\n{"));
    Ok(())
}


#[test]
fn a_failed_sync_is_an_error_and_the_next_call_syncs_again() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    gear.fail_sync.store(true, Ordering::SeqCst);
    let batch = vec![record("x1", "a")];
    assert!(matches!(file_commit(&gear.detector.store, "a", &batch), Err(SinkError::Sync(_))));
    assert!(matches!(file_commit(&gear.detector.store, "a", &batch), Err(SinkError::Sync(_))));
    gear.fail_sync.store(false, Ordering::SeqCst);
    assert_eq!(file_commit(&gear.detector.store, "a", &batch)?, 0);
    assert_eq!(records_of(&gear.output)?.len(), 1);
    Ok(())
}


#[test]
fn the_ids_in_a_file_are_read_and_damaged_lines_are_skipped() -> TestResult {
    let mut bytes = format!("{}\n\n{{\"id\":\"cut\n{}\n", line_of("x1")?, line_of("x2")?).into_bytes();
    bytes.extend_from_slice(b"\xff\xfe\n");
    bytes.extend_from_slice(line_of("x3")?.as_bytes());
    let seen = load_seen(&mut BufReader::new(bytes.as_slice()), LARGE_LINE, SMALL_LINE)?;
    assert_eq!(seen, HashSet::from(["x1".to_owned(), "x2".to_owned(), "x3".to_owned()]));
    assert_eq!(line_id("   ", 1), None);
    assert_eq!(line_id("{", 1), None);
    Ok(())
}


#[test]
fn an_oversized_line_too_many_ids_or_a_read_error_refuse_the_file() -> TestResult {
    let long = format!("{}\n", line_of("x1")?);
    assert!(matches!(
        load_seen(&mut BufReader::new(long.as_bytes()), SMALL_LINE, SMALL_LINE),
        Err(SinkError::LineTooLong { line: 1 })
    ));
    let two = format!("{}\n{}\n", line_of("x1")?, line_of("x2")?);
    assert!(matches!(
        load_seen(&mut BufReader::new(two.as_bytes()), LARGE_LINE, SMALL_IDS),
        Err(SinkError::TooManyAlerts { max: SMALL_IDS })
    ));
    assert!(matches!(
        load_seen(&mut BufReader::new(Broken), LARGE_LINE, SMALL_LINE),
        Err(SinkError::Read(_))
    ));
    Ok(())
}


#[test]
fn the_alerts_file_keeps_its_ids_across_a_restart_and_a_torn_tail() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let first = open_alert_store(&path)?;
    assert_eq!(file_commit(&first, "a", &[record("x1", "a"), record("x2", "a")])?, TWO);
    drop(first);
    let mut tail = fs::OpenOptions::new().append(true).open(&path)?;
    tail.write_all(b"{\"id\":\"torn")?;
    drop(tail);
    let second = open_alert_store(&path)?;
    assert_eq!(file_commit(&second, "a", &[record("x1", "a"), record("x3", "a")])?, 1);
    drop(second);
    let text = fs::read_to_string(&path)?;
    let ids: Vec<String> = parse_records(&text)?.into_iter().map(|stored| stored.id).collect();
    assert_eq!(ids, ["x1", "x2", "x3"]);
    assert_eq!(open_alert_store(&path)?.inner.lock().map_err(|_| "poisoned")?.seen.len(), THREE);
    Ok(())
}


#[test]
fn an_alerts_file_that_cannot_be_opened_is_an_error() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(
        open_alert_store(dir.path()),
        Err(SinkError::Open { .. }) | Err(SinkError::Read(_))
    ));
    assert!(matches!(
        open_alert_store(&dir.path().join("missing").join("alerts")),
        Err(SinkError::Open { .. })
    ));
    Ok(())
}


struct Rig {
    bench: Bench,
    stub: Stub,
    detector: Arc<Detector>,
    output: Shared,
    fail: Arc<AtomicBool>,
    pipeline: Pipeline,
}


fn queued(subject: &str, payload: &str) -> Queued {
    Queued {
        subject: subject.to_owned(),
        payload: payload.as_bytes().to_vec(),
        extra_headers: 0,
        repeated_values: 0,
    }
}


fn rig(rules: &[&str]) -> Result<Rig, Box<dyn Error + Send + Sync>> {
    let stub = start_stub(None, |_| ())?;
    let (dir, path) = write_bench(rules, stub.port, "")?;
    let audit = Shared::default();
    let rules_engine = Arc::new(open_rules_engine(path.clone(), audit_fn(&audit), context(&path))?);
    let ingest = Arc::new(open_ingest(path.clone(), audit_fn(&audit), context(&path))?);
    let bench = Bench {
        dir,
        path,
        rules: Arc::clone(&rules_engine),
        audit,
    };
    let Gear {
        detector: bare,
        output,
        fail,
        ..
    } = default_gear(&bench);
    let detector = Arc::new(bare);
    let wiring = siem_ingest::nats::nats_wiring(Arc::clone(&ingest))?;
    let pipeline = detection_pipeline(ingest, Arc::clone(&detector), wiring, (fixed_clock, no_sleep));
    Ok(Rig {
        bench,
        stub,
        detector,
        output,
        fail,
        pipeline,
    })
}


fn acks(rig: &Rig) -> Vec<String> {
    lock(&rig.stub.hub).acks.clone()
}


#[test]
fn a_matching_event_is_stored_then_acknowledged() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e1", 0)));
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!((report.fetched, report.acknowledged), (1, 1));
    wait_until(&rig.stub, |state| state.acks.len() == 1)?;
    assert_eq!(acks(&rig), ["+ACK"]);
    assert_eq!(records_of(&rig.output)?.len(), 1);
    assert!(rig.bench.path.exists());
    Ok(())
}


#[test]
fn a_failing_store_leaves_the_message_unacknowledged_and_the_redelivery_stores_one_alert() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    let payload = whoami("e1", 0);
    rig.fail.store(true, Ordering::SeqCst);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &payload));
    let failed = run_cycle(&mut rig.pipeline)?;
    assert_eq!((failed.acknowledged, failed.redelivered), (0, 1));
    wait_until(&rig.stub, |state| state.acks.len() == 1)?;
    assert_eq!(acks(&rig), ["-NAK"]);
    assert!(records_of(&rig.output)?.is_empty());
    rig.fail.store(false, Ordering::SeqCst);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &payload));
    run_cycle(&mut rig.pipeline)?;
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &payload));
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| state.acks.len() == THREE)?;
    assert_eq!(acks(&rig), ["-NAK", "+ACK", "+ACK"]);
    assert_eq!(records_of(&rig.output)?.len(), 1);
    Ok(())
}


#[test]
fn an_event_published_for_one_tenant_never_alerts_under_another() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    let claim = event_text("e1", "/bin/whoami", 0, r#","tenant":"b""#);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &claim));
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| !state.acks.is_empty())?;
    let records = records_of(&rig.output)?;
    assert_eq!(records.iter().map(|stored| stored.tenant.as_str()).collect::<Vec<_>>(), ["a"]);
    lock(&rig.stub.hub).queue.push_back(queued("events.b", &whoami("e2", 1)));
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| state.acks.len() == TWO)?;
    let tenants: Vec<String> = records_of(&rig.output)?.into_iter().map(|stored| stored.tenant).collect();
    assert_eq!(tenants, ["a", "b"]);
    assert!(rig.detector.engines.lock().map_err(|_| "poisoned")?.contains_key("b"));
    Ok(())
}


#[test]
fn a_failing_fetch_backs_off_and_the_loop_ends_with_a_checkpoint() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    fs::create_dir_all(bench.dir.path().join("checkpoints"))?;
    let audit = Shared::default();
    let ingest = Arc::new(open_ingest(bench.path.clone(), audit_fn(&audit), context(&bench.path))?);
    let detector = Arc::new(default_gear(&bench).detector);
    let wiring = Wiring {
        fetch: Box::new(|_| Err("bus down".into())),
        ack: Box::new(|_, _| Ok(())),
        dead_letter: Box::new(|_, _, _| Ok(())),
    };
    let mut pipeline = detection_pipeline(ingest, Arc::clone(&detector), wiring, (fixed_clock, no_sleep));
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let stop = Box::new(move || counter.fetch_add(1, Ordering::SeqCst) >= THREE);
    let summary = run_detection(&mut pipeline, Arc::clone(&detector), stop)?;
    assert_eq!((summary.cycles, summary.fetch_failures), (THREE as u64, THREE as u64));
    Ok(())
}


#[test]
fn the_loop_saves_the_windows_after_a_committed_batch_and_a_final_save_failure_is_an_error() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_TWICE])?;
    let gear = default_gear(&bench);
    let detector = Arc::new(gear.detector);
    let (_dir, path) = write_bench(&[WHOAMI, SEEN_TWICE], 1, "")?;
    let audit = Shared::default();
    let ingest = Arc::new(open_ingest(path.clone(), audit_fn(&audit), context(&path))?);
    let feeding = Arc::clone(&detector);
    let wiring = Wiring {
        fetch: Box::new(move |_| {
            detect_batch(&feeding, "a", &documents(&[whoami("e1", 0)]))?;
            Ok(Vec::new())
        }),
        ack: Box::new(|_, _| Ok(())),
        dead_letter: Box::new(|_, _, _| Ok(())),
    };
    let mut pipeline = detection_pipeline(ingest, Arc::clone(&detector), wiring, (fixed_clock, no_sleep));
    let stop_after = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&stop_after);
    let outcome = run_detection(
        &mut pipeline,
        Arc::clone(&detector),
        Box::new(move || counter.fetch_add(1, Ordering::SeqCst) >= TWO),
    );
    assert!(outcome.is_err());
    fs::create_dir_all(bench.dir.path().join("checkpoints"))?;
    let again = run_detection(&mut pipeline, Arc::clone(&detector), Box::new(|| true))?;
    assert_eq!(again.cycles, 0);
    assert!(checkpoint_path(&bench.dir.path().join("checkpoints"), "a").exists());
    Ok(())
}


fn service_files(extra: &str) -> Result<(TempDir, Stub, PathBuf), Box<dyn Error + Send + Sync>> {
    let stub = start_stub(None, |_| ())?;
    let (dir, path) = write_bench(&[WHOAMI, SEEN_TWICE], stub.port, extra)?;
    Ok((dir, stub, path))
}


#[test]
fn the_service_runs_over_the_bus_and_survives_a_restart_without_a_duplicate_alert() -> TestResult {
    let (dir, stub, path) = service_files("")?;
    let payloads = [whoami("e1", 0), whoami("e2", 1)];
    payloads
        .iter()
        .for_each(|payload| lock(&stub.hub).queue.push_back(queued("events.a", payload)));
    let first = Arc::clone(&stub.hub);
    let stop = Box::new(move || lock(&first).acks.len() >= TWO);
    let summary = run_service(&path, stop, file_commit)?;
    assert!(summary.cycles > 0);
    let alerts_file = dir.path().join("alerts.jsonl");
    assert_eq!(parse_records(&fs::read_to_string(&alerts_file)?)?.len(), 1);
    assert!(dir.path().join("checkpoints").join("a.json").exists());
    assert!(fs::read_to_string(dir.path().join("audit.log"))?.is_empty());
    payloads
        .iter()
        .for_each(|payload| lock(&stub.hub).queue.push_back(queued("events.a", payload)));
    let second = Arc::clone(&stub.hub);
    let restart_stop = Box::new(move || lock(&second).acks.len() >= TWO * TWO);
    run_service(&path, restart_stop, file_commit)?;
    assert_eq!(parse_records(&fs::read_to_string(&alerts_file)?)?.len(), 1);
    Ok(())
}


#[test]
fn the_service_refuses_to_start_on_a_bad_file() -> TestResult {
    let (dir, path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "")?;
    fs::write(dir.path().join("rules.yaml"), "title: broken\ncorrelation:\n  type: sequence\n")?;
    assert!(run_service(&path, Box::new(|| true), file_commit).is_err());
    fs::write(&path, "audit_file: x\n")?;
    assert!(run_service(&path, Box::new(|| true), file_commit).is_err());
    Ok(())
}


#[test]
fn a_document_the_batcher_refuses_is_dead_lettered_not_detected() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    lock(&rig.stub.hub).queue.push_back(queued("events.a", "not json"));
    let report = run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| !state.published.is_empty() && !state.acks.is_empty())?;
    assert_eq!(report.dead_lettered, 1);
    let state = lock(&rig.stub.hub);
    let letter = state.published.first().ok_or("no dead letter")?;
    assert_eq!(letter.subject, "dead.events");
    assert!(letter.headers.contains("Ostyr-Tenant: a"));
    assert_eq!(letter.payload, b"not json");
    assert!(records_of(&rig.output)?.is_empty());
    Ok(())
}


#[test]
fn the_loop_recovers_after_the_server_drops_every_connection() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e1", 0)));
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| state.acks.len() == 1)?;
    kill_connections(&rig.stub);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e2", 1)));
    let recovered = (0..RETRIES).any(|_| run_cycle(&mut rig.pipeline).is_ok_and(|report| report.acknowledged > 0));
    assert!(recovered);
    assert_eq!(records_of(&rig.output)?.len(), TWO);
    Ok(())
}

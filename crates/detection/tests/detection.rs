#[path = "postgres/certs.rs"]
mod certs;
mod common;
#[path = "postgres/fake.rs"]
mod fake;
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;
#[path = "postgres/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::Severity;
use alerts::types::RowFuture;
use certs::{loopback, make_pki};
use common::types::{Tables, TestResult};
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use detection::detect::{
    checkpoint_if_dirty, checkpoint_path, collect_alerts, commit_in_place, detect_batch, detection_sink, engine_for, identity_of, is_permanent,
    new_detector, record_of, restore_state, save_all, valid_tenant,
};
use detection::error::{DetectionError, SinkError};
use detection::id::{event_identity, payload_hash, MAX_EVENT_ID_CHARS};
use detection::model::{
    AlertRecord, AlertStore, CommitPolicy, Detector, FixedPaths, PgStore, SinkKind, MAX_ALERTS_PER_BATCH, MAX_ALERT_LINE_BYTES, MAX_GROUP_FIELDS,
    MAX_STORED_EVENT_IDS,
};
use detection::pg::{alert_of, commit_pg, commit_with, open_pg_store, pg_commit, screen_records, severity_of, system_micros};
use detection::run::{detection_pipeline, run_detection, run_service};
use detection::settings::{check_backoff, check_fixed, fixed_paths, load_detection_file, open_ingest, open_pg_engine, open_rules_engine};
use detection::store::{
    bound_record, commit_alerts, cut_text, file_commit, line_id, load_seen, move_file, new_store, open_alert_store, rotate_to_new, rotated_name,
    sync_directory, temp_name, OMITTED_KEY,
};
use detection::types::{AlertSyncFn, AlertWriter, RotateFn};
use fake::{Fake, Mode, Reply};
use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued, Stub};
use rcgen::SanType;
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
use stream_correlation::level::Level;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use tokio::runtime::{Builder, Runtime};
use types::Handler;


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
    flakes: Arc<AtomicUsize>,
    torn: bool,
    shared: Shared,
}


fn spend_flake(flakes: &AtomicUsize) -> bool {
    flakes.try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1)).is_ok()
}


impl Write for Flaky {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::SeqCst) || spend_flake(&self.flakes) {
            if self.torn {
                let half = buffer.get(..buffer.len() / HALF).unwrap_or(&[]);
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
    ingest: Arc<ReloadEngine<siem_ingest::settings::IngestSettings>>,
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


fn bench_with(rules: &[&str], extra: &str) -> Result<Bench, Box<dyn Error + Send + Sync>> {
    let (dir, path) = write_bench(rules, 1, extra)?;
    let audit = Shared::default();
    let engine = open_rules_engine(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?;
    let ingest = open_ingest(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?;
    Ok(Bench {
        dir,
        path,
        rules: Arc::new(engine),
        ingest: Arc::new(ingest),
        audit,
    })
}


fn bench(rules: &[&str]) -> Result<Bench, Box<dyn Error + Send + Sync>> {
    bench_with(rules, "")
}


fn fixed_of(path: &Path) -> Result<FixedPaths, Box<dyn Error + Send + Sync>> {
    Ok(fixed_paths(&load_detection_file(path)?))
}


fn no_rotation() -> RotateFn {
    Box::new(|| Err(io::Error::other("no rotation")))
}


fn memory_store(writer: Flaky, fail_sync: Arc<AtomicBool>) -> Arc<AlertStore> {
    let sync: AlertSyncFn = Box::new(move || {
        if fail_sync.load(Ordering::SeqCst) {
            Err(io::Error::other("sync failed"))
        } else {
            Ok(())
        }
    });
    let output: (AlertWriter, AlertSyncFn) = (Box::new(writer), sync);
    Arc::new(new_store(output, no_rotation(), HashSet::new(), false, usize::MAX))
}


fn seen_of(store: &AlertStore) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
    match store {
        AlertStore::File(inner) => Ok(inner.lock().map_err(|_| "poisoned")?.seen.clone()),
        AlertStore::Postgres(_) => Err("not a file store".into()),
    }
}


struct Gear {
    detector: Detector,
    output: Shared,
    fail: Arc<AtomicBool>,
    flakes: Arc<AtomicUsize>,
    fail_sync: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    progress_calls: Arc<AtomicUsize>,
    progress_fails: Arc<AtomicBool>,
}


fn gear(bench: &Bench, limits: (usize, usize)) -> Gear {
    let output = Shared::default();
    let fail = Arc::new(AtomicBool::new(false));
    let flakes = Arc::new(AtomicUsize::new(0));
    let fail_sync = Arc::new(AtomicBool::new(false));
    let stopping = Arc::new(AtomicBool::new(true));
    let progress_calls = Arc::new(AtomicUsize::new(0));
    let progress_fails = Arc::new(AtomicBool::new(false));
    let writer = Flaky {
        fail: Arc::clone(&fail),
        flakes: Arc::clone(&flakes),
        torn: false,
        shared: output.clone(),
    };
    let stop_flag = Arc::clone(&stopping);
    let calls = Arc::clone(&progress_calls);
    let failing = Arc::clone(&progress_fails);
    let policy = CommitPolicy {
        ingest: Arc::clone(&bench.ingest),
        progress: Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            if failing.load(Ordering::SeqCst) {
                Err("bus refused".into())
            } else {
                Ok(())
            }
        }),
        stop: Arc::new(move || stop_flag.load(Ordering::SeqCst)),
        sleep: no_sleep,
        max_attempts: RETRIES as u32,
    };
    let detector = new_detector(
        Arc::clone(&bench.rules),
        memory_store(writer, Arc::clone(&fail_sync)),
        file_commit,
        limits,
        bench.dir.path().join("checkpoints"),
        policy,
    );
    Gear {
        detector,
        output,
        fail,
        flakes,
        fail_sync,
        stopping,
        progress_calls,
        progress_fails,
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
    assert!(!valid_tenant("-x"));
    assert!(!valid_tenant("_x"));
    assert!(!valid_tenant(&"a".repeat(core_pg::scope::MAX_TENANT_BYTES + 1)));
    assert!(valid_tenant("a.b-c_d"));
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
    assert!(detect_batch(&gear.detector, "z", &documents(&[whoami("z1", 0)])).is_err());
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
    let engine = open_ingest(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?;
    assert_eq!(current_config(&engine).nats_consumer, "detection");
    fs::write(
        &path,
        detection_yaml(dir.path(), 1, "").replace("nats_consumer: detection", "nats_consumer: siem-ingest"),
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).nats_consumer, "detection");
    assert!(matches!(
        open_ingest(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path)),
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
    let (dir, path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "")?;
    let baseline = fixed_of(&path)?;
    fs::write(&path, detection_yaml(dir.path(), 1, "  max_batch_messages: 0\n"))?;
    let audit = Shared::default();
    let invalid = open_ingest(path.clone(), baseline.clone(), audit_fn(&audit), context(&path));
    assert!(matches!(invalid, Err(DetectionError::Config(_) | DetectionError::Ingest(_))));
    fs::write(&path, detection_yaml(dir.path(), 1, "").replace("ingest:", "unknown: 1\ningest:"))?;
    assert!(load_detection_file(&path).is_err());
    assert!(open_rules_engine(path.clone(), baseline.clone(), audit_fn(&audit), context(&path)).is_err());
    fs::write(&path, detection_yaml(dir.path(), 1, "  nats_user: someone\n"))?;
    assert!(matches!(
        open_ingest(path.clone(), baseline, audit_fn(&audit), context(&path)),
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
        level: Level::Medium,
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
        flakes: Arc::new(AtomicUsize::new(0)),
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
fn after_a_failed_sync_the_ids_are_not_remembered_and_the_retry_writes_them_again() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    gear.fail_sync.store(true, Ordering::SeqCst);
    let batch = vec![record("x1", "a")];
    assert!(matches!(file_commit(&gear.detector.store, "a", &batch), Err(SinkError::Sync(_))));
    assert!(seen_of(&gear.detector.store)?.is_empty());
    assert!(matches!(file_commit(&gear.detector.store, "a", &batch), Err(SinkError::Sync(_))));
    gear.fail_sync.store(false, Ordering::SeqCst);
    assert_eq!(file_commit(&gear.detector.store, "a", &batch)?, 1);
    assert_eq!(file_commit(&gear.detector.store, "a", &batch)?, 0);
    let written = records_of(&gear.output)?;
    assert_eq!(written.len(), THREE);
    assert!(written.iter().all(|stored| stored.id == "x1"));
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
fn too_many_ids_or_a_read_error_refuse_the_file_and_an_oversized_line_is_skipped() -> TestResult {
    let long = format!("{}\n{}\n", line_of("x1")?, line_of("x2")?);
    let skipped = load_seen(&mut BufReader::new(long.as_bytes()), SMALL_LINE, SMALL_LINE)?;
    assert!(skipped.is_empty());
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
    let first = open_alert_store(&path, LARGE_LINE, TWO)?;
    assert_eq!(file_commit(&first, "a", &[record("x1", "a"), record("x2", "a")])?, TWO);
    drop(first);
    let mut tail = fs::OpenOptions::new().append(true).open(&path)?;
    tail.write_all(b"{\"id\":\"torn")?;
    drop(tail);
    let second = open_alert_store(&path, LARGE_LINE, TWO)?;
    assert_eq!(file_commit(&second, "a", &[record("x1", "a"), record("x3", "a")])?, 1);
    drop(second);
    let text = fs::read_to_string(&path)?;
    let ids: Vec<String> = parse_records(&text)?.into_iter().map(|stored| stored.id).collect();
    assert_eq!(ids, ["x1", "x2", "x3"]);
    assert_eq!(seen_of(&open_alert_store(&path, LARGE_LINE, TWO)?)?.len(), THREE);
    Ok(())
}


#[test]
fn an_alerts_file_that_cannot_be_opened_is_an_error() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(
        open_alert_store(dir.path(), LARGE_LINE, TWO),
        Err(SinkError::Open { .. }) | Err(SinkError::Read(_))
    ));
    assert!(matches!(
        open_alert_store(&dir.path().join("missing").join("alerts"), LARGE_LINE, TWO),
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
    flakes: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
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
    rig_with(rules, "")
}


fn rig_with(rules: &[&str], extra: &str) -> Result<Rig, Box<dyn Error + Send + Sync>> {
    let stub = start_stub(None, |_| ())?;
    let (dir, path) = write_bench(rules, stub.port, extra)?;
    let audit = Shared::default();
    let rules_engine = Arc::new(open_rules_engine(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?);
    let ingest = Arc::new(open_ingest(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?);
    let bench = Bench {
        dir,
        path,
        rules: Arc::clone(&rules_engine),
        ingest: Arc::clone(&ingest),
        audit,
    };
    let Gear {
        detector: mut bare,
        output,
        fail,
        flakes,
        stopping,
        ..
    } = default_gear(&bench);
    let wiring = siem_ingest::nats::nats_wiring(Arc::clone(&ingest))?;
    bare.retry.progress = Arc::clone(&wiring.progress);
    let detector = Arc::new(bare);
    let pipeline = detection_pipeline(ingest, Arc::clone(&detector), wiring, (fixed_clock, no_sleep));
    Ok(Rig {
        bench,
        stub,
        detector,
        output,
        fail,
        flakes,
        stopping,
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
    let ingest = Arc::new(open_ingest(
        bench.path.clone(),
        fixed_of(&bench.path)?,
        audit_fn(&audit),
        context(&bench.path),
    )?);
    let detector = Arc::new(default_gear(&bench).detector);
    let wiring = Wiring {
        fetch: Box::new(|_| Err("bus down".into())),
        ack: Box::new(|_, _| Ok(())),
        dead_letter: Box::new(|_, _, _| Ok(())),
        progress: Arc::new(|| Ok(())),
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
    let ingest = Arc::new(open_ingest(path.clone(), fixed_of(&path)?, audit_fn(&audit), context(&path))?);
    let feeding = Arc::clone(&detector);
    let wiring = Wiring {
        fetch: Box::new(move |_| {
            detect_batch(&feeding, "a", &documents(&[whoami("e1", 0)]))?;
            Ok(Vec::new())
        }),
        ack: Box::new(|_, _| Ok(())),
        dead_letter: Box::new(|_, _, _| Ok(())),
        progress: Arc::new(|| Ok(())),
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


const HUGE_TEXT: usize = 1_100_000;


const MANY_FIELDS: usize = 20;


const MANY_IDS: usize = 300;


const STORE_LIMIT: usize = 4096;


const ACK_WAIT_SHORT: &str = "  max_batch_age_seconds: 1\n  nats_ack_wait_ms: 2000\n  backoff_initial_ms: 500\n  backoff_max_ms: 500\n";


fn ids_of(path: &Path) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    Ok(parse_records(&fs::read_to_string(path)?)?.into_iter().map(|stored| stored.id).collect())
}


fn earlier(payload: &str) -> String {
    payload.replace("T10:00:", "T08:00:")
}


#[test]
fn the_commit_is_retried_in_place_until_the_store_recovers() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    gear.stopping.store(false, Ordering::SeqCst);
    gear.flakes.store(THREE, Ordering::SeqCst);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    assert_eq!(gear.flakes.load(Ordering::SeqCst), 0);
    assert_eq!(gear.progress_calls.load(Ordering::SeqCst), 0);
    Ok(())
}


#[test]
fn a_retry_past_half_the_ack_wait_tells_the_bus_and_a_refused_notice_does_not_stop_it() -> TestResult {
    let bench = bench_with(&[WHOAMI, SEEN_ONCE], ACK_WAIT_SHORT)?;
    let gear = default_gear(&bench);
    gear.stopping.store(false, Ordering::SeqCst);
    gear.flakes.store(THREE + 1, Ordering::SeqCst);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(gear.progress_calls.load(Ordering::SeqCst), TWO);
    gear.progress_fails.store(true, Ordering::SeqCst);
    gear.flakes.store(TWO, Ordering::SeqCst);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e2", 1)]))?;
    assert_eq!(gear.progress_calls.load(Ordering::SeqCst), THREE);
    assert_eq!(records_of(&gear.output)?.len(), TWO);
    Ok(())
}


#[test]
fn a_retry_ends_when_the_service_stops_at_the_attempt_cap_or_with_no_attempt() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let mut gear = default_gear(&bench);
    gear.fail.store(true, Ordering::SeqCst);
    let batch = documents(&[whoami("e1", 0)]);
    assert!(detect_batch(&gear.detector, "a", &batch).is_err());
    gear.stopping.store(false, Ordering::SeqCst);
    gear.detector.retry.max_attempts = THREE as u32;
    let capped = detect_batch(&gear.detector, "a", &batch).err().ok_or("no error at the cap")?;
    assert_eq!(capped.to_string(), "cannot write the alerts file");
    gear.detector.retry.max_attempts = 0;
    let none = detect_batch(&gear.detector, "a", &batch).err().ok_or("no error without attempts")?;
    assert_eq!(none.to_string(), "the store kept refusing the alerts until the retry cap");
    assert!(records_of(&gear.output)?.is_empty());
    Ok(())
}


#[test]
fn events_older_than_the_lateness_are_counted_per_batch() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(gear.detector.late.load(Ordering::SeqCst), 0);
    detect_batch(&gear.detector, "a", &documents(&[earlier(&whoami("e2", 1)), earlier(&whoami("e3", TWO))]))?;
    assert_eq!(gear.detector.late.load(Ordering::SeqCst), TWO as u64);
    assert_eq!(records_of(&gear.output)?.len(), 1);
    Ok(())
}


#[test]
fn a_later_batch_never_commits_before_a_failed_one_and_every_alert_is_stored_in_order() -> TestResult {
    let mut rig = rig(&[WHOAMI, SEEN_ONCE])?;
    rig.stopping.store(false, Ordering::SeqCst);
    rig.flakes.store(TWO, Ordering::SeqCst);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e1", 0)));
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e2", 1)));
    run_cycle(&mut rig.pipeline)?;
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| state.acks.len() == TWO)?;
    assert_eq!(acks(&rig), ["+ACK", "+ACK"]);
    let records = records_of(&rig.output)?;
    let firsts: Vec<&str> = records
        .iter()
        .flat_map(|stored| stored.event_ids.first())
        .flat_map(|event| event.get(..TWO))
        .collect();
    assert_eq!(firsts, ["e1", "e2"]);
    assert_eq!(rig.flakes.load(Ordering::SeqCst), 0);
    Ok(())
}


#[test]
fn a_long_store_outage_keeps_the_batch_alive_on_the_bus_with_in_progress_acknowledgements() -> TestResult {
    let mut rig = rig_with(&[WHOAMI, SEEN_ONCE], ACK_WAIT_SHORT)?;
    rig.stopping.store(false, Ordering::SeqCst);
    rig.flakes.store(THREE + 1, Ordering::SeqCst);
    lock(&rig.stub.hub).queue.push_back(queued("events.a", &whoami("e1", 0)));
    run_cycle(&mut rig.pipeline)?;
    wait_until(&rig.stub, |state| state.acks.len() == THREE)?;
    assert_eq!(acks(&rig), ["+WPI", "+WPI", "+ACK"]);
    assert_eq!(records_of(&rig.output)?.len(), 1);
    Ok(())
}


#[test]
fn a_stop_during_a_store_outage_ends_the_service_with_nothing_stored() -> TestResult {
    let (dir, stub, path) = service_files("")?;
    lock(&stub.hub).queue.push_back(queued("events.a", &whoami("e1", 0)));
    let hub = Arc::clone(&stub.hub);
    let stop = Box::new(move || !lock(&hub).pulls.is_empty());
    let summary = run_service(&path, stop, refusing_commit)?;
    assert_eq!(summary.cycles, 1);
    assert!(fs::read_to_string(dir.path().join("alerts.jsonl"))?.is_empty());
    Ok(())
}


#[test]
fn a_change_of_a_start_only_setting_is_refused_and_audited() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let original = detection_yaml(bench.dir.path(), 1, "");
    ["alerts.jsonl", "checkpoints", "audit.log"].iter().try_for_each(|name| -> TestResult {
        fs::write(&bench.path, original.replace(name, &format!("moved-{name}")))?;
        assert!(matches!(reload(&bench.rules), ReloadOutcome::Refused { .. }));
        assert!(matches!(reload(&bench.ingest), ReloadOutcome::Refused { .. }));
        fs::write(&bench.path, &original)?;
        assert!(!matches!(reload(&bench.rules), ReloadOutcome::Refused { .. }));
        assert!(!matches!(reload(&bench.ingest), ReloadOutcome::Refused { .. }));
        Ok(())
    })?;
    assert!(text_of(&bench.audit)?.contains("refused"));
    Ok(())
}


fn long_record() -> AlertRecord {
    AlertRecord {
        rule_title: "t".repeat(HUGE_TEXT),
        level: Level::Medium,
        group: (0..MANY_FIELDS).map(|index| (format!("k{index:02}"), "v".repeat(HUGE_TEXT))).collect(),
        event_ids: (0..MANY_IDS).map(|index| format!("e{index}")).collect(),
        ..record("x1", "a")
    }
}


#[test]
fn a_record_is_bounded_when_written_so_the_file_always_reopens() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let store = open_alert_store(&path, STORE_LIMIT, TWO)?;
    assert_eq!(file_commit(&store, "a", &[long_record()])?, 1);
    drop(store);
    let text = fs::read_to_string(&path)?;
    assert!(text.lines().all(|line| line.len() <= MAX_ALERT_LINE_BYTES));
    let stored = parse_records(&text)?.pop().ok_or("no record")?;
    assert_eq!(stored.id, "x1");
    assert!(stored.rule_title.ends_with(&format!("[cut, {HUGE_TEXT} chars]")));
    assert!(stored.group.contains_key(OMITTED_KEY));
    assert_eq!(stored.group.len(), MAX_GROUP_FIELDS + 1);
    assert_eq!(stored.event_ids.len(), MAX_STORED_EVENT_IDS + 1);
    assert!(stored.event_ids.last().ok_or("no ids")?.contains("more event ids omitted"));
    assert_eq!(ids_of(&path)?, ["x1"]);
    assert_eq!(seen_of(&open_alert_store(&path, STORE_LIMIT, TWO)?)?.len(), 1);
    assert_eq!(bound_record(&record("x2", "a")), record("x2", "a"));
    assert_eq!(cut_text("abc", THREE), "abc");
    Ok(())
}


#[test]
fn an_oversized_or_torn_line_never_stops_the_service_from_restarting() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let giant = "x".repeat(MAX_ALERT_LINE_BYTES + 1);
    fs::write(&path, format!("{giant}\n{}\n{{\"id\":\"torn", line_of("x1")?))?;
    let store = open_alert_store(&path, STORE_LIMIT, TWO)?;
    assert_eq!(seen_of(&store)?, HashSet::from(["x1".to_owned()]));
    assert_eq!(file_commit(&store, "a", &[record("x2", "a")])?, 1);
    Ok(())
}


#[test]
fn a_full_alerts_file_is_rotated_with_a_bounded_number_of_old_files() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let store = open_alert_store(&path, TWO, TWO)?;
    let commit = |ids: &[&str]| file_commit(&store, "a", &ids.iter().map(|id| record(id, "a")).collect::<Vec<_>>());
    assert_eq!(commit(&["x1", "x2"])?, TWO);
    assert_eq!(commit(&["x3", "x4", "x5"])?, THREE);
    assert_eq!(ids_of(&rotated_name(&path, 1))?, ["x1", "x2"]);
    assert_eq!(ids_of(&path)?, ["x3", "x4", "x5"]);
    assert_eq!(commit(&["x6"])?, 1);
    assert_eq!(ids_of(&rotated_name(&path, TWO))?, ["x1", "x2"]);
    assert_eq!(ids_of(&rotated_name(&path, 1))?, ["x3", "x4", "x5"]);
    assert_eq!(commit(&["x1"])?, 1);
    assert_eq!(commit(&["x7", "x8"])?, TWO);
    assert_eq!(commit(&["x9"])?, 1);
    assert!(!rotated_name(&path, THREE).exists());
    assert_eq!(ids_of(&rotated_name(&path, TWO))?, ["x6", "x1"]);
    assert_eq!(ids_of(&path)?, ["x9"]);
    assert_eq!(commit(&["x9"])?, 0);
    Ok(())
}


#[test]
fn a_rotation_that_fails_is_an_error_and_the_alerts_are_not_stored() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let store = open_alert_store(&path, 1, 1)?;
    assert_eq!(file_commit(&store, "a", &[record("x1", "a")])?, 1);
    fs::create_dir(temp_name(&path))?;
    assert!(matches!(file_commit(&store, "a", &[record("x2", "a")]), Err(SinkError::Rotate(_))));
    let memory = Arc::new(new_store(
        (Box::new(Shared::default()), Box::new(|| Ok(()))),
        no_rotation(),
        HashSet::new(),
        false,
        0,
    ));
    assert!(matches!(file_commit(&memory, "a", &[record("x3", "a")]), Err(SinkError::Rotate(_))));
    Ok(())
}


fn flaky_move(from: &Path, to: &Path) -> io::Result<()> {
    let mut marker = to.as_os_str().to_owned();
    marker.push(".fault");
    if PathBuf::from(marker).exists() {
        Err(io::Error::other("injected rename failure"))
    } else {
        move_file(from, to)
    }
}


const ALL_SLOTS: [usize; 4] = [0, 1, 2, 3];


const THREE_SLOTS: [usize; 3] = [0, 1, 2];


const ROTATION_RETRIES: usize = 10;


const ACK_WAIT_MS: u64 = 10_000;


fn snapshot_of(path: &Path, numbers: &[usize]) -> Result<Vec<Option<String>>, io::Error> {
    numbers
        .iter()
        .map(|number| {
            let name = if *number == 0 { path.to_path_buf() } else { rotated_name(path, *number) };
            name.exists().then(|| fs::read_to_string(name)).transpose()
        })
        .collect()
}


#[test]
fn a_rotation_failing_at_each_step_and_retried_loses_no_rotated_file() -> TestResult {
    ["alerts.jsonl.3", "alerts.jsonl.2", "alerts.jsonl.1"]
        .iter()
        .try_for_each(|fault| -> TestResult {
            let dir = tempdir()?;
            let path = dir.path().join("alerts.jsonl");
            [("", "current"), (".1", "one"), (".2", "two"), (".3", "three")]
                .iter()
                .try_for_each(|(suffix, text)| fs::write(dir.path().join(format!("alerts.jsonl{suffix}")), text))?;
            let marker = dir.path().join(format!("{fault}.fault"));
            fs::write(&marker, "")?;
            (0..ROTATION_RETRIES).try_for_each(|_| -> TestResult {
                assert!(rotate_to_new(&path, THREE, flaky_move, sync_directory).is_err());
                assert_eq!(fs::read_to_string(&path)?, "current");
                Ok(())
            })?;
            fs::remove_file(&marker)?;
            let _output = rotate_to_new(&path, THREE, flaky_move, sync_directory)?;
            assert_eq!(
                snapshot_of(&path, &ALL_SLOTS)?,
                [
                    Some(String::new()),
                    Some("current".to_owned()),
                    Some("one".to_owned()),
                    Some("two".to_owned())
                ]
            );
            Ok(())
        })
}


#[test]
fn a_rotation_failing_on_the_last_step_keeps_the_rotated_files_and_recovers() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    fs::write(&path, "current")?;
    fs::write(rotated_name(&path, 1), "one")?;
    fs::write(format!("{}.fault", path.display()), "")?;
    (0..ROTATION_RETRIES).try_for_each(|_| -> TestResult {
        assert!(rotate_to_new(&path, TWO, flaky_move, sync_directory).is_err());
        assert_eq!(
            snapshot_of(&path, &THREE_SLOTS)?,
            [None, Some("current".to_owned()), Some("one".to_owned())]
        );
        Ok(())
    })?;
    fs::remove_file(format!("{}.fault", path.display()))?;
    let _output = rotate_to_new(&path, TWO, flaky_move, sync_directory)?;
    assert_eq!(
        snapshot_of(&path, &THREE_SLOTS)?,
        [Some(String::new()), Some("current".to_owned()), Some("one".to_owned())]
    );
    Ok(())
}


#[test]
fn a_rotation_that_cannot_open_the_new_file_or_remove_the_oldest_changes_nothing() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    fs::write(&path, "current")?;
    fs::write(rotated_name(&path, 1), "one")?;
    fs::create_dir(temp_name(&path))?;
    (0..ROTATION_RETRIES).try_for_each(|_| -> TestResult {
        assert!(rotate_to_new(&path, 1, flaky_move, sync_directory).is_err());
        assert_eq!(snapshot_of(&path, &[0, 1])?, [Some("current".to_owned()), Some("one".to_owned())]);
        Ok(())
    })?;
    fs::remove_dir(temp_name(&path))?;
    fs::remove_file(rotated_name(&path, 1))?;
    fs::create_dir(rotated_name(&path, 1))?;
    (0..ROTATION_RETRIES).try_for_each(|_| -> TestResult {
        assert!(rotate_to_new(&path, 1, flaky_move, sync_directory).is_err());
        assert_eq!(fs::read_to_string(&path)?, "current");
        Ok(())
    })
}


#[test]
fn a_rotation_with_the_current_file_missing_just_moves_the_new_one_in() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    let _output = rotate_to_new(&path, 0, flaky_move, sync_directory)?;
    assert!(path.exists());
    assert!(!temp_name(&path).exists());
    Ok(())
}


#[test]
fn a_backoff_that_could_outlast_the_progress_ack_is_refused() -> TestResult {
    let with = |backoff_max_ms: u64| siem_ingest::settings::IngestSettings {
        nats_ack_wait_ms: ACK_WAIT_MS,
        backoff_max_ms,
        ..Default::default()
    };
    assert!(check_backoff(&with(ACK_WAIT_MS / TWO as u64)).is_err());
    assert!(check_backoff(&with(ACK_WAIT_MS / TWO as u64 - 1)).is_ok());
    Ok(())
}


#[test]
fn a_service_file_that_differs_from_the_start_baseline_is_refused() -> TestResult {
    let (_dir, path) = write_bench(&[WHOAMI], 1, "")?;
    let mut baseline = fixed_of(&path)?;
    baseline.alerts_file = PathBuf::from("/elsewhere");
    let audit = Shared::default();
    assert!(open_ingest(path.clone(), baseline.clone(), audit_fn(&audit), context(&path)).is_err());
    assert!(open_rules_engine(path.clone(), baseline, audit_fn(&audit), context(&path)).is_err());
    Ok(())
}


fn checking_sync(path: &Path) -> io::Result<()> {
    if temp_name(path).exists() || !rotated_name(path, 1).exists() {
        Err(io::Error::other("directory flushed before the renames"))
    } else if PathBuf::from(format!("{}.syncfault", path.display())).exists() {
        Err(io::Error::other("injected directory sync failure"))
    } else {
        Ok(())
    }
}


#[test]
fn the_rotation_flushes_the_directory_after_both_renames() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("alerts.jsonl");
    fs::write(&path, "current")?;
    let _output = rotate_to_new(&path, TWO, move_file, checking_sync)?;
    assert_eq!(fs::read_to_string(rotated_name(&path, 1))?, "current");
    assert!(!temp_name(&path).exists());
    fs::write(format!("{}.syncfault", path.display()), "")?;
    assert!(rotate_to_new(&path, TWO, move_file, checking_sync).is_err());
    Ok(())
}


#[test]
fn the_directory_sync_works_on_a_directory_and_fails_on_a_missing_one() -> TestResult {
    let dir = tempdir()?;
    sync_directory(&dir.path().join("alerts.jsonl"))?;
    assert!(sync_directory(&dir.path().join("missing").join("alerts.jsonl")).is_err());
    Ok(())
}


#[test]
fn the_record_id_is_the_alert_store_id_and_matches_the_t163_vector() -> TestResult {
    let events = vec!["e1".to_owned(), "e2".to_owned()];
    let vector = alert_id("a", "r", &events);
    assert!(vector.starts_with("2d6c7e2f"), "{vector}");
    let record = record_of(
        "a",
        stream_correlation::window::Alert {
            rule_id: "r".to_owned(),
            rule_title: "R".to_owned(),
            level: stream_correlation::level::Level::Medium,
            group: Default::default(),
            first_ms: 0,
            last_ms: 1,
            event_ids: vec!["e2".to_owned(), "e1".to_owned()],
        },
    );
    assert_eq!(record.id, vector);
    Ok(())
}


const PG_SECTION: &str =
    "postgres:\n  host: 127.0.0.1\n  database: ostyr\n  user: ostyr\n  password_file: /nonexistent/pass\n  ca_file: /nonexistent/ca\n";


#[test]
fn the_sink_setting_is_validated() -> TestResult {
    let (_dir, file_path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "")?;
    assert_eq!(load_detection_file(&file_path)?.sink, SinkKind::File);
    let (_bad_dir, bad_path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "sink: elsewhere\n")?;
    assert!(load_detection_file(&bad_path).is_err());
    let (_missing_dir, missing_path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "sink: postgres\n")?;
    let audit = Shared::default();
    assert!(open_pg_engine(missing_path.clone(), fixed_of(&missing_path)?, audit_fn(&audit), context(&missing_path)).is_err());
    let (_pg_dir, pg_path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, &format!("sink: postgres\n{PG_SECTION}"))?;
    let engine = open_pg_engine(pg_path.clone(), fixed_of(&pg_path)?, audit_fn(&audit), context(&pg_path))?;
    assert_eq!(current_config(&engine).host, "127.0.0.1");
    assert_eq!(load_detection_file(&pg_path)?.sink, SinkKind::Postgres);
    Ok(())
}


#[test]
fn a_live_change_of_the_sink_is_refused() -> TestResult {
    let (_dir, path) = write_bench(&[WHOAMI, SEEN_ONCE], 1, "")?;
    let baseline = fixed_of(&path)?;
    let (_other, changed) = write_bench(&[WHOAMI, SEEN_ONCE], 1, &format!("sink: postgres\n{PG_SECTION}"))?;
    let file = load_detection_file(&changed)?;
    let file_sink = FixedPaths {
        sink: SinkKind::File,
        ..fixed_paths(&file)
    };
    assert!(check_fixed(&file_sink, file.clone()).is_err());
    assert!(check_fixed(&fixed_paths(&file), file).is_ok());
    assert_eq!(baseline.sink, SinkKind::File);
    Ok(())
}


const PG_CLOCK_MICROS: u64 = 1_700_000_000_000_000;


const MIN_NOW_MICROS: u64 = 1_700_000_000_000_000;


const HUNDRED: usize = 100;


const TITLE_LIMIT: usize = 256;


const BEYOND_RANGE_MS: i64 = 253_402_304_399_000;


const BEFORE_YEAR_ZERO_MS: i64 = -62_167_222_800_000;


const POLL_ATTEMPTS: usize = 2000;


const POLL_STEP: Duration = Duration::from_millis(5);


fn fixed_micros() -> u64 {
    PG_CLOCK_MICROS
}


fn pg_handler(failing: Arc<AtomicBool>, hangup: Arc<AtomicBool>) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("ON CONFLICT") {
            if hangup.load(Ordering::SeqCst) {
                Reply::Hangup
            } else if failing.load(Ordering::SeqCst) {
                Reply::Error("XX000")
            } else {
                Reply::Rows(vec![vec!["1".to_owned()]])
            }
        } else {
            Reply::Done
        }
    })
}


struct Database {
    runtime: Runtime,
    fake: Fake,
    failing: Arc<AtomicBool>,
    hangup: Arc<AtomicBool>,
    files: TempDir,
    section: String,
}


fn database() -> Result<Database, Box<dyn Error + Send + Sync>> {
    let pki = make_pki(SanType::IpAddress(loopback())).map_err(|error| error.to_string())?;
    let runtime = Builder::new_multi_thread().worker_threads(TWO).enable_all().build()?;
    let failing = Arc::new(AtomicBool::new(false));
    let hangup = Arc::new(AtomicBool::new(false));
    let handler = pg_handler(Arc::clone(&failing), Arc::clone(&hangup));
    let fake = runtime.block_on(fake::start(Mode::Tls(pki.server), "p", handler))?;
    let files = tempdir()?;
    fs::write(files.path().join("pg.pass"), "p")?;
    fs::write(files.path().join("ca.pem"), &pki.ca_pem)?;
    let section = format!(
        "postgres:\n  host: 127.0.0.1\n  port: {}\n  database: ostyr\n  user: ostyr\n  password_file: {}\n  ca_file: {}\n  connect_timeout_secs: 2\n",
        fake.port,
        files.path().join("pg.pass").display(),
        files.path().join("ca.pem").display()
    );
    Ok(Database {
        runtime,
        fake,
        failing,
        hangup,
        files,
        section,
    })
}


fn statements_of(database: &mut Database) -> Vec<String> {
    std::iter::repeat_with(|| database.fake.statements.try_recv())
        .take(POLL_ATTEMPTS)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


fn stored_docs(statements: &[String], tenant: &str) -> Result<Vec<Value>, Box<dyn Error + Send + Sync>> {
    let prefix = format!("PARAMS {tenant}|");
    statements
        .iter()
        .filter_map(|entry| entry.strip_prefix(&prefix))
        .map(|text| Ok(serde_json::from_str::<Value>(text)?))
        .collect()
}


fn pg_store_over(bench: &Bench) -> Result<PgStore, Box<dyn Error + Send + Sync>> {
    let engine = open_pg_engine(bench.path.clone(), fixed_of(&bench.path)?, audit_fn(&bench.audit), context(&bench.path))?;
    Ok(open_pg_store(Arc::new(engine), fixed_micros)?)
}


fn pg_bench() -> Result<(Database, Bench), Box<dyn Error + Send + Sync>> {
    let database = database()?;
    assert!(database.files.path().exists());
    let bench = bench_with(&[WHOAMI, SEEN_ONCE], &format!("sink: postgres\n{}", database.section))?;
    Ok((database, bench))
}


fn alert_record(tenant: &str, events: &[&str]) -> AlertRecord {
    AlertRecord {
        id: "unused".to_owned(),
        tenant: tenant.to_owned(),
        rule_id: "rule".to_owned(),
        rule_title: "Rule".to_owned(),
        level: Level::Medium,
        group: [("host.name".to_owned(), "h1".to_owned())].into_iter().collect(),
        first_ms: 0,
        last_ms: 1,
        event_ids: events.iter().map(|event| (*event).to_owned()).collect(),
    }
}


fn memory_rows(origin: &Tables) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'static> {
    let shared = Arc::clone(origin);
    move |scope, _sql, params| -> RowFuture<'static> {
        let tables = Arc::clone(&shared);
        Box::pin(async move {
            let docs: Vec<Value> = serde_json::from_str(params.first().map_or("[]", String::as_str)).map_err(|_| PgError::InvalidTenant)?;
            let ids: Vec<String> = docs
                .iter()
                .filter_map(|doc| doc.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect();
            let mut guard = tables.lock().map_err(|_| PgError::InvalidTenant)?;
            let table = guard.entry(tenant_of(&scope).to_owned()).or_default();
            let fresh = ids.iter().filter(|id| !table.contains(id)).count();
            table.extend(ids.into_iter().filter(|id| !table.contains(id)).collect::<Vec<_>>());
            Ok(vec![vec![fresh.to_string()]])
        })
    }
}


fn plain_runtime() -> Result<Runtime, Box<dyn Error + Send + Sync>> {
    Ok(Builder::new_current_thread().enable_all().build()?)
}


#[test]
fn an_alert_is_stored_once_under_the_batch_tenant_and_a_replay_adds_nothing() -> TestResult {
    let tables: Tables = Arc::default();
    let exec = memory_rows(&tables);
    let runtime = plain_runtime()?;
    let batch = [alert_record("a", &["e1", "e2"])];
    assert_eq!(commit_with(&runtime, &exec, "a", &batch, PG_CLOCK_MICROS)?, 1);
    assert_eq!(commit_with(&runtime, &exec, "a", &batch, PG_CLOCK_MICROS + 1)?, 0);
    let stored = tables.lock().map_err(|_| "poisoned")?;
    assert_eq!(stored.get("a").map(Vec::len), Some(1));
    assert!(stored.get("b").is_none());
    assert_eq!(
        stored.get("a").and_then(|ids| ids.first()),
        Some(&alert_id("a", "rule", &["e1".to_owned(), "e2".to_owned()]))
    );
    Ok(())
}


#[test]
fn the_scope_is_the_batch_tenant_only() -> TestResult {
    let tables: Tables = Arc::default();
    let exec = memory_rows(&tables);
    let runtime = plain_runtime()?;
    let foreign = [alert_record("b", &["e1"])];
    assert!(matches!(
        commit_with(&runtime, &exec, "a", &foreign, PG_CLOCK_MICROS),
        Err(SinkError::Store(StoreError::TenantMismatch))
    ));
    assert!(matches!(
        commit_with(&runtime, &exec, "-x", &[], PG_CLOCK_MICROS),
        Err(SinkError::Database(_))
    ));
    assert!(tables.lock().map_err(|_| "poisoned")?.is_empty());
    assert_eq!(commit_with(&runtime, &exec, "b", &foreign, PG_CLOCK_MICROS)?, 1);
    let stored = tables.lock().map_err(|_| "poisoned")?;
    assert_eq!((stored.get("a"), stored.get("b").map(Vec::len)), (None, Some(1)));
    Ok(())
}


#[test]
fn a_store_failure_is_returned() -> TestResult {
    let runtime = plain_runtime()?;
    let failing =
        |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'static> { Box::pin(async { Err(PgError::InvalidTenant) }) };
    assert!(matches!(
        commit_with(&runtime, &failing, "a", &[alert_record("a", &["e1"])], PG_CLOCK_MICROS),
        Err(SinkError::Store(_))
    ));
    Ok(())
}


#[test]
fn two_long_event_ids_with_different_payloads_keep_their_hash_and_get_different_alert_ids() -> TestResult {
    let long = "A".repeat(HUGE_TEXT);
    let first = event_identity(Some(&long), b"one");
    let second = event_identity(Some(&long), b"two");
    let alert_first = alert_of(&alert_record("a", &[first.as_str()]), 0)?;
    let alert_second = alert_of(&alert_record("a", &[second.as_str()]), 0)?;
    assert_eq!(alert_first.event_ids, [first]);
    assert_ne!(alert_first.id, alert_second.id);
    Ok(())
}


#[test]
fn the_mapping_bounds_every_field_and_derives_the_id_from_what_is_stored() -> TestResult {
    let alert = alert_of(&alert_record("a", &["e2", "e1"]), PG_CLOCK_MICROS)?;
    assert_eq!(alert.event_ids, ["e1", "e2"]);
    assert_eq!(alert.id, alert_id("a", "rule", &alert.event_ids));
    assert_eq!((alert.host_name.as_deref(), alert.user_name.as_deref()), (Some("h1"), None));
    assert_eq!(
        (alert.event_time.as_str(), alert.created_micros),
        ("1970-01-01T00:00:00.001Z", PG_CLOCK_MICROS)
    );
    let many: Vec<String> = (0..HUNDRED + THREE).map(|number| format!("e{number:04}")).collect();
    let crowded = AlertRecord {
        event_ids: many.clone(),
        ..alert_record("a", &[])
    };
    let stored = alert_of(&crowded, 0)?;
    assert_eq!(stored.event_ids.len(), HUNDRED);
    assert_eq!(stored.id, alert_id("a", "rule", &stored.event_ids));
    assert_eq!(alert_of(&crowded, 1)?.id, stored.id);
    let hostile = AlertRecord {
        rule_id: "r\0".repeat(HUGE_TEXT),
        rule_title: "t".repeat(HUGE_TEXT),
        group: (0..MAX_GROUP_FIELDS * TWO)
            .map(|number| (format!("k{number}"), "v".repeat(HUGE_TEXT)))
            .collect(),
        ..alert_record("a", &["x\0y"])
    };
    let bounded = alert_of(&hostile, 0)?;
    assert!(!bounded.rule_id.contains('\0') && !bounded.event_ids.iter().any(|id| id.contains('\0')));
    assert!(bounded.rule_title.chars().count() <= TITLE_LIMIT);
    assert!(bounded.summary.truncated);
    let nameless = AlertRecord {
        group: [("host.name".to_owned(), String::new()), ("user.name".to_owned(), "u".to_owned())]
            .into_iter()
            .collect(),
        ..alert_record("a", &["e1"])
    };
    let anonymous = alert_of(&nameless, 0)?;
    assert_eq!((anonymous.host_name, anonymous.user_name.as_deref()), (None, Some("u")));
    assert!(system_micros() > MIN_NOW_MICROS);
    Ok(())
}


#[test]
fn a_sink_given_the_other_kind_of_store_refuses() -> TestResult {
    let (_database, bench) = pg_bench()?;
    let pg = AlertStore::Postgres(pg_store_over(&bench)?);
    assert!(matches!(file_commit(&pg, "a", &[]), Err(SinkError::WrongStore)));
    let dir = tempdir()?;
    let file = open_alert_store(&dir.path().join("alerts.jsonl"), LARGE_LINE, TWO)?;
    assert!(matches!(pg_commit(&file, "a", &[]), Err(SinkError::WrongStore)));
    assert_eq!(commit_alerts(&file, "a", &[record("x1", "a")])?, 1);
    assert_eq!(commit_alerts(&pg, "a", &[])?, 0);
    Ok(())
}


#[test]
fn the_connection_is_kept_migrated_once_and_survives_a_refusal_from_the_database() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let store = pg_store_over(&bench)?;
    let batch = [alert_record("a", &["e1", "e2"])];
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    database.failing.store(true, Ordering::SeqCst);
    assert!(matches!(commit_pg(&store, "a", &batch), Err(SinkError::Store(_))));
    assert!(store.link.lock().map_err(|_| "poisoned")?.is_some());
    database.failing.store(false, Ordering::SeqCst);
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    let statements = statements_of(&mut database);
    let docs = stored_docs(&statements, "a")?;
    assert_eq!(docs.len(), THREE);
    let ids: Vec<Option<&str>> = docs
        .iter()
        .map(|doc| doc.get(0).and_then(|alert| alert.get("id")).and_then(Value::as_str))
        .collect();
    assert!(ids.first().is_some_and(Option::is_some));
    assert!(ids.iter().all(|id| *id == ids.first().copied().flatten()));
    assert_eq!(
        statements.iter().filter(|entry| entry.contains("INSERT INTO schema_migrations")).count(),
        alerts::store::MIGRATIONS.len()
    );
    let passwords: Vec<Vec<u8>> = std::iter::repeat_with(|| database.fake.passwords.try_recv())
        .take(POLL_ATTEMPTS)
        .take_while(Result::is_ok)
        .flatten()
        .collect();
    assert_eq!(passwords, [b"p".to_vec()]);
    assert_eq!(stored_docs(&statements, "b")?.len(), 0);
    let created = docs
        .iter()
        .all(|doc| doc.get(0).and_then(|alert| alert.get("created")).and_then(Value::as_u64) == Some(PG_CLOCK_MICROS));
    assert!(created);
    Ok(())
}


#[test]
fn a_closed_connection_is_replaced_and_an_unreachable_database_is_an_error() -> TestResult {
    let (database, bench) = pg_bench()?;
    let store = pg_store_over(&bench)?;
    let batch = [alert_record("a", &["e1"])];
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    drop(database.runtime);
    let closed = (0..POLL_ATTEMPTS).any(|_| {
        std::thread::sleep(POLL_STEP);
        store
            .link
            .lock()
            .map(|slot| slot.as_ref().is_some_and(tokio_postgres::Client::is_closed))
            .unwrap_or(false)
    });
    assert!(closed);
    assert!(matches!(commit_pg(&store, "a", &batch), Err(SinkError::Database(_))));
    assert!(store.link.lock().map_err(|_| "poisoned")?.is_none());
    Ok(())
}


#[test]
fn an_event_identity_over_the_store_limit_is_refused_not_cut() -> TestResult {
    let long = "x".repeat(alerts::store::MAX_EVENT_ID_CHARS + 1);
    assert!(matches!(
        alert_of(&alert_record("a", &[long.as_str()]), 0),
        Err(SinkError::EventIdTooLong { .. })
    ));
    let tables: Tables = Arc::default();
    let exec = memory_rows(&tables);
    let refused = commit_with(&plain_runtime()?, &exec, "a", &[alert_record("a", &[long.as_str()])], 0);
    assert!(matches!(refused, Err(SinkError::EventIdTooLong { .. })));
    assert!(tables.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[test]
fn an_empty_commit_never_connects_and_a_non_empty_one_fails_typed_on_a_dropped_database() -> TestResult {
    let (database, bench) = pg_bench()?;
    let store = pg_store_over(&bench)?;
    drop(database.runtime);
    assert_eq!(commit_pg(&store, "a", &[])?, 0);
    assert!(store.link.lock().map_err(|_| "poisoned")?.is_none());
    let batch = [alert_record("a", &["e1"])];
    assert!(matches!(commit_pg(&store, "a", &batch), Err(SinkError::Database(_))));
    Ok(())
}


#[test]
fn a_failed_store_leaves_the_batch_unacknowledged_and_the_redelivery_stores_the_same_alert() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let stopping = Arc::new(AtomicBool::new(true));
    let stop_flag = Arc::clone(&stopping);
    let policy = CommitPolicy {
        ingest: Arc::clone(&bench.ingest),
        progress: Arc::new(|| Ok(())),
        stop: Arc::new(move || stop_flag.load(Ordering::SeqCst)),
        sleep: no_sleep,
        max_attempts: RETRIES as u32,
    };
    let detector = new_detector(
        Arc::clone(&bench.rules),
        Arc::new(AlertStore::Postgres(pg_store_over(&bench)?)),
        commit_alerts,
        (MAX_ALERTS_PER_BATCH, THREE),
        bench.dir.path().join("checkpoints"),
        policy,
    );
    let batch = documents(&[whoami("e1", 0)]);
    database.failing.store(true, Ordering::SeqCst);
    assert!(detect_batch(&detector, "a", &batch).is_err());
    database.failing.store(false, Ordering::SeqCst);
    detect_batch(&detector, "a", &batch)?;
    let statements = statements_of(&mut database);
    assert_eq!(statements.iter().filter(|entry| entry.contains("ON CONFLICT")).count(), TWO);
    let docs = stored_docs(&statements, "a")?;
    assert_eq!(docs.len(), 1);
    let stored = docs.first().and_then(|doc| doc.get(0)).ok_or("no alert")?;
    let events: Vec<String> = serde_json::from_value(stored.get("event_ids").cloned().ok_or("no events")?)?;
    assert_eq!(
        stored.get("id").and_then(Value::as_str),
        Some(alert_id("a", "whoami-seen", &events).as_str())
    );
    Ok(())
}


#[test]
fn the_service_runs_with_the_postgres_sink() -> TestResult {
    let mut database = database()?;
    let (dir, stub, path) = service_files(&format!("sink: postgres\n{}", database.section))?;
    let payloads = [whoami("e1", 0), whoami("e2", 1)];
    payloads
        .iter()
        .for_each(|payload| lock(&stub.hub).queue.push_back(queued("events.a", payload)));
    let hub = Arc::clone(&stub.hub);
    let stop = Box::new(move || lock(&hub).acks.len() >= TWO);
    let summary = run_service(&path, stop, commit_alerts)?;
    assert!(summary.cycles > 0);
    let statements = statements_of(&mut database);
    let docs = stored_docs(&statements, "a")?;
    assert_eq!(docs.len(), 1);
    assert_eq!(
        docs.first()
            .and_then(|doc| doc.get(0))
            .and_then(|alert| alert.get("rule_id"))
            .and_then(Value::as_str),
        Some("whoami-twice")
    );
    assert!(!dir.path().join("alerts.jsonl").exists() || fs::read_to_string(dir.path().join("alerts.jsonl"))?.is_empty());
    Ok(())
}


const OVER_INSERT: usize = 501;


const MANY_ALERTS: usize = 600;


const LAST_INSTANT: &str = "9999-12-31T23:59:59.999Z";


const FIRST_INSTANT: &str = "0000-01-01T00:00:00Z";


fn permanent_for_a(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    if tenant == "a" {
        Err(SinkError::EventIdTooLong { max: 1 })
    } else {
        file_commit(store, tenant, records)
    }
}


#[test]
fn an_event_time_outside_years_0_to_9999_is_clamped_and_the_original_is_kept_in_the_summary() -> TestResult {
    let late = AlertRecord {
        last_ms: BEYOND_RANGE_MS,
        ..alert_record("a", &["e"])
    };
    let early = AlertRecord {
        last_ms: BEFORE_YEAR_ZERO_MS,
        ..alert_record("a", &["e"])
    };
    let (after, before, inside) = (alert_of(&late, 0)?, alert_of(&early, 0)?, alert_of(&alert_record("a", &["e"]), 0)?);
    assert_eq!((after.event_time.as_str(), before.event_time.as_str()), (LAST_INSTANT, FIRST_INSTANT));
    assert!(after.summary.text.contains(&format!("\"last_ms\":{BEYOND_RANGE_MS}")) && after.summary.text.contains("\"event_time_clamped\":true"));
    assert!(before.summary.text.contains(&format!("\"last_ms\":{BEFORE_YEAR_ZERO_MS}")));
    assert!(inside.summary.text.contains("\"event_time_clamped\":false"));
    let extreme = AlertRecord {
        last_ms: i64::MIN,
        ..alert_record("a", &["e"])
    };
    assert_eq!(alert_of(&extreme, 0)?.event_time, FIRST_INSTANT);
    Ok(())
}


#[test]
fn more_alerts_than_one_insert_holds_are_stored_in_chunks() -> TestResult {
    let tables: Tables = Arc::default();
    let inserts = AtomicUsize::new(0);
    let inner = memory_rows(&tables);
    let exec = |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'static> {
        inserts.fetch_add(1, Ordering::SeqCst);
        inner(scope, sql, params)
    };
    let runtime = plain_runtime()?;
    let names: Vec<String> = (0..OVER_INSERT).map(|number| format!("e{number}")).collect();
    let batch: Vec<AlertRecord> = names.iter().map(|name| alert_record("a", &[name.as_str()])).collect();
    assert_eq!(commit_with(&runtime, &exec, "a", &batch, PG_CLOCK_MICROS)?, OVER_INSERT);
    assert_eq!(inserts.load(Ordering::SeqCst), TWO);
    assert_eq!(tables.lock().map_err(|_| "poisoned")?.get("a").map(Vec::len), Some(OVER_INSERT));
    Ok(())
}


#[test]
fn a_permanent_refusal_is_counted_and_acknowledged_and_never_blocks_another_tenant() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let mut gear = default_gear(&bench);
    gear.detector.commit = permanent_for_a;
    gear.stopping.store(false, Ordering::SeqCst);
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    assert!(records_of(&gear.output)?.is_empty());
    detect_batch(&gear.detector, "b", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    let counts = gear.detector.permanent.lock().map_err(|_| "poisoned")?;
    assert_eq!(counts.len(), 1);
    assert_eq!(counts.get("an event identity is longer than 1 characters"), Some(&1));
    Ok(())
}


fn permanent_for_bad(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    if records.iter().any(|record| record.event_ids.iter().any(|id| id.starts_with("bad"))) {
        Err(SinkError::EventIdTooLong { max: 1 })
    } else {
        file_commit(store, tenant, records)
    }
}


#[test]
fn a_refused_record_never_drops_the_valid_records_of_its_batch() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let mut gear = default_gear(&bench);
    gear.detector.commit = permanent_for_bad;
    detect_batch(&gear.detector, "a", &documents(&[whoami("bad", 0), whoami("good", 1)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    let counts = gear.detector.permanent.lock().map_err(|_| "poisoned")?;
    assert_eq!(counts.get("an event identity is longer than 1 characters"), Some(&1));
    Ok(())
}


fn permanent_then_transient(_store: &AlertStore, _tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    if records.len() > 1 {
        Err(SinkError::TenantMismatch)
    } else {
        Err(SinkError::Write(io::Error::other("down")))
    }
}


#[test]
fn a_transient_failure_while_isolating_the_records_is_returned() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let mut gear = default_gear(&bench);
    gear.detector.commit = permanent_then_transient;
    gear.stopping.store(true, Ordering::SeqCst);
    let records = [alert_record("a", &["e1"]), alert_record("a", &["e2"])];
    assert!(matches!(commit_in_place(&gear.detector, "a", &records), Err(SinkError::Write(_))));
    Ok(())
}


#[test]
fn a_tenant_core_pg_refuses_gets_no_engine_and_never_blocks_another_tenant() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = default_gear(&bench);
    detect_batch(&gear.detector, "-x", &documents(&[whoami("e1", 0), whoami("e2", 1)]))?;
    detect_batch(&gear.detector, "b", &documents(&[whoami("e1", 0)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    let counts = gear.detector.permanent.lock().map_err(|_| "poisoned")?;
    assert_eq!(counts.values().copied().sum::<u64>(), TWO as u64);
    assert!(counts.keys().all(|kind| !kind.contains("-x")));
    Ok(())
}


#[test]
fn only_a_refusal_the_store_would_repeat_is_permanent() -> TestResult {
    let range = OffsetDateTime::from_unix_timestamp(i64::MAX).err().ok_or("in range")?;
    let json = serde_json::from_str::<Value>("{").err().ok_or("parsed")?;
    let permanent = [
        SinkError::EventIdTooLong { max: 1 },
        SinkError::EventTimeRange(range),
        SinkError::EventTimeFormat(time::error::Format::InvalidComponent("year")),
        SinkError::TenantMismatch,
        SinkError::Database(PgError::InvalidTenant),
        SinkError::Serialize(json),
        SinkError::Store(StoreError::IdMismatch),
        SinkError::Store(StoreError::TooManyAlerts { limit: 1 }),
        SinkError::Store(StoreError::FieldEmpty { field: "rule_title" }),
    ];
    assert!(permanent.iter().all(is_permanent));
    let transient = [
        SinkError::Exhausted,
        SinkError::WrongStore,
        SinkError::Write(io::Error::other("down")),
        SinkError::Database(PgError::ConnectTimeout { seconds: 1 }),
        SinkError::Store(StoreError::Pg(PgError::InvalidTenant)),
        SinkError::Store(StoreError::BadRow { column: 0 }),
        SinkError::Store(StoreError::Busy),
        SinkError::Store(StoreError::BadCursor),
        SinkError::Store(StoreError::BadEvents(serde_json::from_str::<Value>("{").err().ok_or("parsed")?)),
    ];
    assert!(!transient.iter().any(is_permanent));
    Ok(())
}


#[test]
fn an_event_in_year_10000_or_before_year_0_never_stalls_detection_and_is_stored_clamped() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let stopping = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stopping);
    let policy = CommitPolicy {
        ingest: Arc::clone(&bench.ingest),
        progress: Arc::new(|| Ok(())),
        stop: Arc::new(move || stop_flag.load(Ordering::SeqCst)),
        sleep: no_sleep,
        max_attempts: RETRIES as u32,
    };
    let detector = new_detector(
        Arc::clone(&bench.rules),
        Arc::new(AlertStore::Postgres(pg_store_over(&bench)?)),
        commit_alerts,
        (MAX_ALERTS_PER_BATCH, THREE),
        bench.dir.path().join("checkpoints"),
        policy,
    );
    let late = whoami("e1", 0).replace("2026-11-10T10:00:00Z", "9999-12-31T23:59:59-01:00");
    let early = whoami("e2", 0).replace("2026-11-10T10:00:00Z", "0000-01-01T00:00:00+01:00");
    detect_batch(&detector, "a", &documents(&[late]))?;
    detect_batch(&detector, "c", &documents(&[early]))?;
    detect_batch(&detector, "b", &documents(&[whoami("e3", 0)]))?;
    let statements = statements_of(&mut database);
    assert_eq!(stored_docs(&statements, "b")?.len(), 1);
    assert_eq!(stored_docs(&statements, "a")?.len(), 1);
    assert_eq!(stored_docs(&statements, "c")?.len(), 1);
    assert!(detector.permanent.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[test]
fn six_hundred_matching_events_in_one_batch_are_all_stored() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let stopping = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stopping);
    let policy = CommitPolicy {
        ingest: Arc::clone(&bench.ingest),
        progress: Arc::new(|| Ok(())),
        stop: Arc::new(move || stop_flag.load(Ordering::SeqCst)),
        sleep: no_sleep,
        max_attempts: RETRIES as u32,
    };
    let detector = new_detector(
        Arc::clone(&bench.rules),
        Arc::new(AlertStore::Postgres(pg_store_over(&bench)?)),
        commit_alerts,
        (MAX_ALERTS_PER_BATCH, THREE),
        bench.dir.path().join("checkpoints"),
        policy,
    );
    let payloads: Vec<String> = (0..MANY_ALERTS)
        .map(|number| whoami(&format!("e{number}"), number % SECONDS_PER_MINUTE))
        .collect();
    detect_batch(&detector, "a", &documents(&payloads))?;
    let statements = statements_of(&mut database);
    let stored: usize = stored_docs(&statements, "a")?.iter().map(|doc| doc.as_array().map_or(0, Vec::len)).sum();
    assert_eq!(stored, MANY_ALERTS);
    assert_eq!(statements.iter().filter(|entry| entry.contains("ON CONFLICT")).count(), TWO);
    Ok(())
}


#[test]
fn every_level_is_stored_with_its_own_severity() -> TestResult {
    let expected = [
        (Level::Informational, Severity::Informational),
        (Level::Low, Severity::Low),
        (Level::Medium, Severity::Medium),
        (Level::High, Severity::High),
        (Level::Critical, Severity::Critical),
    ];
    for (level, severity) in expected {
        let record = AlertRecord {
            level,
            ..alert_record("a", &["e1"])
        };
        assert_eq!(severity_of(level), severity);
        assert_eq!(alert_of(&record, 0)?.severity, severity);
    }
    Ok(())
}


const SECONDS_PER_MINUTE: usize = 60;


const REFUSED_BEFORE_SQL: usize = 599;


fn pg_detector(bench: &Bench) -> Result<Detector, Box<dyn Error + Send + Sync>> {
    let stopping = Arc::new(AtomicBool::new(true));
    let policy = CommitPolicy {
        ingest: Arc::clone(&bench.ingest),
        progress: Arc::new(|| Ok(())),
        stop: Arc::new(move || stopping.load(Ordering::SeqCst)),
        sleep: no_sleep,
        max_attempts: RETRIES as u32,
    };
    Ok(new_detector(
        Arc::clone(&bench.rules),
        Arc::new(AlertStore::Postgres(pg_store_over(bench)?)),
        commit_alerts,
        (MAX_ALERTS_PER_BATCH, THREE),
        bench.dir.path().join("checkpoints"),
        policy,
    ))
}


fn connections_of(database: &mut Database) -> usize {
    std::iter::repeat_with(|| database.fake.passwords.try_recv())
        .take(POLL_ATTEMPTS)
        .take_while(Result::is_ok)
        .count()
}


#[test]
fn records_the_store_refuses_are_screened_in_memory_and_cost_no_connection() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let detector = pg_detector(&bench)?;
    let names: Vec<String> = (0..=REFUSED_BEFORE_SQL).map(|number| format!("e{number}")).collect();
    let batch: Vec<AlertRecord> = names
        .iter()
        .enumerate()
        .map(|(number, name)| AlertRecord {
            rule_title: if number == 0 { "ok".to_owned() } else { String::new() },
            ..alert_record("a", &[name.as_str()])
        })
        .collect();
    assert_eq!(commit_in_place(&detector, "a", &batch)?, 1);
    assert_eq!(connections_of(&mut database), 1);
    let statements = statements_of(&mut database);
    assert_eq!(statements.iter().filter(|entry| entry.contains("ON CONFLICT")).count(), 1);
    let counts = detector.permanent.lock().map_err(|_| "poisoned")?;
    assert_eq!(counts.get("field `rule_title` is empty"), Some(&(REFUSED_BEFORE_SQL as u64)));
    assert_eq!(counts.len(), 1);
    Ok(())
}


#[test]
fn a_batch_the_store_refuses_entirely_never_connects() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let detector = pg_detector(&bench)?;
    let batch = [AlertRecord {
        rule_title: String::new(),
        ..alert_record("a", &["e1"])
    }];
    assert_eq!(commit_in_place(&detector, "a", &batch)?, 0);
    assert_eq!(connections_of(&mut database), 0);
    assert!(matches!(screen_records("-x", &batch), Err(SinkError::Database(_))));
    Ok(())
}


#[test]
fn a_transport_failure_drops_the_connection_and_the_next_commit_reconnects() -> TestResult {
    let (mut database, bench) = pg_bench()?;
    let store = pg_store_over(&bench)?;
    let batch = [alert_record("a", &["e1"])];
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    database.hangup.store(true, Ordering::SeqCst);
    assert!(matches!(commit_pg(&store, "a", &batch), Err(SinkError::Store(_))));
    assert!(store.link.lock().map_err(|_| "poisoned")?.is_none());
    database.hangup.store(false, Ordering::SeqCst);
    assert_eq!(commit_pg(&store, "a", &batch)?, 1);
    assert_eq!(connections_of(&mut database), TWO);
    Ok(())
}


#[test]
fn a_tenant_over_the_cap_is_counted_and_acknowledged_not_redelivered() -> TestResult {
    let bench = bench(&[WHOAMI, SEEN_ONCE])?;
    let gear = gear(&bench, (MAX_ALERTS_PER_BATCH, 1));
    detect_batch(&gear.detector, "a", &documents(&[whoami("e1", 0)]))?;
    detect_batch(&gear.detector, "b", &documents(&[whoami("e1", 0), whoami("e2", 1)]))?;
    assert_eq!(records_of(&gear.output)?.len(), 1);
    let counts = gear.detector.permanent.lock().map_err(|_| "poisoned")?;
    assert_eq!(counts.get("more than 1 tenants"), Some(&(TWO as u64)));
    Ok(())
}

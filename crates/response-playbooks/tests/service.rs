#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use alerts::model::{Alert, FeedItem, FeedRow, Severity};
use alerts::store::{summarise, MAX_PAGE_SIZE, PLAYBOOK_ACK_SQL, PLAYBOOK_FEED_SQL};
use alerts::types::{Row, RowFuture};
use core_audit::error::AuditError;
use core_audit::log::{append, append_declared, genesis_log};
use core_audit::model::{NewEntry, Outcome as AuditOutcome};
use core_audit::verify::MAX_RECORD_BYTES;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use response_playbooks::batch::{AlertRun, DryRunReport, SkipReason};
use response_playbooks::bundle::{load_bundle, validate_bundle};
use response_playbooks::error::RoundError;
use response_playbooks::feed::{alert_json, summary_value};
use response_playbooks::model::{ConditionOutcome, Mode, Trace, TraceEvent};
use response_playbooks::service::{
    backoff, bounded_name, list, load_settings, next_failures, open_service_settings, outcome_of, round_entry, run_id, run_round, serve, shown_id,
    sort_page, start_only_changed, validate_settings, Live, Outcome, ServiceSettings, Sorted, INVALID_ID, MAX_BACKOFF_SHIFT, MAX_FEED_AGE_SECONDS,
    MAX_NAME_BYTES, MAX_RECORD_NAMES, NO_RANGE_REQUEST, ROUND_KEYS,
};
use serde_json::{json, Value};
use std::fs;
use std::future::ready;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const BIG_NAME: usize = 10_000;


const BIG_TEXT: usize = 1_000;


const EVENTS_PER_TRACE: usize = 3;


const TRACES_PER_ALERT: usize = 8;


const DISTINCT_NAMES: usize = 800;


const NODE_FLOOD: usize = 1_020;


const AGE_OLD: u64 = MAX_FEED_AGE_SECONDS + 1;


const FIRST_SEQ: u64 = 5;


const LATE_SEQ: u64 = 9;


const EIGHT_SECONDS: u64 = 8;


const SEQ_THREE: u64 = 3;


const SEQ_FOUR: u64 = 4;


const COLUMN_THREE: usize = 3;


const THIRD_CALL: usize = 3;


pub struct Fake {
    pub rows: Mutex<Vec<Row>>,
    pub events: Mutex<Vec<&'static str>>,
    pub entries: Mutex<Vec<NewEntry>>,
    pub fail_feed: Mutex<bool>,
    pub fail_ack: Mutex<bool>,
    pub fail_audit: Mutex<bool>,
}


pub struct Env {
    pub dir: TempDir,
    pub fake: Fake,
    pub live: Live,
}


pub struct Buffer {
    pub bytes: Arc<Mutex<Vec<u8>>>,
}


impl Write for Buffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        lock(&self.bytes).extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}


pub fn wait(_duration: Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(ready(()))
}


pub fn server_error() -> PgError {
    PgError::Server {
        code: "XX000".to_owned(),
        class: "internal",
    }
}


pub fn handle(fake: &Fake, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let first = params.first().ok_or_else(server_error)?;
    if sql == PLAYBOOK_FEED_SQL {
        lock(&fake.events).push("feed");
        if *lock(&fake.fail_feed) {
            Err(server_error())
        } else {
            let size = first.parse::<usize>().map_err(|_bad| server_error())?;
            Ok(lock(&fake.rows).iter().take(size).cloned().collect())
        }
    } else if sql == PLAYBOOK_ACK_SQL {
        lock(&fake.events).push("ack");
        if *lock(&fake.fail_ack) {
            Err(server_error())
        } else {
            let ids: Vec<String> = serde_json::from_str(first).map_err(|_bad| server_error())?;
            let mut rows = lock(&fake.rows);
            let before = rows.len();
            rows.retain(|row| row.first().is_none_or(|id| !ids.contains(id)));
            Ok(vec![vec![(before - rows.len()).to_string()]])
        }
    } else {
        Err(server_error())
    }
}


pub fn audit_into(fake: &Fake, entry: NewEntry) -> Result<(), AuditError> {
    lock(&fake.events).push("audit");
    if *lock(&fake.fail_audit) {
        Err(AuditError::Io(io::Error::other("audit refused")))
    } else {
        lock(&fake.entries).push(entry);
        Ok(())
    }
}


pub fn alert(rule: &str, name: &str, severity: Severity, summary: &Value) -> Alert {
    let event_ids = vec![name.to_owned()];
    Alert {
        id: alert_id("acme", rule, &event_ids),
        tenant: "acme".to_owned(),
        rule_id: rule.to_owned(),
        rule_title: "Whoami executed".to_owned(),
        severity,
        event_time: "2026-11-10T10:00:00Z".to_owned(),
        created_micros: 1,
        host_name: Some("host-1".to_owned()),
        user_name: None,
        event_ids,
        summary: summarise(summary),
    }
}


pub fn whoami(name: &str) -> Alert {
    alert("rule", name, Severity::High, &json!({"process": {"name": "whoami"}}))
}


pub fn row_of(alert: &Alert, seq: u64, age: u64) -> Row {
    vec![
        alert.id.clone(),
        alert.rule_id.clone(),
        alert.rule_title.clone(),
        alert.severity.to_string(),
        alert.event_time.clone(),
        alert.created_micros.to_string(),
        alert.host_name.as_ref().map_or_else(String::new, Clone::clone),
        alert.user_name.as_ref().map_or_else(String::new, Clone::clone),
        json!(alert.event_ids).to_string(),
        alert.summary.text.clone(),
        alert.summary.truncated.to_string(),
        alert.summary.original_bytes.to_string(),
        seq.to_string(),
        age.to_string(),
    ]
}


pub fn settings_in(dir: &Path) -> ServiceSettings {
    ServiceSettings {
        tenant: "acme".to_owned(),
        pg_settings: dir.join("pg.yaml"),
        catalogue: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/catalogue.yaml"),
        inventory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/inventory.yaml"),
        playbooks: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/store_alert.yaml")],
        limits_file: dir.join("limits.yaml"),
        scratch_dir: dir.to_path_buf(),
        audit_file: dir.join("audit.log"),
        poll_interval_seconds: 1,
        page_size: MAX_PAGE_SIZE,
        max_matches_per_alert: THREE,
        max_trace_events: MAX_PAGE_SIZE,
    }
}


pub fn env_with(settings: impl FnOnce(&mut ServiceSettings)) -> Result<Env, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("limits.yaml"), "limits: {}\n")?;
    let mut current = settings_in(dir.path());
    settings(&mut current);
    let bundle = load_bundle(&current.catalogue, &current.inventory, &current.playbooks)?;
    validate_bundle(&bundle)?;
    let fake = Fake {
        rows: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
        entries: Mutex::new(Vec::new()),
        fail_feed: Mutex::new(false),
        fail_ack: Mutex::new(false),
        fail_audit: Mutex::new(false),
    };
    Ok(Env {
        dir,
        fake,
        live: Live {
            bundle: Arc::new(bundle),
            settings: Arc::new(current),
        },
    })
}


pub fn env() -> Result<Env, Box<dyn std::error::Error>> {
    env_with(|_settings| ())
}


pub async fn round(env: &Env, out: &mut impl Write) -> Result<Outcome, RoundError> {
    let exec = |_scope, sql, params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(handle(&env.fake, sql, &params))) };
    let audit = |entry| audit_into(&env.fake, entry);
    let scope = tenant_scope("acme").map_err(|_bad| RoundError::Store(alerts::error::StoreError::BadId))?;
    run_round(&exec, &scope, &env.live, &audit, now, out).await
}


pub fn put(env: &Env, rows: Vec<Row>) {
    lock(&env.fake.rows).extend(rows);
}


pub fn left(env: &Env) -> usize {
    lock(&env.fake.rows).len()
}


pub fn param<'a>(entry: &'a NewEntry, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    Ok(entry.parameters.get(key).ok_or("no such parameter")?.as_str())
}


pub fn recorded(env: &Env) -> Vec<NewEntry> {
    lock(&env.fake.entries).clone()
}


#[test]
fn a_store_alert_maps_to_fixed_keys_with_the_summary_nested() -> TestResult {
    let hostile = json!({"tenant": "evil", "id": "x", "host": {"value": "evil"}, "severity": "low", "process": {"name": "whoami"}});
    let stored = alert("rule", "e1", Severity::High, &hostile);
    let mapped = alert_json("acme", &stored);
    assert_eq!(mapped.get("tenant"), Some(&json!("acme")));
    assert_eq!(mapped.get("id"), Some(&json!(stored.id)));
    assert_eq!(mapped.get("host"), Some(&json!({"value": "host-1"})));
    assert_eq!(mapped.get("severity"), Some(&json!("high")));
    assert_eq!(mapped.get("summary"), Some(&hostile));
    assert!(mapped.get("user").is_none());
    assert_eq!(mapped.get("created"), Some(&json!(1)));
    assert_eq!(mapped.pointer("/summary/process/name"), Some(&json!("whoami")));
    let with_user = Alert {
        user_name: Some("root".to_owned()),
        host_name: None,
        ..stored
    };
    let other = alert_json("acme", &with_user);
    assert_eq!(other.get("user"), Some(&json!({"value": "root"})));
    assert!(other.get("host").is_none());
    Ok(())
}


#[test]
fn a_summary_stays_text_unless_whole_and_an_object() -> TestResult {
    let whole = alert("rule", "e1", Severity::High, &json!({"a": 1}));
    assert_eq!(summary_value(&whole.summary), json!({"a": 1}));
    let mut cut = whole.summary.clone();
    cut.truncated = true;
    assert_eq!(summary_value(&cut), json!(cut.text));
    let array = alert("rule", "e2", Severity::High, &json!([1]));
    assert_eq!(summary_value(&array.summary), json!("[1]"));
    let mut repeated = whole.summary.clone();
    repeated.text = "{\"a\":1,\"a\":2}".to_owned();
    assert_eq!(summary_value(&repeated), json!(repeated.text));
    Ok(())
}


#[test]
fn settings_are_bounded_and_the_start_only_part_is_pinned() -> TestResult {
    let dir = tempdir()?;
    let good = settings_in(dir.path());
    validate_settings(&good)?;
    let breakers: Vec<fn(&mut ServiceSettings)> = vec![
        |settings| settings.tenant = "-x".to_owned(),
        |settings| settings.playbooks = Vec::new(),
        |settings| settings.poll_interval_seconds = 0,
        |settings| settings.page_size = MAX_PAGE_SIZE + 1,
        |settings| settings.max_matches_per_alert = 0,
        |settings| settings.max_trace_events = 0,
    ];
    breakers.iter().for_each(|breaker| {
        let mut bad = good.clone();
        breaker(&mut bad);
        assert!(validate_settings(&bad).is_err());
    });
    let mut live_change = good.clone();
    live_change.page_size = TWO;
    live_change.poll_interval_seconds = THREE as u64;
    live_change.max_matches_per_alert = 1;
    live_change.max_trace_events = FIVE;
    assert!(!start_only_changed(&good, &live_change));
    let mut moved = good.clone();
    moved.tenant = "globex".to_owned();
    assert!(start_only_changed(&good, &moved));
    let mut other_pg = good.clone();
    other_pg.pg_settings = PathBuf::from("/elsewhere");
    assert!(start_only_changed(&good, &other_pg));
    Ok(())
}


pub fn yaml_of(settings: &ServiceSettings, page_size: usize, tenant: &str) -> String {
    format!(
        "tenant: {tenant}\npg_settings: {}\ncatalogue: {}\ninventory: {}\nplaybooks: [{}]\nlimits_file: {}\nscratch_dir: {}\naudit_file: {}\n\
         poll_interval_seconds: 1\npage_size: {page_size}\nmax_matches_per_alert: 3\nmax_trace_events: 100\n",
        settings.pg_settings.display(),
        settings.catalogue.display(),
        settings.inventory.display(),
        settings
            .playbooks
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        settings.limits_file.display(),
        settings.scratch_dir.display(),
        settings.audit_file.display(),
    )
}


#[test]
fn a_reload_changes_the_live_values_and_refuses_and_audits_the_start_only_ones() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    let base = settings_in(dir.path());
    fs::write(&file, yaml_of(&base, MAX_PAGE_SIZE, "acme"))?;
    assert_eq!(load_settings(&file)?.page_size, MAX_PAGE_SIZE);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::new(genesis_log(Buffer { bytes: Arc::clone(&bytes) }));
    let engine = open_service_settings(&file, Box::new(move |entry| append(&log, entry)))?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    fs::write(&file, yaml_of(&base, TWO, "acme"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(core_config::reload::current_config(&engine).page_size, TWO);
    fs::write(&file, yaml_of(&base, TWO, "globex"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(core_config::reload::current_config(&engine).tenant, "acme");
    let text = String::from_utf8(lock(&bytes).clone())?;
    assert!(text.contains("denied") && text.contains("read at start only"));
    fs::write(&file, "tenant: acme\n")?;
    assert!(load_settings(&file).is_err());
    assert!(open_service_settings(&file, Box::new(|_entry| Err(AuditError::Io(io::Error::other("none"))))).is_err());
    Ok(())
}


#[test]
fn a_page_is_sorted_into_runnable_expired_and_undecodable_rows() -> TestResult {
    let fresh = whoami("e1");
    let old = whoami("e2");
    let items = vec![
        FeedItem {
            id: fresh.id.clone(),
            row: Ok(FeedRow {
                seq: LATE_SEQ,
                age_seconds: 0,
                alert: fresh.clone(),
            }),
        },
        FeedItem {
            id: old.id.clone(),
            row: Ok(FeedRow {
                seq: FIRST_SEQ,
                age_seconds: AGE_OLD,
                alert: old.clone(),
            }),
        },
        FeedItem {
            id: "not an id".to_owned(),
            row: Err(alerts::error::StoreError::BadId),
        },
    ];
    let sorted = sort_page(&items);
    assert_eq!(sorted.runnable.len(), 1);
    assert_eq!(sorted.expired, vec![old.id]);
    assert_eq!(sorted.undecodable, vec![INVALID_ID.to_owned()]);
    assert_eq!(sorted.range, Some((FIRST_SEQ, LATE_SEQ)));
    assert_eq!(sort_page(&[]).range, None);
    assert_eq!(shown_id(&fresh.id), fresh.id);
    assert_eq!(shown_id("x"), INVALID_ID);
    Ok(())
}


#[test]
fn names_are_cut_on_a_character_boundary_and_listed_as_json() -> TestResult {
    assert_eq!(bounded_name("short"), "short");
    let long = "é".repeat(MAX_NAME_BYTES);
    assert_eq!(bounded_name(&long).len(), MAX_NAME_BYTES);
    assert_eq!(list(&["a".to_owned(), "b\"c".to_owned()]), "[\"a\",\"b\\\"c\"]");
    assert_eq!(backoff(THREE as u64, 0), Duration::from_secs(THREE as u64));
    assert_eq!(backoff(1, THREE as u32), Duration::from_secs(EIGHT_SECONDS));
    assert_eq!(backoff(1, u32::MAX), Duration::from_secs(1 << MAX_BACKOFF_SHIFT));
    let failed: Result<Outcome, RoundError> = Err(RoundError::Store(alerts::error::StoreError::BadId));
    assert_eq!(next_failures(THREE as u32, &failed), THREE as u32 + 1);
    assert_eq!(next_failures(u32::MAX, &failed), u32::MAX);
    assert_eq!(next_failures(THREE as u32, &Ok(Outcome::default())), 0);
    Ok(())
}


pub fn run_of(position: usize, skipped: Option<SkipReason>, names: &[String]) -> AlertRun {
    AlertRun {
        position,
        request_id: format!("dry-run-{position}"),
        skipped,
        traces: names
            .iter()
            .map(|name| Trace {
                playbook: name.clone(),
                version: 1,
                mode: Mode::Simulate,
                events: (0..EVENTS_PER_TRACE)
                    .map(|_event| TraceEvent::Condition {
                        path: "steps.0".to_owned(),
                        expression: "x".repeat(BIG_TEXT),
                        outcome: ConditionOutcome::True,
                    })
                    .collect(),
            })
            .collect(),
        matches_over_bound: 1,
        matches_over_budget: 1,
        events_omitted: 1,
    }
}


#[test]
fn the_largest_possible_record_fits_the_audit_bound_and_holds_no_trace_text() -> TestResult {
    let stored: Vec<Alert> = (0..MAX_PAGE_SIZE).map(|index| whoami(&format!("e{index}"))).collect();
    let rows: Vec<FeedRow> = stored
        .iter()
        .map(|alert| FeedRow {
            seq: 1,
            age_seconds: 0,
            alert: alert.clone(),
        })
        .collect();
    let sorted = Sorted {
        runnable: rows.iter().collect(),
        expired: stored.iter().map(|alert| alert.id.clone()).collect(),
        undecodable: vec![INVALID_ID.to_owned(); MAX_PAGE_SIZE],
        range: Some((u64::MAX - 1, u64::MAX)),
    };
    let runs: Vec<AlertRun> = (0..MAX_PAGE_SIZE)
        .map(|position| {
            if position % TWO == 0 {
                run_of(position, Some(SkipReason::TooMuchText), &[])
            } else {
                let names: Vec<String> = (0..TRACES_PER_ALERT)
                    .map(|index| format!("{}{}", position * TRACES_PER_ALERT + index, "n".repeat(BIG_NAME)))
                    .collect();
                run_of(position, None, &names)
            }
        })
        .collect();
    let report = DryRunReport {
        tenant_refused: false,
        alerts: runs,
        alerts_not_run: 0,
        trace_events: 1,
    };
    let items: Vec<FeedItem> = Vec::new();
    let outcome = outcome_of(&items, &sorted, Some(&report), 0);
    assert_eq!(outcome.playbooks.len(), MAX_RECORD_NAMES);
    assert_eq!(outcome.playbooks_omitted, DISTINCT_NAMES / TWO - MAX_RECORD_NAMES);
    assert_eq!(outcome.bounds, vec!["backlog", "max_matches_per_alert", "max_trace_events"]);
    let rendered = response_playbooks::render::render_dry_run(&report);
    assert!(rendered.len() > MAX_RECORD_BYTES);
    let entry = round_entry("acme", &outcome, now());
    let size: usize = entry.parameters.values().map(String::len).sum();
    assert!(size < MAX_RECORD_BYTES / THREE);
    assert!(entry
        .parameters
        .values()
        .all(|value| !value.contains("steps.0") && !value.contains("condition")));
    let log = genesis_log(io::sink());
    let written = append_declared(&log, entry, &ROUND_KEYS)?;
    assert!(written.parameters.values().all(|value| value != "[REDACTED]"));
    assert_eq!(written.request_id, format!("round-{}-{}", u64::MAX - 1, u64::MAX));
    Ok(())
}


#[tokio::test]
async fn a_round_simulates_audits_and_only_then_deletes() -> TestResult {
    let env = env()?;
    let matching = whoami("e1");
    let quiet = alert("rule", "e2", Severity::Low, &json!({"process": {"name": "whoami"}}));
    put(&env, vec![row_of(&matching, FIRST_SEQ, 0), row_of(&quiet, FIRST_SEQ + 1, 0)]);
    let mut trace = Vec::new();
    let outcome = round(&env, &mut trace).await?;
    assert_eq!((outcome.read, outcome.simulated, outcome.matches), (TWO, TWO, 1));
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed", "audit", "ack"]);
    assert_eq!(left(&env), 0);
    let text = String::from_utf8(trace)?;
    assert!(text.contains("playbook Notify on store alert v1 mode=simulate") && text.contains("action"));
    let entries = recorded(&env);
    let entry = entries.first().ok_or("no record")?;
    assert_eq!(entry.outcome, AuditOutcome::Success);
    assert_eq!(entry.tenant, "acme");
    assert_eq!(param(entry, "alerts")?, "2");
    assert_eq!((param(entry, "seq_first")?, param(entry, "seq_last")?), ("5", "6"));
    assert_eq!(param(entry, "matched_alerts")?, json!([matching.id]).to_string());
    assert_eq!(param(entry, "playbooks")?, "[\"Notify on store alert\"]");
    assert_eq!(entry.request_id, "round-5-6");
    assert!(entry
        .parameters
        .values()
        .all(|value| !value.contains("Whoami executed") && !value.contains("#soc")));
    Ok(())
}


#[tokio::test]
async fn an_empty_round_writes_no_record_and_deletes_nothing() -> TestResult {
    let env = env()?;
    let mut trace = Vec::new();
    let outcome = round(&env, &mut trace).await?;
    assert_eq!(outcome, Outcome::default());
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed"]);
    assert!(trace.is_empty() && recorded(&env).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failed_audit_keeps_every_row_and_deletes_nothing() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), 1, 0)]);
    *lock(&env.fake.fail_audit) = true;
    let failed = round(&env, &mut Vec::new()).await;
    assert!(matches!(failed, Err(RoundError::Audit(_))));
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed", "audit"]);
    assert_eq!(left(&env), 1);
    Ok(())
}


#[tokio::test]
async fn a_crash_between_the_record_and_the_delete_replays_the_page_with_the_same_range() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_ack) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Store(_))));
    *lock(&env.fake.fail_ack) = false;
    round(&env, &mut Vec::new()).await?;
    let entries = recorded(&env);
    assert_eq!(entries.len(), TWO);
    let ranges: Vec<&str> = entries.iter().map(|entry| entry.request_id.as_str()).collect();
    assert_eq!(ranges, ["round-5-5", "round-5-5"]);
    assert_eq!(left(&env), 0);
    Ok(())
}


#[tokio::test]
async fn a_failing_feed_trace_writer_or_dry_run_keeps_the_rows() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), 1, 0)]);
    *lock(&env.fake.fail_feed) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Store(_))));
    *lock(&env.fake.fail_feed) = false;
    assert!(matches!(round(&env, &mut FailingWriter).await, Err(RoundError::Trace(_))));
    assert!(recorded(&env).is_empty());
    assert_eq!(left(&env), 1);
    let broken = env_with(|settings| settings.limits_file = PathBuf::from("/nonexistent/limits.yaml"))?;
    put(&broken, vec![row_of(&whoami("e1"), 1, 0)]);
    assert!(matches!(round(&broken, &mut Vec::new()).await, Err(RoundError::DryRun(_))));
    assert_eq!(left(&broken), 1);
    assert!(recorded(&broken).is_empty());
    Ok(())
}


#[tokio::test]
async fn expired_undecodable_and_skipped_rows_are_named_and_deleted_and_the_next_alert_still_runs() -> TestResult {
    let env = env()?;
    let old = whoami("old");
    let flood: Vec<u64> = vec![1; NODE_FLOOD];
    let heavy = alert("rule", "heavy", Severity::High, &json!({"process": {"name": "whoami"}, "n": flood}));
    let mut headless = row_of(&whoami("bad"), SEQ_THREE, 0);
    headless.get_mut(COLUMN_THREE).ok_or("column")?.clear();
    let mut odd_id = row_of(&whoami("odd"), SEQ_FOUR, 0);
    odd_id.first_mut().ok_or("column")?.push_str("-odd");
    let rows = vec![
        row_of(&old, 1, AGE_OLD),
        headless,
        odd_id,
        row_of(&heavy, FIRST_SEQ, 0),
        row_of(&whoami("good"), FIRST_SEQ + 1, 0),
    ];
    put(&env, rows);
    let exec = |_scope, sql, params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(handle(&env.fake, sql, &params))) };
    let audit = |entry| audit_into(&env.fake, entry);
    let scope = tenant_scope("acme")?;
    let mut trace = Vec::new();
    let outcome = run_round(&exec, &scope, &env.live, &audit, now, &mut trace).await?;
    assert_eq!(left(&env), 0);
    assert_eq!(outcome.expired, vec![old.id.clone()]);
    assert_eq!(outcome.undecodable.len(), TWO);
    assert!(outcome.undecodable.iter().any(|shown| shown == INVALID_ID));
    assert_eq!(outcome.skipped.len(), 1);
    assert!(outcome.skipped.iter().all(|entry| entry.starts_with(&heavy.id)));
    assert_eq!(outcome.matches, 1);
    assert_eq!(outcome.simulated, 1);
    Ok(())
}


#[tokio::test]
async fn a_round_of_only_expired_rows_simulates_nothing_still_writes_a_record_and_deletes() -> TestResult {
    let env = env()?;
    let old = whoami("old");
    put(&env, vec![row_of(&old, 1, AGE_OLD)]);
    let mut trace = Vec::new();
    let outcome = round(&env, &mut trace).await?;
    assert_eq!((outcome.read, outcome.simulated, outcome.matches), (1, 0, 0));
    assert_eq!(outcome.expired, vec![old.id.clone()]);
    assert!(trace.is_empty());
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed", "audit", "ack"]);
    assert_eq!(recorded(&env).len(), 1);
    assert_eq!(left(&env), 0);
    Ok(())
}


#[tokio::test]
async fn a_round_of_only_undecodable_rows_has_no_range_and_a_run_outside_the_page_is_named_invalid() -> TestResult {
    let env = env()?;
    let mut odd_id = row_of(&whoami("odd"), 1, 0);
    odd_id.first_mut().ok_or("column")?.push_str("-odd");
    put(&env, vec![odd_id]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!(outcome.range, None);
    let entries = recorded(&env);
    assert_eq!(entries.first().ok_or("no record")?.request_id, NO_RANGE_REQUEST);
    assert_eq!(run_id(&Sorted::default(), &run_of(FIRST_SEQ as usize, None, &[])), INVALID_ID);
    Ok(())
}


#[tokio::test]
async fn a_full_page_names_the_backlog_and_only_the_page_is_deleted() -> TestResult {
    let env = env_with(|settings| settings.page_size = TWO)?;
    let rows: Vec<Row> = (0..THREE).map(|index| row_of(&whoami(&format!("e{index}")), index as u64, 0)).collect();
    put(&env, rows);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!(outcome.bounds, vec!["backlog"]);
    assert_eq!(left(&env), 1);
    Ok(())
}


#[tokio::test]
async fn an_alert_that_commits_late_is_read_in_a_later_round() -> TestResult {
    let env = env()?;
    let second = whoami("second");
    let first = whoami("first");
    put(&env, vec![row_of(&second, FIRST_SEQ + 1, 0)]);
    round(&env, &mut Vec::new()).await?;
    put(&env, vec![row_of(&first, FIRST_SEQ, 0)]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!((outcome.read, outcome.range), (1, Some((FIRST_SEQ, FIRST_SEQ))));
    assert_eq!(left(&env), 0);
    Ok(())
}


pub fn failing_then_fine(call: usize) -> Result<Outcome, RoundError> {
    match call {
        early if early < THIRD_CALL => Err(RoundError::Store(alerts::error::StoreError::BadId)),
        THIRD_CALL => Ok(Outcome {
            read: 1,
            ..Outcome::default()
        }),
        _other => Ok(Outcome::default()),
    }
}


#[tokio::test]
async fn the_service_loop_takes_a_snapshot_per_round_and_survives_failures() -> TestResult {
    let env = env()?;
    let seen = Mutex::new(Vec::new());
    let live = || env.live.clone();
    let mut calls = 0;
    let mut one_round = |snapshot: Live| {
        lock(&seen).push(snapshot.settings.page_size);
        let outcome = failing_then_fine(calls);
        calls += 1;
        ready(outcome)
    };
    serve(FIVE, &live, &mut one_round, wait).await;
    assert_eq!(calls, FIVE);
    assert_eq!(lock(&seen).len(), FIVE);
    Ok(())
}


#[test]
fn nothing_in_the_service_can_reach_a_connector() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    ["service.rs", "feed.rs"].iter().try_for_each(|file| -> TestResult {
        let text = fs::read_to_string(root.join(file))?;
        [
            "ConnectorFn",
            "ConnectorCall",
            "ConnectorResult",
            "call_connector",
            "crate::run",
            "model::Executor",
            "open_breakers",
            "Breakers",
        ]
        .iter()
        .for_each(|name| assert!(!text.contains(name), "{file} names {name}"));
        Ok(())
    })?;
    Ok(())
}

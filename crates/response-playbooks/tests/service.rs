#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use alerts::id::is_alert_id;
use alerts::model::{Alert, FeedItem, FeedRow, Severity};
use alerts::store::{summarise, MAX_PAGE_SIZE, PLAYBOOK_ACK_SQL, PLAYBOOK_FEED_SQL};
use alerts::types::{Row, RowFuture};
use core_audit::error::AuditError;
use core_audit::log::{append, append_declared, genesis_log};
use core_audit::model::{NewEntry, Outcome as AuditOutcome};
use core_audit::verify::MAX_RECORD_BYTES;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use core_pg::transaction::Boundary;
use response_playbooks::batch::{AlertRun, DryRunReport, SkipReason};
use response_playbooks::bundle::{load_bundle, validate_bundle};
use response_playbooks::error::RoundError;
use response_playbooks::feed::{alert_json, summary_value};
use response_playbooks::model::{ConditionOutcome, Mode, Trace, TraceEvent};
use response_playbooks::render::{render_trace_redacted, write_dry_run_redacted};
use response_playbooks::runs::{
    bounded_trace, cut_text, playbook_run_id, row_of as run_row_of, run_rows, RunRow, COUNT_SQL, CUT_MARKER, INSERT_SQL, LOCK_SQL, MAX_PLAYBOOK_RUNS,
    MAX_TRACE_BYTES, MIGRATIONS, MIGRATION_NAMESPACE, PRUNE_SQL,
};
use response_playbooks::service::log_pruned;
use response_playbooks::service::{
    backoff, bounded_name, is_loud, is_replay, list, load_settings, log_partial_ack, next_failures, next_replays, open_service_settings, outcome_of,
    round_entry, run_id, run_round, serve, shown_id, sort_page, start_only_changed, validate_settings, Db, Live, Outcome, Replays, ServiceSettings,
    Sorted, INVALID_ID, MAX_BACKOFF_SHIFT, MAX_FEED_AGE_SECONDS, MAX_NAME_BYTES, MAX_RECORD_NAMES, MAX_REPLAYED_ROUNDS, NO_RANGE_REQUEST, ROUND_KEYS,
};
use response_playbooks::types::ControlFuture;
use response_playbooks::types::ParamMap;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
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


const ID_HEX: usize = 64;


const FIVE: usize = 5;


const FOUR: u32 = 4;


const EIGHT: u32 = 8;


const SIXTEEN: u32 = 16;


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


const SEQ_COLUMN: usize = 12;


const THIRD_CALL: usize = 3;


pub struct Fake {
    pub rows: Mutex<Vec<Row>>,
    pub events: Mutex<Vec<&'static str>>,
    pub entries: Mutex<Vec<NewEntry>>,
    pub fail_feed: Mutex<bool>,
    pub fail_ack: Mutex<bool>,
    pub fail_audit: Mutex<bool>,
    pub short_ack: Mutex<bool>,
    pub over_ack: Mutex<bool>,
    pub fail_commit: Mutex<bool>,
    pub fail_begin: Mutex<bool>,
    pub fail_rollback: Mutex<bool>,
    pub fail_insert: Mutex<bool>,
    pub bad_count: Mutex<bool>,
    pub runs: Mutex<BTreeMap<String, u64>>,
    pub documents: Mutex<Vec<String>>,
    pub created: Mutex<Vec<String>>,
    pub tenants: Mutex<Vec<String>>,
    pub saved: Mutex<Option<Saved>>,
}


pub struct Saved {
    pub rows: Vec<Row>,
    pub runs: BTreeMap<String, u64>,
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


pub fn first_param(params: &[String]) -> Result<&String, PgError> {
    params.first().ok_or_else(server_error)
}


pub fn insert_runs(fake: &Fake, params: &[String]) -> Result<Vec<Row>, PgError> {
    let document = first_param(params)?;
    lock(&fake.documents).push(document.clone());
    lock(&fake.created).push(params.get(1).ok_or_else(server_error)?.clone());
    let items: Vec<Value> = serde_json::from_str(document).map_err(|_bad| server_error())?;
    let mut runs = lock(&fake.runs);
    let mut written = 0;
    for item in &items {
        let id = item.get("id").and_then(Value::as_str).ok_or_else(server_error)?;
        if !runs.contains_key(id) {
            let seq = runs.values().max().map_or(1, |top| top + 1);
            runs.insert(id.to_owned(), seq);
            written += 1;
        }
    }
    Ok(vec![vec![written.to_string()]])
}


pub fn prune_runs(fake: &Fake, params: &[String]) -> Result<Vec<Row>, PgError> {
    let count: usize = first_param(params)?.parse().map_err(|_bad| server_error())?;
    let mut runs = lock(&fake.runs);
    let mut by_seq: Vec<(u64, String)> = runs.iter().map(|(id, seq)| (*seq, id.clone())).collect();
    by_seq.sort();
    let doomed: Vec<String> = by_seq.into_iter().take(count).map(|(_seq, id)| id).collect();
    doomed.iter().for_each(|id| {
        runs.remove(id);
    });
    Ok(vec![vec![doomed.len().to_string()]])
}


pub fn restore(fake: &Fake) {
    if let Some(saved) = lock(&fake.saved).take() {
        *lock(&fake.rows) = saved.rows;
        *lock(&fake.runs) = saved.runs;
    }
}


pub fn cross_fake(fake: &Fake, boundary: Boundary) -> Result<(), PgError> {
    match boundary {
        Boundary::Begin => {
            lock(&fake.events).push("begin");
            if *lock(&fake.fail_begin) {
                Err(server_error())
            } else {
                *lock(&fake.saved) = Some(Saved {
                    rows: lock(&fake.rows).clone(),
                    runs: lock(&fake.runs).clone(),
                });
                Ok(())
            }
        }
        Boundary::Commit => {
            lock(&fake.events).push("commit");
            if *lock(&fake.fail_commit) {
                restore(fake);
                Err(server_error())
            } else {
                *lock(&fake.saved) = None;
                Ok(())
            }
        }
        Boundary::Rollback => {
            lock(&fake.events).push("rollback");
            restore(fake);
            if *lock(&fake.fail_rollback) {
                Err(server_error())
            } else {
                Ok(())
            }
        }
    }
}


pub fn handle(fake: &Fake, tenant: &str, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    lock(&fake.tenants).push(tenant.to_owned());
    if sql == LOCK_SQL {
        lock(&fake.events).push("lock");
        Ok(vec![vec![String::new()]])
    } else if sql == INSERT_SQL {
        lock(&fake.events).push("insert");
        if *lock(&fake.fail_insert) {
            Err(server_error())
        } else {
            insert_runs(fake, params)
        }
    } else if sql == COUNT_SQL {
        lock(&fake.events).push("count");
        if *lock(&fake.bad_count) {
            Ok(vec![vec!["many".to_owned()]])
        } else {
            Ok(vec![vec![lock(&fake.runs).len().to_string()]])
        }
    } else if sql == PRUNE_SQL {
        lock(&fake.events).push("prune");
        prune_runs(fake, params)
    } else {
        handle_feed(fake, sql, params)
    }
}


pub fn handle_feed(fake: &Fake, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let first = first_param(params)?;
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
            if !*lock(&fake.short_ack) {
                rows.retain(|row| row.first().is_none_or(|id| !ids.contains(id)));
            }
            let extra = usize::from(*lock(&fake.over_ack));
            Ok(vec![vec![(before - rows.len() + extra).to_string()]])
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
        format!("(0,{seq})"),
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
    let mut current = settings_in(dir.path());
    settings(&mut current);
    build_env(dir, current)
}


pub fn env_with_two_playbooks() -> Result<Env, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let mut current = settings_in(dir.path());
    let second = dir.path().join("second.yaml");
    fs::copy(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/store_alert.yaml"), &second)?;
    current.playbooks.push(second);
    build_env(dir, current)
}


pub fn build_env(dir: TempDir, current: ServiceSettings) -> Result<Env, Box<dyn std::error::Error>> {
    fs::write(dir.path().join("limits.yaml"), "limits: {}\n")?;
    let bundle = load_bundle(&current.catalogue, &current.inventory, &current.playbooks)?;
    validate_bundle(&bundle)?;
    let fake = new_fake();
    Ok(Env {
        dir,
        fake,
        live: Live {
            bundle: Arc::new(bundle),
            settings: Arc::new(current),
        },
    })
}


pub fn new_fake() -> Fake {
    Fake {
        rows: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
        entries: Mutex::new(Vec::new()),
        fail_feed: Mutex::new(false),
        fail_ack: Mutex::new(false),
        fail_audit: Mutex::new(false),
        short_ack: Mutex::new(false),
        over_ack: Mutex::new(false),
        fail_commit: Mutex::new(false),
        fail_begin: Mutex::new(false),
        fail_rollback: Mutex::new(false),
        fail_insert: Mutex::new(false),
        bad_count: Mutex::new(false),
        runs: Mutex::new(BTreeMap::new()),
        documents: Mutex::new(Vec::new()),
        created: Mutex::new(Vec::new()),
        tenants: Mutex::new(Vec::new()),
        saved: Mutex::new(None),
    }
}


pub fn env() -> Result<Env, Box<dyn std::error::Error>> {
    env_with(|_settings| ())
}


pub async fn drive(env: &Env, out: &mut impl Write, replays: &mut Replays) -> Result<Outcome, RoundError> {
    let exec =
        |scope: TenantScope, sql, params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(handle(&env.fake, tenant_of(&scope), sql, &params))) };
    let control = |boundary| -> ControlFuture<'_> { Box::pin(ready(cross_fake(&env.fake, boundary))) };
    let db = Db {
        exec: &exec,
        control: &control,
    };
    let audit = |entry| audit_into(&env.fake, entry);
    let scope = tenant_scope("acme").map_err(|_bad| RoundError::Store(alerts::error::StoreError::BadId))?;
    run_round(&db, &scope, &env.live, &audit, now, out, replays).await
}


pub async fn round(env: &Env, out: &mut impl Write) -> Result<Outcome, RoundError> {
    drive(env, out, &mut Replays::default()).await
}


pub async fn round_with(env: &Env, replays: &mut Replays) -> Result<Outcome, RoundError> {
    drive(env, &mut Vec::new(), replays).await
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
            tid: "(0,1)".to_owned(),
            seq: Some(LATE_SEQ),
            row: Ok(FeedRow {
                seq: LATE_SEQ,
                age_seconds: 0,
                alert: fresh.clone(),
            }),
        },
        FeedItem {
            id: old.id.clone(),
            tid: "(0,1)".to_owned(),
            seq: Some(FIRST_SEQ),
            row: Ok(FeedRow {
                seq: FIRST_SEQ,
                age_seconds: AGE_OLD,
                alert: old.clone(),
            }),
        },
        FeedItem {
            id: "not an id".to_owned(),
            tid: "(0,2)".to_owned(),
            seq: Some(SEQ_THREE),
            row: Err(alerts::error::StoreError::BadId),
        },
    ];
    let sorted = sort_page(&items);
    assert_eq!(sorted.runnable.len(), 1);
    assert_eq!(sorted.expired, vec![old.id]);
    assert_eq!(sorted.undecodable, vec![INVALID_ID.to_owned()]);
    assert_eq!(sorted.range, Some((SEQ_THREE, LATE_SEQ)));
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
        files: names.iter().map(|name| format!("{name}.yaml")).collect(),
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
    assert_eq!(
        lock(&env.fake.events).as_slice(),
        ["feed", "begin", "lock", "insert", "count", "ack", "audit", "commit"]
    );
    assert_eq!(left(&env), 0);
    assert_eq!(lock(&env.fake.runs).len(), 1);
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
    assert_eq!(
        (
            param(entry, "runs_written")?,
            param(entry, "runs_replayed")?,
            param(entry, "runs_pruned")?
        ),
        ("1", "0", "0")
    );
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
    assert_eq!(
        lock(&env.fake.events).as_slice(),
        ["feed", "begin", "lock", "insert", "count", "ack", "audit", "rollback"]
    );
    assert_eq!(left(&env), 1);
    assert!(lock(&env.fake.runs).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_crash_between_the_record_and_the_commit_replays_the_page_with_the_same_range_and_one_run() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_commit) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Pg(_))));
    assert!(lock(&env.fake.runs).is_empty());
    *lock(&env.fake.fail_commit) = false;
    let replayed = round(&env, &mut Vec::new()).await?;
    assert_eq!((replayed.runs_written, replayed.runs_replayed), (1, 0));
    assert_eq!(lock(&env.fake.runs).len(), 1);
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
    let mut trace = Vec::new();
    let outcome = round(&env, &mut trace).await?;
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
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed", "begin", "ack", "audit", "commit"]);
    assert_eq!(recorded(&env).len(), 1);
    assert_eq!(left(&env), 0);
    Ok(())
}


#[tokio::test]
async fn a_round_of_only_undecodable_rows_has_a_range_and_a_run_outside_the_page_is_named_invalid() -> TestResult {
    let env = env()?;
    let mut odd_id = row_of(&whoami("odd"), SEQ_THREE, 0);
    odd_id.first_mut().ok_or("column")?.push_str("-odd");
    let mut odd_too = row_of(&whoami("odd2"), SEQ_FOUR, 0);
    odd_too.first_mut().ok_or("column")?.push_str("-odd");
    put(&env, vec![odd_id, odd_too]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!((outcome.read, outcome.simulated, outcome.range), (TWO, 0, Some((SEQ_THREE, SEQ_FOUR))));
    let entries = recorded(&env);
    assert_eq!(entries.first().ok_or("no record")?.request_id, "round-3-4");
    assert_eq!(run_id(&Sorted::default(), &run_of(FIRST_SEQ as usize, None, &[])), INVALID_ID);
    Ok(())
}


#[tokio::test]
async fn a_round_whose_rows_have_no_readable_seq_has_no_range() -> TestResult {
    let env = env()?;
    let mut unreadable = row_of(&whoami("odd"), 1, 0);
    unreadable.get_mut(SEQ_COLUMN).ok_or("column")?.clear();
    put(&env, vec![unreadable]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!((outcome.read, outcome.range, outcome.undecodable.len()), (1, None, 1));
    assert_eq!(recorded(&env).first().ok_or("no record")?.request_id, NO_RANGE_REQUEST);
    assert_eq!(left(&env), 0);
    Ok(())
}


#[tokio::test]
async fn consecutive_failed_deletes_stop_appending_after_the_replay_cap_and_resume_once_deleted() -> TestResult {
    let env = env()?;
    let e1 = whoami("e1");
    put(&env, vec![row_of(&e1, FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_commit) = true;
    let mut replays = Replays::default();
    let rounds = MAX_REPLAYED_ROUNDS as usize + TWO;
    for _attempt in 0..rounds {
        assert!(matches!(round_with(&env, &mut replays).await, Err(RoundError::Pg(_))));
    }
    assert_eq!(recorded(&env).len(), MAX_REPLAYED_ROUNDS as usize);
    assert_eq!(
        replays,
        Replays {
            ids: ids_of(&[&e1.id]),
            records: MAX_REPLAYED_ROUNDS
        }
    );
    *lock(&env.fake.fail_commit) = false;
    round_with(&env, &mut replays).await?;
    assert_eq!(recorded(&env).len(), MAX_REPLAYED_ROUNDS as usize);
    assert_eq!((left(&env), replays.clone()), (0, Replays::default()));
    put(&env, vec![row_of(&whoami("e2"), LATE_SEQ, 0)]);
    round_with(&env, &mut replays).await?;
    assert_eq!(recorded(&env).len(), MAX_REPLAYED_ROUNDS as usize + 1);
    Ok(())
}


pub fn ids_of(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}


#[test]
fn a_page_with_an_id_outside_the_recorded_set_restarts_the_replay_count() -> TestResult {
    let low = ids_of(&["a", "b"]);
    let first = next_replays(&Replays::default(), &low);
    let again = next_replays(&first, &low);
    let shrunk = next_replays(&again, &ids_of(&["a"]));
    let grown = next_replays(&shrunk, &low);
    assert_eq!(
        (first.records, again.records, shrunk.records, grown.records),
        (1, TWO as u32, THREE as u32, 1)
    );
    assert_eq!(grown.ids, low);
    let capped = Replays {
        ids: low.clone(),
        records: MAX_REPLAYED_ROUNDS,
    };
    assert!(is_replay(&capped, &low) && is_replay(&capped, &ids_of(&["a"])));
    assert!(!is_replay(&capped, &ids_of(&["a", "late"])));
    assert!(!is_replay(
        &Replays {
            ids: low.clone(),
            records: 1
        },
        &low
    ));
    Ok(())
}


#[tokio::test]
async fn a_late_row_inside_the_range_is_named_in_a_record_before_its_row_is_deleted() -> TestResult {
    let env = env()?;
    let (x1, x2, x3) = (whoami("x1"), whoami("x2"), whoami("x3"));
    put(&env, vec![row_of(&x1, SEQ_THREE, 0), row_of(&x3, FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_commit) = true;
    let mut replays = Replays::default();
    for _attempt in 0..=MAX_REPLAYED_ROUNDS {
        assert!(matches!(round_with(&env, &mut replays).await, Err(RoundError::Pg(_))));
    }
    assert_eq!(recorded(&env).len(), MAX_REPLAYED_ROUNDS as usize);
    lock(&env.fake.rows).insert(1, row_of(&x2, SEQ_FOUR, 0));
    *lock(&env.fake.fail_commit) = false;
    round_with(&env, &mut replays).await?;
    assert_eq!(left(&env), 0);
    let entries = recorded(&env);
    assert_eq!(entries.len(), MAX_REPLAYED_ROUNDS as usize + 1);
    let last = entries.last().ok_or("no record")?;
    assert_eq!(last.request_id, "round-3-5");
    [&x1, &x2, &x3].iter().try_for_each(|alert| -> TestResult {
        assert!(param(last, "acknowledged")?.contains(&alert.id));
        Ok(())
    })?;
    Ok(())
}


#[tokio::test]
async fn a_delete_count_above_the_page_is_a_named_error_rolled_back_with_no_record() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.over_ack) = true;
    let mut replays = Replays::default();
    let failed = round_with(&env, &mut replays).await;
    assert!(matches!(failed, Err(RoundError::AckCount { deleted: TWO, expected: 1 })));
    assert_eq!(replays, Replays::default());
    assert!(recorded(&env).is_empty() && lock(&env.fake.runs).is_empty());
    assert_eq!(lock(&env.fake.events).last().copied(), Some("rollback"));
    assert!(failed.err().ok_or("no error")?.to_string().contains("2 rows deleted for a page of 1"));
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
            "crate::run::",
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


#[tokio::test]
async fn a_partial_delete_is_not_a_success_and_keeps_the_replay_count() -> TestResult {
    let env = env()?;
    let e1 = whoami("e1");
    put(&env, vec![row_of(&e1, FIRST_SEQ, 0)]);
    *lock(&env.fake.short_ack) = true;
    let mut replays = Replays::default();
    round_with(&env, &mut replays).await?;
    assert_eq!(
        replays,
        Replays {
            ids: ids_of(&[&e1.id]),
            records: 1
        }
    );
    assert_eq!(left(&env), 1);
    round_with(&env, &mut replays).await?;
    assert_eq!(replays.records, TWO as u32);
    *lock(&env.fake.short_ack) = false;
    round_with(&env, &mut replays).await?;
    assert_eq!((left(&env), replays), (0, Replays::default()));
    log_partial_ack(None, 0, 1);
    Ok(())
}


#[test]
fn a_failure_streak_is_loud_at_each_power_of_two_from_the_second_failure() -> TestResult {
    let loud: Vec<u32> = (0..=SIXTEEN).filter(|failures| is_loud(*failures)).collect();
    assert_eq!(loud, [TWO as u32, FOUR, EIGHT, SIXTEEN]);
    Ok(())
}


const MARKER: &str = "SECRET-MARKER-9f3a";


const MEGABYTE: usize = 1_048_576;


const MANY_ELEMENTS: usize = 5_000;


pub fn trace_of(name: &str, events: Vec<TraceEvent>) -> Trace {
    Trace {
        playbook: name.to_owned(),
        version: 1,
        mode: Mode::Simulate,
        events,
    }
}


pub fn feed_row_of(name: &str, seq: u64) -> FeedRow {
    FeedRow {
        seq,
        age_seconds: 0,
        alert: whoami(name),
    }
}


pub fn marker_events() -> Vec<TraceEvent> {
    let values: ParamMap = [("channel", json!(MARKER)), ("message", json!(MARKER)), ("extra", json!(MARKER))]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    vec![
        TraceEvent::Trigger {
            matched: false,
            mismatches: vec![MARKER.to_owned()],
        },
        TraceEvent::Condition {
            path: "steps.0".to_owned(),
            expression: MARKER.to_owned(),
            outcome: ConditionOutcome::Failed(MARKER.to_owned()),
        },
        TraceEvent::Action {
            path: "steps.1".to_owned(),
            connector: Some("slack".to_owned()),
            action: "notify".to_owned(),
            params: values.clone(),
            verdict: Some(format!("needs-approval alert=true reason={MARKER}")),
        },
        TraceEvent::Rejected {
            path: "steps.2".to_owned(),
            action: "notify".to_owned(),
            reason: MARKER.to_owned(),
        },
        TraceEvent::Approval {
            path: "steps.3".to_owned(),
            params: values,
            granted: false,
        },
        TraceEvent::NotRun {
            path: "steps.4".to_owned(),
            step: "later".to_owned(),
        },
        TraceEvent::UnknownAsset {
            path: "steps.5".to_owned(),
            id: MARKER.to_owned(),
        },
        TraceEvent::Halted { path: "steps.6".to_owned() },
        TraceEvent::Failure {
            path: "steps.7".to_owned(),
            action: "notify".to_owned(),
        },
        TraceEvent::ActionFailed {
            path: "steps.8".to_owned(),
            action: "notify".to_owned(),
            reason: MARKER.to_owned(),
        },
        TraceEvent::Compensation {
            action: "unblock_ip".to_owned(),
            compensates: "block_ip".to_owned(),
        },
        TraceEvent::ErrorHandler,
    ]
}


#[test]
fn no_trace_element_holds_a_reason_a_failure_text_an_asset_id_a_verdict_or_a_value() -> TestResult {
    let env = env()?;
    let events = marker_events();
    let row = row_of_run(&env, &events)?;
    let text = row.trace.to_string();
    assert!(!text.contains(MARKER), "{text}");
    let elements = row.trace.as_array().ok_or("not an array")?;
    let kinds: Vec<&str> = elements
        .iter()
        .filter_map(|element| element.get("kind").and_then(Value::as_str))
        .collect();
    assert_eq!(
        kinds,
        [
            "trigger",
            "condition",
            "action",
            "rejected",
            "approval",
            "not_run",
            "unknown_asset",
            "halted",
            "failure",
            "action_failed",
            "compensation",
            "error_handler"
        ]
    );
    let outcomes: Vec<Option<&str>> = elements.iter().map(|element| element.get("outcome").and_then(Value::as_str)).collect();
    assert_eq!(
        outcomes,
        [
            Some("false"),
            Some("failed"),
            Some("needs_approval"),
            Some("rejected"),
            Some("denied"),
            Some("not_run"),
            Some("unknown_asset"),
            Some("halted"),
            Some("failure"),
            Some("failure"),
            None,
            None
        ]
    );
    let action = elements.get(TWO).ok_or("no action")?;
    assert_eq!(
        action.get("params"),
        Some(&json!({"channel": "string", "message": "string", "extra": "unknown"}))
    );
    assert_eq!(row.outcome, "needs_approval");
    Ok(())
}


pub fn row_of_run(env: &Env, events: &[TraceEvent]) -> Result<RunRow, Box<dyn std::error::Error>> {
    let trace = trace_of("pb", events.to_vec());
    Ok(run_row_of("acme", &feed_row_of("e1", 1), &trace, "pb.yaml", &env.live.bundle.catalogue))
}


#[test]
fn an_allowed_verdict_and_a_run_without_failures_are_completed() -> TestResult {
    let env = env()?;
    let action = |verdict: Option<&str>| TraceEvent::Action {
        path: "steps.0".to_owned(),
        connector: None,
        action: "x".to_owned(),
        params: ParamMap::new(),
        verdict: verdict.map(str::to_owned),
    };
    let granted = TraceEvent::Approval {
        path: "steps.1".to_owned(),
        params: ParamMap::new(),
        granted: true,
    };
    let passed = TraceEvent::Condition {
        path: "steps.2".to_owned(),
        expression: "x".to_owned(),
        outcome: ConditionOutcome::True,
    };
    let skipped = TraceEvent::Condition {
        path: "steps.3".to_owned(),
        expression: "x".to_owned(),
        outcome: ConditionOutcome::False,
    };
    let row = row_of_run(
        &env,
        &[
            action(None),
            action(Some("allowed")),
            action(Some("allowed only by override of x")),
            granted,
            passed,
            skipped,
        ],
    )?;
    assert_eq!((row.outcome, row.steps), ("completed", THREE));
    let odd = row_of_run(&env, &[action(Some("unreadable"))])?;
    assert_eq!(odd.outcome, "needs_approval");
    let halted = row_of_run(&env, &[TraceEvent::Halted { path: "p".to_owned() }])?;
    assert_eq!((halted.outcome, halted.steps), ("halted", 0));
    let failed = row_of_run(
        &env,
        &[TraceEvent::Condition {
            path: "p".to_owned(),
            expression: "x".to_owned(),
            outcome: ConditionOutcome::Failed("x".to_owned()),
        }],
    )?;
    assert_eq!(failed.outcome, "halted");
    Ok(())
}


#[test]
fn operator_text_is_cut_with_a_marker_and_controls_are_replaced() -> TestResult {
    let long = "n".repeat(MEGABYTE);
    let cut = cut_text(&long);
    assert_eq!(cut.len(), MAX_NAME_BYTES);
    assert!(cut.ends_with(CUT_MARKER));
    let wide = cut_text(&"é".repeat(MAX_NAME_BYTES));
    assert!(wide.len() <= MAX_NAME_BYTES && wide.ends_with(CUT_MARKER));
    assert_eq!(cut_text("short"), "short");
    assert_eq!(cut_text("a\u{0}b\u{1b}c"), "a\u{fffd}b\u{fffd}c");
    let env = env()?;
    let row = row_of_run(
        &env,
        &[TraceEvent::NotRun {
            path: "steps.0".to_owned(),
            step: long.clone(),
        }],
    )?;
    let step = row
        .trace
        .get(0)
        .and_then(|element| element.get("step"))
        .and_then(Value::as_str)
        .ok_or("no step")?;
    assert!(step.len() <= MAX_NAME_BYTES && step.ends_with(CUT_MARKER));
    let named = trace_of(&long, Vec::new());
    let named_row = run_row_of("acme", &feed_row_of("e1", 1), &named, "pb.yaml", &env.live.bundle.catalogue);
    assert!(named_row.playbook.ends_with(CUT_MARKER) && named_row.playbook.len() <= MAX_NAME_BYTES);
    Ok(())
}


#[test]
fn a_long_trace_stops_before_the_element_that_passes_the_bound_and_counts_the_rest() -> TestResult {
    let elements: Vec<Value> = (0..MANY_ELEMENTS)
        .map(|index| json!({"kind": "action", "path": format!("steps.{index}")}))
        .collect();
    let bounded = bounded_trace(&elements);
    let text = bounded.to_string();
    assert!(text.len() <= MAX_TRACE_BYTES, "{}", text.len());
    assert_eq!(serde_json::from_str::<Value>(&text)?, bounded);
    let kept = bounded.as_array().ok_or("not an array")?;
    let closing = kept.last().ok_or("empty")?;
    assert_eq!(closing.get("kind"), Some(&json!("omitted")));
    assert_eq!(closing.get("events"), Some(&json!(MANY_ELEMENTS - (kept.len() - 1))));
    let few: Vec<Value> = elements.iter().take(THREE).cloned().collect();
    let small = bounded_trace(&few);
    assert_eq!(small.as_array().map(Vec::len), Some(THREE));
    assert_eq!(bounded_trace(&[]), json!([]));
    Ok(())
}


#[test]
fn a_run_id_depends_on_each_field_and_the_fields_cannot_run_together() -> TestResult {
    let base = playbook_run_id("acme", "a1", 1, "pb.yaml");
    assert_eq!(base.len(), ID_HEX);
    assert!(is_alert_id(&base));
    assert_eq!(base, playbook_run_id("acme", "a1", 1, "pb.yaml"));
    let others = [
        playbook_run_id("acm", "a1", 1, "pb.yaml"),
        playbook_run_id("acme", "a2", 1, "pb.yaml"),
        playbook_run_id("acme", "a1", TWO as u64, "pb.yaml"),
        playbook_run_id("acme", "a1", 1, "other.yaml"),
        playbook_run_id("acmea", "1", 1, "pb.yaml"),
        playbook_run_id("acme", "a11", 0, "pb.yaml"),
    ];
    assert!(others.iter().all(|other| *other != base));
    let unique: BTreeSet<&String> = others.iter().collect();
    assert_eq!(unique.len(), others.len());
    Ok(())
}


#[test]
fn the_cap_leaves_room_for_two_full_rounds_and_the_statements_name_the_tenant_and_the_order() -> TestResult {
    assert!(std::hint::black_box(MAX_PLAYBOOK_RUNS) >= MAX_PAGE_SIZE * response_playbooks::service::MAX_MATCHES * TWO);
    [LOCK_SQL, INSERT_SQL, COUNT_SQL, PRUNE_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("$1"), "{sql}"));
    assert!(COUNT_SQL.contains("WHERE tenant = $1"));
    assert!(PRUNE_SQL.contains("tenant = $1::text ORDER BY run_seq LIMIT $2"));
    assert!(INSERT_SQL.contains("ON CONFLICT (tenant, id) DO NOTHING"));
    assert!(LOCK_SQL.contains("hashtextextended('playbook_runs/'") && LOCK_SQL.contains("0::pg_catalog.int8"));
    assert_eq!(MIGRATION_NAMESPACE, "playbooks");
    assert!(MIGRATIONS.iter().all(|migration| migration.sql.contains("PRIMARY KEY (tenant, id)")));
    Ok(())
}


#[test]
fn no_report_gives_no_run_and_a_position_outside_the_page_gives_none() -> TestResult {
    let env = env()?;
    let catalogue = &env.live.bundle.catalogue;
    assert!(run_rows("acme", &[], None, catalogue).is_empty());
    let report = DryRunReport {
        tenant_refused: false,
        alerts: vec![run_of(THREE, None, &["pb".to_owned()])],
        alerts_not_run: 0,
        trace_events: 0,
    };
    assert!(run_rows("acme", &[], Some(&report), catalogue).is_empty());
    let row = feed_row_of("e1", 1);
    let inside = DryRunReport {
        alerts: vec![run_of(0, None, &["pb".to_owned()])],
        ..report
    };
    let rows = run_rows("acme", &[&row], Some(&inside), catalogue);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows.first().map(|found| found.id.clone()),
        Some(playbook_run_id("acme", &row.alert.id, 1, "pb.yaml"))
    );
    Ok(())
}


#[tokio::test]
async fn two_playbooks_with_one_name_matching_one_alert_give_two_rows() -> TestResult {
    let env = env_with_two_playbooks()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!((outcome.matches, outcome.runs_written, outcome.runs_replayed), (TWO, TWO, 0));
    assert_eq!(lock(&env.fake.runs).len(), TWO);
    let document: Vec<Value> = serde_json::from_str(lock(&env.fake.documents).first().ok_or("no document")?)?;
    let names: BTreeSet<&str> = document.iter().filter_map(|run| run.get("playbook").and_then(Value::as_str)).collect();
    assert_eq!(names, BTreeSet::from(["Notify on store alert"]));
    Ok(())
}


#[tokio::test]
async fn a_replayed_page_counts_its_conflicts_in_the_record() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.short_ack) = true;
    let mut replays = Replays::default();
    let first = round_with(&env, &mut replays).await?;
    let again = round_with(&env, &mut replays).await?;
    assert_eq!((first.runs_written, first.runs_replayed), (1, 0));
    assert_eq!((again.runs_written, again.runs_replayed), (0, 1));
    assert_eq!(lock(&env.fake.runs).len(), 1);
    let entries = recorded(&env);
    assert_eq!(param(entries.last().ok_or("no record")?, "runs_replayed")?, "1");
    Ok(())
}


#[tokio::test]
async fn a_full_store_deletes_the_oldest_runs_of_the_tenant_and_the_record_says_so() -> TestResult {
    let env = env()?;
    *lock(&env.fake.runs) = (0..MAX_PLAYBOOK_RUNS).map(|index| (format!("old-{index}"), index as u64 + 1)).collect();
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    let outcome = round(&env, &mut Vec::new()).await?;
    assert_eq!((outcome.runs_written, outcome.runs_pruned), (1, 1));
    assert!(outcome.bounds.contains(&"max_playbook_runs"));
    {
        let runs = lock(&env.fake.runs);
        assert_eq!(runs.len(), MAX_PLAYBOOK_RUNS);
        assert!(!runs.contains_key("old-0") && runs.contains_key("old-1"));
    }
    assert_eq!(
        lock(&env.fake.events).as_slice(),
        ["feed", "begin", "lock", "insert", "count", "prune", "ack", "audit", "commit"]
    );
    let entries = recorded(&env);
    let entry = entries.first().ok_or("no record")?;
    assert_eq!(param(entry, "runs_pruned")?, "1");
    assert!(param(entry, "bounds")?.contains("max_playbook_runs"));
    log_pruned(1);
    Ok(())
}


#[tokio::test]
async fn every_statement_runs_under_the_service_tenant_and_no_alert_text_names_another() -> TestResult {
    let env = env()?;
    let hostile = alert("rule", "e1", Severity::High, &json!({"process": {"name": "whoami"}, "tenant": "evil"}));
    put(&env, vec![row_of(&hostile, FIRST_SEQ, 0)]);
    round(&env, &mut Vec::new()).await?;
    let tenants = lock(&env.fake.tenants).clone();
    assert!(tenants.len() > THREE && tenants.iter().all(|tenant| tenant == "acme"), "{tenants:?}");
    let documents = lock(&env.fake.documents).clone();
    assert!(documents
        .iter()
        .all(|document| !document.contains("evil") && !document.contains("tenant")));
    assert_eq!(lock(&env.fake.created).clone(), ["0"]);
    Ok(())
}


#[tokio::test]
async fn a_failed_ack_insert_or_count_rolls_everything_back_with_no_record() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_ack) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Store(_))));
    *lock(&env.fake.fail_ack) = false;
    *lock(&env.fake.fail_insert) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Pg(_))));
    *lock(&env.fake.fail_insert) = false;
    *lock(&env.fake.bad_count) = true;
    let failed = round(&env, &mut Vec::new()).await;
    assert!(matches!(failed, Err(RoundError::Answer { .. })));
    assert!(failed.err().ok_or("no error")?.to_string().contains("gave no count"));
    assert!(recorded(&env).is_empty() && lock(&env.fake.runs).is_empty());
    assert_eq!(left(&env), 1);
    assert_eq!(lock(&env.fake.events).iter().filter(|event| **event == "rollback").count(), THREE);
    *lock(&env.fake.bad_count) = false;
    round(&env, &mut Vec::new()).await?;
    assert_eq!((left(&env), lock(&env.fake.runs).len(), recorded(&env).len()), (0, 1, 1));
    Ok(())
}


#[tokio::test]
async fn a_refused_begin_runs_no_statement_and_a_failed_rollback_keeps_the_first_error() -> TestResult {
    let env = env()?;
    put(&env, vec![row_of(&whoami("e1"), FIRST_SEQ, 0)]);
    *lock(&env.fake.fail_begin) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Pg(_))));
    assert_eq!(lock(&env.fake.events).as_slice(), ["feed", "begin"]);
    *lock(&env.fake.fail_begin) = false;
    *lock(&env.fake.fail_audit) = true;
    *lock(&env.fake.fail_rollback) = true;
    assert!(matches!(round(&env, &mut Vec::new()).await, Err(RoundError::Audit(_))));
    assert_eq!(left(&env), 1);
    Ok(())
}


#[test]
fn the_redacted_trace_holds_no_marker_and_names_parameters_and_kinds() -> TestResult {
    let env = env()?;
    let trace = trace_of("pb", marker_events());
    let text = render_trace_redacted(&env.live.bundle.catalogue, &trace);
    assert!(!text.contains(MARKER), "{text}");
    assert!(
        text.starts_with("playbook pb v1 mode=simulate\n") && text.contains("\"kind\":\"action\""),
        "{text}"
    );
    Ok(())
}


#[tokio::test]
async fn a_round_writes_no_alert_value_to_its_trace_output() -> TestResult {
    let env = env()?;
    let mut marked = whoami("e1");
    marked.rule_title = format!("title {MARKER}");
    marked.host_name = Some(format!("host-{MARKER}"));
    put(&env, vec![row_of(&marked, FIRST_SEQ, 0)]);
    let mut trace = Vec::new();
    round(&env, &mut trace).await?;
    let text = String::from_utf8(trace)?;
    assert!(text.contains("\"kind\":\"action\"") && text.contains("\"channel\":"), "{text}");
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}


#[test]
fn the_redacted_writer_reports_a_failing_output() -> TestResult {
    let env = env()?;
    let report = DryRunReport {
        tenant_refused: false,
        alerts_not_run: 0,
        trace_events: 0,
        alerts: Vec::new(),
    };
    assert!(write_dry_run_redacted(&mut FailingWriter, &report, &env.live.bundle.catalogue).is_err());
    Ok(())
}

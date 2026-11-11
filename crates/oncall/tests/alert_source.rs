#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use alerts::model::{Alert as SourceAlert, Severity, Summary};
use alerts::store::GET_SQL;
use alerts::types::RowFuture;
use chrono::{DateTime, Utc};
use core_pg::error::PgError;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use oncall::alert::{Cell, Param, Statement};
use oncall::alert_source::{
    alert_notice, clean_text, count_answer, map_severity, parse_source_settings, poll_all, poll_tenant, purge_unpolled, purged_counts, record_alert,
    run_rounds, skip_backlog, source_details, take_lease, validate_source_settings, Round, RoundHooks, SourceSettings, TenantCounts, DETAILS_SQL,
    FINGERPRINT_PREFIX, LEASE_SQL, PURGE_SQL, RECORD_SQL, SKIP_SQL, UNRECORDED_SQL,
};
use oncall::error::{OncallError, SourceError, StoreError};
use oncall::limits::{MAX_PURGE_PER_ROUND, MAX_SKIP_PER_POLL, MAX_SOURCE_TEXT_CHARS};
use oncall::model::{Channel, ChannelKind};
use oncall::render::render;
use oncall::store::MIGRATIONS;
use oncall::types::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::future::{ready, Ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Duration;
use types::TestResult;


const P_SOURCE_ID: usize = 6;


const P_SEVERITY: usize = 2;


const P_TITLE: usize = 3;


const P_HOST: usize = 4;


const P_USER: usize = 5;


const BASE_CREATED: u64 = 1_000;


const FLOOD: u64 = 10;


const SUMMARY_BYTES: u64 = 2;


const TWICE: usize = 2;


const CAP: usize = 2;


const THREE: usize = 3;


const ROUNDS: usize = 3;


const FAIL_ON_SECOND_RECORD: usize = 2;


const VALID_SETTINGS: &str = "tenants: [acme, other]\nmax_per_poll: 2\ninterval_seconds: 30\nseverity_map:\n  informational: info\n  low: info\n  medium: ticket\n  high: page\n  critical: page-now\n";


#[derive(Default)]
struct SourceDb {
    alerts: Mutex<Vec<(String, SourceAlert)>>,
    fail: Mutex<bool>,
    reads: Mutex<Vec<String>>,
    gone: Mutex<Vec<(String, String)>>,
    bad_count: Mutex<Option<Vec<Vec<String>>>>,
    purge_scopes: Mutex<Vec<String>>,
    queued: Mutex<BTreeMap<String, i64>>,
}


#[derive(Default)]
struct Db {
    alerts: Vec<(String, i64, String)>,
    details: Vec<(String, i64, Vec<Param>)>,
    calls: Vec<&'static str>,
    consumed: Vec<(String, String)>,
    fail_on_call: Option<usize>,
    lease: Option<String>,
    lease_expired: bool,
    lease_calls: usize,
    steal_on_lease: Option<usize>,
    record_rows: Option<Vec<Row>>,
    details_rows: Option<Vec<Row>>,
}


fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


const THIRD_MIGRATION: usize = 2;


const LOAD_DAYS: i64 = 30_000;


fn load_time() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + chrono::Duration::days(LOAD_DAYS)
}


fn queued_micros(db: &SourceDb, alert: &SourceAlert) -> i64 {
    lock(&db.queued)
        .get(&alert.id)
        .copied()
        .unwrap_or_else(|| i64::try_from(alert.created_micros).unwrap_or(i64::MAX))
}


fn requeue(db: &SourceDb, tenant: &str, name: &str, micros: i64) {
    lock(&db.queued).insert(alert_id(tenant, "rule", &[name.to_owned()]), micros);
}


fn poll_time() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH
}


fn quiet(_round: &Round) {}


fn instant(_interval: Duration) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(ready(()))
}


fn settings() -> Result<SourceSettings, OncallError> {
    parse_source_settings(VALID_SETTINGS, "source.yaml", load_time())
}


fn source_alert(tenant: &str, name: &str, created: u64, title: &str) -> SourceAlert {
    let event_ids = vec![name.to_owned()];
    SourceAlert {
        id: alert_id(tenant, "rule", &event_ids),
        tenant: tenant.to_owned(),
        rule_id: "rule".to_owned(),
        rule_title: title.to_owned(),
        severity: Severity::High,
        event_time: "2026-11-10T00:00:00Z".to_owned(),
        created_micros: created,
        host_name: Some("web-1".to_owned()),
        user_name: None,
        event_ids,
        summary: Summary {
            text: "{}".to_owned(),
            truncated: false,
            original_bytes: SUMMARY_BYTES,
        },
    }
}


fn source_row(alert: &SourceAlert) -> Vec<String> {
    vec![
        alert.id.clone(),
        alert.rule_id.clone(),
        alert.rule_title.clone(),
        alert.severity.to_string(),
        alert.event_time.clone(),
        alert.created_micros.to_string(),
        alert.host_name.as_deref().unwrap_or("").to_owned(),
        alert.user_name.as_deref().unwrap_or("").to_owned(),
        "[\"e\"]".to_owned(),
        alert.summary.text.clone(),
        "false".to_owned(),
        "2".to_owned(),
    ]
}


fn malformed() -> PgError {
    PgError::Server {
        code: "22P02".to_owned(),
        class: "data",
    }
}


fn visible(db: &SourceDb, recorded: &Arc<Mutex<Db>>, tenant: &str) -> Vec<SourceAlert> {
    let consumed: Vec<String> = lock(recorded)
        .consumed
        .iter()
        .filter(|(owner, _id)| owner == tenant)
        .map(|(_owner, id)| id.clone())
        .collect();
    let gone = lock(&db.gone).clone();
    lock(&db.alerts)
        .iter()
        .filter(|(owner, _alert)| owner == tenant)
        .map(|(_owner, alert)| alert.clone())
        .filter(|alert| !consumed.contains(&alert.id) && !gone.contains(&(tenant.to_owned(), alert.id.clone())))
        .collect()
}


fn limit_of(params: &[String]) -> Result<usize, PgError> {
    params.last().ok_or_else(malformed)?.parse::<usize>().map_err(|_bad| malformed())
}


fn purge_handle(db: &SourceDb, recorded: &Arc<Mutex<Db>>, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    lock(&db.purge_scopes).push(tenant_of(scope).to_owned());
    let polled: Vec<String> = serde_json::from_str(params.first().ok_or_else(malformed)?).map_err(|_bad| malformed())?;
    let owners: BTreeSet<String> = lock(&db.alerts).iter().map(|(owner, _alert)| owner.clone()).collect();
    let victims: Vec<(String, String)> = owners
        .iter()
        .filter(|owner| !polled.contains(owner) && polled.iter().any(|name| name == tenant_of(scope)))
        .flat_map(|owner| visible(db, recorded, owner).into_iter().map(|alert| (owner.clone(), alert.id)))
        .take(limit_of(params)?)
        .collect();
    lock(&db.gone).extend(victims.iter().cloned());
    let per_tenant: BTreeMap<&String, usize> = victims.iter().fold(BTreeMap::new(), |mut counts, (owner, _id)| {
        *counts.entry(owner).or_insert(0) += 1;
        counts
    });
    Ok(per_tenant
        .into_iter()
        .map(|(owner, count)| vec![owner.clone(), count.to_string()])
        .collect())
}


fn skip_handle(db: &SourceDb, recorded: &Arc<Mutex<Db>>, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let added = DateTime::parse_from_rfc3339(params.first().ok_or_else(malformed)?)
        .map_err(|_bad| malformed())?
        .timestamp_micros();
    let victims: Vec<(String, String)> = visible(db, recorded, tenant_of(scope))
        .into_iter()
        .filter(|alert| queued_micros(db, alert) < added)
        .take(limit_of(params)?)
        .map(|alert| (tenant_of(scope).to_owned(), alert.id))
        .collect();
    lock(&db.gone).extend(victims.iter().cloned());
    Ok(vec![vec![victims.len().to_string()]])
}


fn source_handle(
    db: &SourceDb,
    recorded: &Arc<Mutex<Db>>,
    scope: &TenantScope,
    sql: &'static str,
    params: &[String],
) -> Result<Vec<Vec<String>>, PgError> {
    if *lock(&db.fail) {
        Err(PgError::InvalidTenant)
    } else if let Some(rows) = lock(&db.bad_count).clone().filter(|_rows| sql != UNRECORDED_SQL) {
        Ok(rows)
    } else if sql == PURGE_SQL {
        purge_handle(db, recorded, scope, params)
    } else if sql == SKIP_SQL {
        skip_handle(db, recorded, scope, params)
    } else {
        assert_eq!(sql, UNRECORDED_SQL);
        lock(&db.reads).push(tenant_of(scope).to_owned());
        let limit = params.first().ok_or_else(malformed)?.parse::<usize>().map_err(|_bad| malformed())?;
        let since = DateTime::parse_from_rfc3339(params.get(1).ok_or_else(malformed)?)
            .map_err(|_bad| malformed())?
            .timestamp_micros();
        Ok(visible(db, recorded, tenant_of(scope))
            .iter()
            .filter(|alert| queued_micros(db, alert) >= since)
            .take(limit)
            .map(source_row)
            .collect())
    }
}


fn source_exec<'a>(db: &'a SourceDb, recorded: &'a Arc<Mutex<Db>>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(source_handle(db, recorded, &scope, sql, &params))) }
}


fn text(params: &[Param], index: usize) -> String {
    match params.get(index) {
        Some(Param::Text(value)) => value.clone(),
        _ => String::new(),
    }
}


fn handle(db: &mut Db, tenant: &str, statement: &Statement) -> Result<Vec<Row>, StoreError> {
    db.calls.push(statement.sql);
    if db.fail_on_call == Some(db.calls.len()) {
        Err(StoreError::Conflict)
    } else if statement.sql == LEASE_SQL {
        let holder = text(&statement.params, 0);
        db.lease_calls += 1;
        if db.steal_on_lease == Some(db.lease_calls) {
            db.lease = Some("poller-thief".to_owned());
        }
        let free = db.lease.as_ref().is_none_or(|current| *current == holder) || db.lease_expired;
        db.lease_expired = false;
        Ok(if free {
            db.lease = Some(holder);
            vec![vec![Cell::Bool(true)]]
        } else {
            Vec::new()
        })
    } else if statement.sql == RECORD_SQL {
        let params = &statement.params;
        let fingerprint = text(params, 0);
        let source_id = text(params, P_SOURCE_ID);
        let recorded = db
            .details
            .iter()
            .any(|(owner, _id, detail)| owner == tenant && text(detail, P_SOURCE_ID) == source_id);
        let known = recorded || db.alerts.iter().any(|(owner, _id, key)| owner == tenant && *key == fingerprint);
        let id = i64::try_from(db.alerts.len()).map_err(|_bad| StoreError::NotFound)? + 1;
        db.consumed.push((tenant.to_owned(), source_id));
        if !known {
            db.alerts.push((tenant.to_owned(), id, fingerprint));
            db.details.push((tenant.to_owned(), id, params.clone()));
        }
        Ok(db
            .record_rows
            .clone()
            .unwrap_or_else(|| vec![vec![Cell::Int(i64::from(!known)), Cell::Int(i64::from(recorded))]]))
    } else if statement.sql == DETAILS_SQL {
        let wanted = match statement.params.first() {
            Some(Param::Int(value)) => Ok(*value),
            _ => Err(StoreError::NotFound),
        }?;
        Ok(db.details_rows.clone().unwrap_or_else(|| {
            db.details
                .iter()
                .filter(|(owner, id, _params)| owner == tenant && *id == wanted)
                .map(|(_owner, _id, params)| {
                    let optional = |index: usize| match params.get(index) {
                        Some(Param::OptText(Some(value))) => value.clone(),
                        _ => String::new(),
                    };
                    vec![
                        Cell::Text(text(params, P_SEVERITY)),
                        Cell::Text(text(params, P_TITLE)),
                        Cell::Text(optional(P_HOST)),
                        Cell::Text(optional(P_USER)),
                    ]
                })
                .collect()
        }))
    } else {
        Err(StoreError::NotFound)
    }
}


fn exec_for(db: &Arc<Mutex<Db>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Arc::clone(db);
    move |scope, statement| {
        let result = match shared.try_lock() {
            Ok(mut guard) => handle(&mut guard, tenant_of(scope), &statement),
            Err(TryLockError::Poisoned(_)) | Err(TryLockError::WouldBlock) => Err(StoreError::NotFound),
        };
        ready(result)
    }
}


fn new_db() -> Arc<Mutex<Db>> {
    Arc::new(Mutex::new(Db::default()))
}


fn count_for(db: &Arc<Mutex<Db>>, tenant: &str) -> usize {
    lock(db).alerts.iter().filter(|(owner, _id, _key)| owner == tenant).count()
}


fn add(source: &SourceDb, tenant: &str, name: &str, created: u64, title: &str) {
    lock(&source.alerts).push((tenant.to_owned(), source_alert(tenant, name, created, title)));
}


fn opened(round: &Round, tenant: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let found = round.outcomes.iter().find(|(name, _result)| name == tenant).ok_or("tenant missing")?;
    match &found.1 {
        Ok(counts) => Ok(counts.opened),
        Err(error) => Err(error.to_string().into()),
    }
}


#[tokio::test]
async fn new_alerts_are_recorded_once_and_a_restart_continues_from_the_cursor() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..THREE).for_each(|index| add(&source, "acme", &format!("e{index}"), BASE_CREATED + index as u64, "disk full"));
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let wide = SourceSettings {
        max_per_poll: THREE + 1,
        ..settings.clone()
    };
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?.opened, THREE);
    assert_eq!(count_for(&db, "acme"), THREE);
    let records_before = lock(&db).calls.iter().filter(|sql| **sql == RECORD_SQL).count();
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?.opened, 0);
    assert_eq!(lock(&db).calls.iter().filter(|sql| **sql == RECORD_SQL).count(), records_before);
    add(&source, "acme", "late", BASE_CREATED + FLOOD, "late one");
    let mut restarted = exec_for(&db);
    assert_eq!(poll_tenant(&alerts_exec, &mut restarted, &wide, "acme", poll_time()).await?.opened, 1);
    assert_eq!(count_for(&db, "acme"), THREE + 1);
    Ok(())
}


#[tokio::test]
async fn a_redelivered_alert_is_a_no_op() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "acme", "e1", BASE_CREATED, "t");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, 1);
    let scope = tenant_scope("acme")?;
    let again = source_alert("acme", "e1", BASE_CREATED, "t");
    let redelivered = TenantCounts {
        already: 1,
        ..TenantCounts::default()
    };
    assert_eq!(record_alert(&mut exec, &scope, &settings, &again, poll_time()).await?, redelivered);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, 0);
    assert_eq!(count_for(&db, "acme"), 1);
    assert_eq!(lock(&db).details.len(), 1);
    Ok(())
}


#[tokio::test]
async fn one_poll_records_at_most_the_cap() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..CAP + THREE).for_each(|index| add(&source, "acme", &format!("e{index}"), BASE_CREATED + index as u64, "t"));
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let first = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened;
    let second = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened;
    let third = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened;
    let fourth = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened;
    assert_eq!((first, second, third, fourth), (CAP, CAP, 1, 0));
    Ok(())
}


#[tokio::test]
async fn failures_leave_the_cursor_and_the_next_poll_resumes() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "acme", "e1", BASE_CREATED, "t");
    add(&source, "acme", "e2", BASE_CREATED + 1, "t");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    *lock(&source.fail) = true;
    assert!(matches!(
        poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await,
        Err(SourceError::Alerts(_))
    ));
    assert_eq!(count_for(&db, "acme"), 0);
    *lock(&source.fail) = false;
    lock(&db).calls.clear();
    lock(&db).fail_on_call = Some(1);
    assert!(matches!(
        poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await,
        Err(SourceError::Store(_))
    ));
    assert_eq!(count_for(&db, "acme"), 0);
    lock(&db).calls.clear();
    lock(&db).fail_on_call = Some(FAIL_ON_SECOND_RECORD);
    assert!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await.is_err());
    assert_eq!(count_for(&db, "acme"), 1);
    lock(&db).fail_on_call = None;
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, 1);
    assert_eq!(count_for(&db, "acme"), CAP);
    Ok(())
}


#[tokio::test]
async fn an_alert_of_another_tenant_never_becomes_ours_and_a_flood_does_not_starve() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..FLOOD).for_each(|index| add(&source, "acme", &format!("e{index}"), BASE_CREATED + index, "flood"));
    add(&source, "other", "x", BASE_CREATED, "theirs");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert_eq!(opened(&outcomes, "acme")?, CAP);
    assert_eq!(opened(&outcomes, "other")?, 1);
    assert_eq!(count_for(&db, "other"), 1);
    let foreign_id = alert_id("other", "rule", &["x".to_owned()]);
    assert!(lock(&db)
        .alerts
        .iter()
        .filter(|(owner, _id, _key)| owner == "acme")
        .all(|(_o, _i, key)| *key != format!("{FINGERPRINT_PREFIX}{foreign_id}")));
    assert!(lock(&source.reads).iter().all(|tenant| tenant == "acme" || tenant == "other"));
    let only_acme = SourceSettings {
        tenants: vec!["acme".to_owned()],
        ..settings
    };
    let before = count_for(&db, "other");
    poll_all(&alerts_exec, &mut exec, &only_acme, "poller-a", poll_time).await;
    assert_eq!(count_for(&db, "other"), before);
    Ok(())
}


#[tokio::test]
async fn a_failing_tenant_does_not_stop_the_others() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = SourceSettings {
        tenants: vec!["acme".to_owned(), "bad name".to_owned()],
        ..settings()?
    };
    add(&source, "acme", "e1", BASE_CREATED, "t");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert!(matches!(
        outcomes.outcomes.get(1).map(|(_n, result)| result),
        Some(Err(SourceError::Tenant(_)))
    ));
    assert_eq!(opened(&outcomes, "acme")?, 1);
    Ok(())
}


#[tokio::test]
async fn rounds_poll_report_and_wait_the_given_number_of_times() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "acme", "e1", BASE_CREATED, "t");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let hooks = RoundHooks {
        now: poll_time,
        wait: instant,
        report: quiet,
        audit_purge: &|_counts| (),
    };
    run_rounds(ROUNDS, &alerts_exec, &mut exec, &settings, "poller-a", &hooks).await;
    assert_eq!(lock(&source.reads).len(), ROUNDS * settings.tenants.len());
    assert_eq!(count_for(&db, "acme"), 1);
    Ok(())
}


#[tokio::test]
async fn alert_text_is_cleaned_stored_and_escaped_when_rendered() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let hostile = format!(
        "<!channel> <https://evil|x>\r\nforged\u{2028}line\u{0}{}",
        "z".repeat(MAX_SOURCE_TEXT_CHARS * TWICE)
    );
    add(&source, "acme", "e1", BASE_CREATED, &hostile);
    lock(&source.alerts)
        .iter_mut()
        .for_each(|(_owner, alert)| alert.user_name = Some("root\n".to_owned()));
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?;
    let scope = tenant_scope("acme")?;
    let details = source_details(&mut exec, &scope, 1).await?.ok_or("no details")?;
    assert_eq!(details.severity, "page");
    assert_eq!(details.host.as_deref(), Some("web-1"));
    assert_eq!(details.user.as_deref(), Some("root "));
    assert!(details.title.contains("[cut, ") && details.title.chars().count() < MAX_SOURCE_TEXT_CHARS + MAX_SOURCE_TEXT_CHARS / TWICE);
    assert!(!details.title.chars().any(|character| character.is_control() || character == '\u{2028}'));
    let notice = alert_notice("acme", &details);
    let slack = Channel {
        name: "ops".to_owned(),
        tenant: "acme".to_owned(),
        kind: ChannelKind::Slack,
        target: "https://hooks.example.com/x".to_owned(),
        secret_file: None,
    };
    let message = render(&notice, &slack)?;
    assert!(message.subject.contains("&lt;!channel&gt;"));
    assert!(!message.subject.contains("<!channel>") && !message.subject.contains("<https"));
    assert!(message.body.contains("label severity: page") && message.body.contains("label host: web-1"));
    assert!(message.body.contains("label user: root"));
    assert!(source_details(&mut exec, &scope, FLOOD as i64 * FLOOD as i64).await?.is_none());
    Ok(())
}


#[tokio::test]
async fn malformed_store_answers_are_refused() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let scope = tenant_scope("acme")?;
    let mut exec = exec_for(&db);
    let mut hostile = source_alert("acme", "e1", BASE_CREATED, "t");
    hostile.id = "bad\nid".to_owned();
    assert!(matches!(
        record_alert(&mut exec, &scope, &settings, &hostile, poll_time()).await,
        Err(SourceError::Store(StoreError::InvalidFingerprint { .. }))
    ));
    let unmapped = SourceSettings {
        severity_map: BTreeMap::new(),
        ..settings.clone()
    };
    let fine = source_alert("acme", "e3", BASE_CREATED, "t");
    assert!(matches!(
        record_alert(&mut exec, &scope, &unmapped, &fine, poll_time()).await,
        Err(SourceError::Unmapped { .. })
    ));
    assert!(map_severity(&settings, Severity::Low).is_ok());
    lock(&db).record_rows = Some(Vec::new());
    assert!(matches!(
        record_alert(&mut exec, &scope, &settings, &fine, poll_time()).await,
        Err(SourceError::Store(StoreError::NotFound))
    ));
    assert!(matches!(
        poll_tenant(&source_exec(&source, &db), &mut exec, &settings, "bad name", poll_time()).await,
        Err(SourceError::Tenant(_))
    ));
    lock(&db).details_rows = Some(vec![vec![Cell::Bool(true)]]);
    assert!(source_details(&mut exec, &scope, 1).await.is_err());
    Ok(())
}


#[test]
fn the_settings_table_is_validated() -> TestResult {
    let valid = settings()?;
    assert_eq!(map_severity(&valid, Severity::Critical)?, "page-now");
    let bad = |edit: &dyn Fn(&mut SourceSettings)| -> Result<OncallError, Box<dyn std::error::Error>> {
        let mut copy = valid.clone();
        edit(&mut copy);
        validate_source_settings(&copy, load_time()).err().ok_or_else(|| "accepted".into())
    };
    bad(&|edited| {
        edited.severity_map.remove("low");
    })?;
    bad(&|edited| {
        edited.severity_map.remove("low");
        edited.severity_map.insert("urgent".to_owned(), "x".to_owned());
    })?;
    bad(&|edited| {
        edited.severity_map.insert("low".to_owned(), String::new());
    })?;
    bad(&|edited| {
        edited.severity_map.insert("low".to_owned(), "a\nb".to_owned());
    })?;
    bad(&|edited| edited.tenants.clear())?;
    bad(&|edited| edited.tenants.push("acme".to_owned()))?;
    bad(&|edited| edited.tenants.push("bad name".to_owned()))?;
    bad(&|edited| edited.max_per_poll = 0)?;
    bad(&|edited| edited.max_per_poll = alerts::store::MAX_PAGE_SIZE + 1)?;
    bad(&|edited| edited.interval_seconds = 0)?;
    bad(&|edited| {
        edited.added_at.insert("stranger".to_owned(), DateTime::<Utc>::UNIX_EPOCH);
    })?;
    let dated = parse_source_settings(
        &format!("{VALID_SETTINGS}added_at:\n  other: 2026-11-10T00:00:00Z\n"),
        "s.yaml",
        load_time(),
    )?;
    assert_eq!(dated.added_at.len(), 1);
    assert!(parse_source_settings(&format!("{VALID_SETTINGS}extra: 1\n"), "s.yaml", load_time()).is_err());
    assert_eq!(clean_text("a\u{85}b\u{2029}c"), "a b c");
    let long = "z".repeat(MAX_SOURCE_TEXT_CHARS + THREE);
    assert_eq!(
        clean_text(&long),
        format!("{}[cut, {} chars]", "z".repeat(MAX_SOURCE_TEXT_CHARS), MAX_SOURCE_TEXT_CHARS + THREE)
    );
    assert_eq!(clean_text(&"z".repeat(MAX_SOURCE_TEXT_CHARS)).chars().count(), MAX_SOURCE_TEXT_CHARS);
    assert_eq!(clean_text("x\u{202E}y\u{202A}\u{2066}z\u{2069}"), "x y  z ");
    assert_eq!(clean_text("\u{2029}\u{202F}\u{2065}\u{206A}"), " \u{202F}\u{2065}\u{206A}");
    assert_eq!(
        clean_text("a\u{200E}b\u{200F}c\u{061C}d\u{200B}e\u{200C}f\u{200D}g\u{FEFF}h"),
        "a b c d e f g h"
    );
    assert_eq!(
        clean_text("\u{200A}\u{2010}\u{0600}\u{FEFE}\u{FF00}"),
        "\u{200A}\u{2010}\u{0600}\u{FEFE}\u{FF00}"
    );
    Ok(())
}


#[test]
fn the_statements_are_tenant_scoped_and_the_migrations_valid() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    assert!(DETAILS_SQL.contains("WHERE tenant = $1"));
    assert!(UNRECORDED_SQL.contains("FROM alert_outbox o JOIN alerts a ON a.tenant = o.tenant AND a.id = o.id WHERE o.tenant = $1"));
    assert!(UNRECORDED_SQL.contains("AND o.queued_at >= LEAST($3::text::timestamptz, now()) ORDER BY o.seq LIMIT"));
    assert!(!UNRECORDED_SQL.contains("NOT EXISTS") && !UNRECORDED_SQL.contains("(created, id)"));
    let columns = GET_SQL.split(" FROM ").next().ok_or("no select list")?;
    assert!(UNRECORDED_SQL.replace("a.", "").starts_with(columns));
    assert!(SKIP_SQL.contains("DELETE FROM alert_outbox WHERE tenant = $1") && SKIP_SQL.contains("queued_at < LEAST($2::text::timestamptz, now())"));
    assert!(SKIP_SQL.contains("LIMIT $3::text::bigint") && PURGE_SQL.contains("LIMIT $3::text::bigint"));
    assert!(PURGE_SQL.contains("tenant <> ALL(") && PURGE_SQL.contains("$1::text = ANY(") && PURGE_SQL.contains("DELETE FROM alert_outbox"));
    assert!(!PURGE_SQL.contains("JOIN alerts") && !PURGE_SQL.contains("FROM alerts"));
    assert!(RECORD_SQL.contains("consumed AS (DELETE FROM alert_outbox WHERE tenant = $1 AND id = $8::text)"));
    assert!(RECORD_SQL.contains("ON CONFLICT (tenant, fingerprint) WHERE state <> 'resolved' DO NOTHING"));
    assert!(RECORD_SQL.contains("ON CONFLICT (tenant, source_alert) DO NOTHING"));
    assert!(!RECORD_SQL.contains("oncall_alert_cursors"));
    let third = MIGRATIONS.get(THIRD_MIGRATION).ok_or("no migration")?;
    assert!(third.sql.contains("UNIQUE (tenant, source_alert)") && third.sql.contains("SET NOT NULL"));
    let last = MIGRATIONS.last().ok_or("no migration")?;
    assert!(last.sql.contains("CREATE TABLE oncall_poller_lease") && last.sql.contains("CHECK (singleton)"));
    assert!(
        LEASE_SQL.contains("ON CONFLICT (singleton) DO UPDATE") && LEASE_SQL.contains("lease.holder = EXCLUDED.holder OR lease.expires_at < now()")
    );
    assert!(PURGE_SQL.contains("WITH RECURSIVE seen") && PURGE_SQL.contains("min(o.tenant) FROM alert_outbox o WHERE o.tenant > seen.tenant"));
    Ok(())
}


#[tokio::test]
async fn an_alert_inserted_below_everything_recorded_is_recorded_on_the_next_poll() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    add(&source, "acme", "recent", BASE_CREATED * TWICE as u64, "recent");
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, 1);
    add(&source, "acme", "late", BASE_CREATED / TWICE as u64, "late commit with an old stamp");
    add(&source, "acme", "newer", BASE_CREATED * THREE as u64, "newer");
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, TWICE);
    assert_eq!(count_for(&db, "acme"), THREE);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?.opened, 0);
    Ok(())
}


#[tokio::test]
async fn the_same_source_id_in_two_tenants_is_recorded_in_each() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let mut mine = source_alert("acme", "e1", BASE_CREATED, "t");
    let mut theirs = mine.clone();
    mine.id = "shared".to_owned();
    theirs.id = "shared".to_owned();
    lock(&source.alerts).push(("acme".to_owned(), mine));
    lock(&source.alerts).push(("other".to_owned(), theirs));
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert_eq!((opened(&outcomes, "acme")?, opened(&outcomes, "other")?), (1, 1));
    assert_eq!((count_for(&db, "acme"), count_for(&db, "other")), (1, 1));
    Ok(())
}


#[tokio::test]
async fn the_alert_read_refuses_malformed_input_and_rows() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let alerts_exec = source_exec(&source, &db);
    let scope = tenant_scope("acme")?;
    assert!(
        alerts_exec(scope.clone(), UNRECORDED_SQL, vec!["many".to_owned(), "1970-01-01T00:00:00Z".to_owned()])
            .await
            .is_err()
    );
    assert!(alerts_exec(scope, UNRECORDED_SQL, Vec::new()).await.is_err());
    let broken = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'static> {
        Box::pin(ready(Ok(vec![vec!["only one column".to_owned()]])))
    };
    let mut exec = exec_for(&db);
    assert!(matches!(
        poll_tenant(&broken, &mut exec, &settings, "acme", poll_time()).await,
        Err(SourceError::Alerts(_))
    ));
    Ok(())
}


#[tokio::test]
async fn a_held_key_is_consumed_not_stuck_and_the_queue_moves_on() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    add(&source, "acme", "held", BASE_CREATED, "held");
    add(&source, "acme", "next", BASE_CREATED + 1, "next");
    let held = alert_id("acme", "rule", &["held".to_owned()]);
    lock(&db).alerts.push(("acme".to_owned(), 1, format!("{FINGERPRINT_PREFIX}{held}")));
    let capped = SourceSettings { max_per_poll: 1, ..settings };
    let held_counts = poll_tenant(&alerts_exec, &mut exec, &capped, "acme", poll_time()).await?;
    assert_eq!((held_counts.opened, held_counts.already, held_counts.conflict), (0, 0, 1));
    assert_eq!(lock(&db).consumed.len(), 1);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &capped, "acme", poll_time()).await?.opened, 1);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &capped, "acme", poll_time()).await?.opened, 0);
    Ok(())
}


#[tokio::test]
async fn the_generic_open_refuses_the_source_fingerprint_prefix() -> TestResult {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let refused = oncall::store::open_alert(&mut exec, &scope, &format!("{FINGERPRINT_PREFIX}x"), poll_time()).await;
    assert!(matches!(refused, Err(StoreError::InvalidFingerprint { .. })));
    assert!(lock(&db).calls.is_empty());
    assert!(oncall::store::valid_fingerprint("manual:1") && !oncall::store::valid_fingerprint("") && !oncall::store::valid_fingerprint("alert:1"));
    Ok(())
}


const GHOST_EXTRA: usize = 5;


const GHOST_ROWS: usize = 2 * MAX_PURGE_PER_ROUND + GHOST_EXTRA;


const OLD_ALERTS: usize = 5;


const ANSWER: usize = 7;


#[tokio::test]
async fn the_outbox_of_an_unpolled_tenant_is_purged_in_bounded_rounds_while_polled_tenants_are_served() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..GHOST_ROWS).for_each(|index| add(&source, "ghost", &format!("g{index}"), BASE_CREATED + index as u64, "ghost"));
    (0..FLOOD).for_each(|index| add(&source, "acme", &format!("a{index}"), BASE_CREATED + index, "mine"));
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let purged: Vec<usize> = {
        let mut rounds = Vec::new();
        for _round in 0..THREE {
            let round = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
            assert_eq!(opened(&round, "acme")?, CAP);
            rounds.push(round.purged?.get("ghost").copied().unwrap_or(0));
        }
        rounds
    };
    assert_eq!(purged, vec![MAX_PURGE_PER_ROUND, MAX_PURGE_PER_ROUND, GHOST_EXTRA]);
    assert_eq!(count_for(&db, "ghost"), 0);
    assert_eq!(count_for(&db, "acme"), CAP * THREE);
    assert!(lock(&source.purge_scopes).iter().all(|tenant| tenant == "acme"));
    assert!(lock(&source.reads).iter().all(|tenant| tenant != "ghost"));
    Ok(())
}


#[tokio::test]
async fn a_tenant_added_later_does_not_page_its_backlog() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let base = settings()?;
    let added = DateTime::<Utc>::UNIX_EPOCH + chrono::Duration::microseconds(BASE_CREATED as i64 + OLD_ALERTS as i64);
    let with_added = SourceSettings {
        added_at: BTreeMap::from([("other".to_owned(), added)]),
        ..base
    };
    (0..FLOOD).for_each(|index| add(&source, "other", &format!("o{index}"), BASE_CREATED + index, "old or new"));
    add(&source, "acme", "mine", 1, "older than any added_at but acme has none");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let first = poll_all(&alerts_exec, &mut exec, &with_added, "poller-a", poll_time).await;
    let counts = first
        .outcomes
        .iter()
        .find(|(name, _result)| name == "other")
        .ok_or("missing")?
        .1
        .as_ref()
        .map_err(ToString::to_string)?;
    assert_eq!((counts.skipped_backlog, counts.opened), (OLD_ALERTS, CAP));
    assert_eq!(opened(&first, "acme")?, 1);
    let second = poll_all(&alerts_exec, &mut exec, &with_added, "poller-a", poll_time).await;
    let again = second
        .outcomes
        .iter()
        .find(|(name, _result)| name == "other")
        .ok_or("missing")?
        .1
        .as_ref()
        .map_err(ToString::to_string)?;
    assert_eq!((again.skipped_backlog, again.opened), (0, CAP));
    assert_eq!(count_for(&db, "other"), CAP * TWICE);
    let ids: Vec<String> = lock(&db).details.iter().map(|(_owner, _id, params)| text(params, P_SOURCE_ID)).collect();
    assert!(!ids.contains(&alert_id("other", "rule", &["o0".to_owned()])));
    Ok(())
}


#[tokio::test]
async fn a_bad_count_answer_or_failing_store_is_reported_not_swallowed() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = SourceSettings {
        added_at: BTreeMap::from([("acme".to_owned(), DateTime::<Utc>::UNIX_EPOCH)]),
        ..settings()?
    };
    let alerts_exec = source_exec(&source, &db);
    let scope = tenant_scope("acme")?;
    assert!(matches!(count_answer(&[]), Err(alerts::error::StoreError::BadRow { .. })));
    assert!(matches!(count_answer(&[Vec::new()]), Err(alerts::error::StoreError::BadRow { .. })));
    assert!(count_answer(&[vec!["many".to_owned()]]).is_err());
    assert_eq!(count_answer(&[vec![ANSWER.to_string()]])?, ANSWER);
    *lock(&source.bad_count) = Some(vec![vec!["many".to_owned()]]);
    assert!(matches!(purge_unpolled(&alerts_exec, &settings).await, Err(SourceError::Alerts(_))));
    assert!(matches!(
        skip_backlog(&alerts_exec, &settings, &scope, "acme").await,
        Err(SourceError::Alerts(_))
    ));
    let mut exec = exec_for(&db);
    assert!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await.is_err());
    *lock(&source.bad_count) = None;
    *lock(&source.fail) = true;
    assert!(matches!(purge_unpolled(&alerts_exec, &settings).await, Err(SourceError::Alerts(_))));
    assert!(matches!(
        skip_backlog(&alerts_exec, &settings, &scope, "acme").await,
        Err(SourceError::Alerts(_))
    ));
    let round = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert!(round.purged.is_err() && round.outcomes.iter().all(|(_tenant, outcome)| outcome.is_err()));
    let empty = SourceSettings {
        tenants: Vec::new(),
        ..settings.clone()
    };
    assert!(matches!(purge_unpolled(&alerts_exec, &empty).await, Err(SourceError::NoTenants)));
    let unnamed = SourceSettings {
        tenants: vec!["bad name".to_owned()],
        ..settings
    };
    assert!(matches!(purge_unpolled(&alerts_exec, &unnamed).await, Err(SourceError::Tenant(_))));
    Ok(())
}


#[tokio::test]
async fn a_fresh_alert_is_paged_in_the_first_round_whatever_backlog_is_left_to_skip() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let added = DateTime::<Utc>::UNIX_EPOCH + chrono::Duration::microseconds((BASE_CREATED + MAX_SKIP_PER_POLL as u64 + GHOST_EXTRA as u64) as i64);
    let with_added = SourceSettings {
        added_at: BTreeMap::from([("acme".to_owned(), added)]),
        ..settings()?
    };
    (0..MAX_SKIP_PER_POLL + GHOST_EXTRA).for_each(|index| add(&source, "acme", &format!("old{index}"), BASE_CREATED + index as u64, "old"));
    add(&source, "acme", "fresh", 1, "fresh");
    requeue(&source, "acme", "fresh", added.timestamp_micros() + 1);
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let first = poll_tenant(&alerts_exec, &mut exec, &with_added, "acme", poll_time()).await?;
    assert_eq!((first.skipped_backlog, first.opened), (MAX_SKIP_PER_POLL, 1));
    let second = poll_tenant(&alerts_exec, &mut exec, &with_added, "acme", poll_time()).await?;
    assert_eq!((second.skipped_backlog, second.opened), (GHOST_EXTRA, 0));
    assert_eq!(count_for(&db, "acme"), 1);
    let ids: Vec<String> = lock(&db).details.iter().map(|(_owner, _id, params)| text(params, P_SOURCE_ID)).collect();
    assert_eq!(ids, vec![alert_id("acme", "rule", &["fresh".to_owned()])]);
    Ok(())
}


#[test]
fn an_added_at_later_than_the_load_time_is_refused() -> TestResult {
    let at = |offset: i64| {
        format!(
            "{VALID_SETTINGS}added_at:\n  other: {}\n",
            (load_time() + chrono::Duration::seconds(offset)).to_rfc3339()
        )
    };
    assert!(parse_source_settings(&at(0), "s.yaml", load_time()).is_ok());
    assert!(matches!(
        parse_source_settings(&at(1), "s.yaml", load_time()),
        Err(OncallError::InvalidSetting { field: "added_at" })
    ));
    assert!(parse_source_settings(&at(LOAD_DAYS), "s.yaml", load_time()).is_err());
    Ok(())
}


#[tokio::test]
async fn one_poller_holds_the_lease_and_the_other_does_nothing_until_it_expires() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let for_a = SourceSettings {
        tenants: vec!["acme".to_owned()],
        ..settings()?
    };
    let for_b = SourceSettings {
        tenants: vec!["beta".to_owned()],
        ..settings()?
    };
    add(&source, "beta", "b1", BASE_CREATED, "b");
    let first = poll_all(&alerts_exec, &mut exec, &for_b, "poller-b", poll_time).await;
    assert!(matches!(first.leased, Ok(true)) && opened(&first, "beta")? == 1);
    assert!(matches!(
        poll_all(&alerts_exec, &mut exec, &for_b, "poller-b", poll_time).await.leased,
        Ok(true)
    ));
    add(&source, "acme", "a1", BASE_CREATED, "a");
    let refused = poll_all(&alerts_exec, &mut exec, &for_a, "poller-a", poll_time).await;
    assert!(matches!(refused.leased, Ok(false)) && matches!(&refused.purged, Ok(counts) if counts.is_empty()) && refused.outcomes.is_empty());
    assert_eq!((count_for(&db, "acme"), count_for(&db, "beta")), (0, 1));
    assert!(lock(&source.purge_scopes).iter().all(|tenant| tenant == "beta"));
    lock(&db).lease_expired = true;
    let taken = poll_all(&alerts_exec, &mut exec, &for_a, "poller-a", poll_time).await;
    assert!(matches!(taken.leased, Ok(true)) && opened(&taken, "acme")? == 1);
    assert_eq!(lock(&db).lease.as_deref(), Some("poller-a"));
    Ok(())
}


#[tokio::test]
async fn rounds_without_the_lease_report_it_and_page_nothing() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "acme", "e1", BASE_CREATED, "t");
    lock(&db).lease = Some("poller-b".to_owned());
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let hooks = RoundHooks {
        now: poll_time,
        wait: instant,
        report: quiet,
        audit_purge: &|_counts| (),
    };
    run_rounds(ROUNDS, &alerts_exec, &mut exec, &settings, "poller-a", &hooks).await;
    assert!(lock(&source.reads).is_empty() && count_for(&db, "acme") == 0);
    lock(&db).lease_expired = true;
    run_rounds(1, &alerts_exec, &mut exec, &settings, "poller-a", &hooks).await;
    assert_eq!(count_for(&db, "acme"), 1);
    Ok(())
}


#[tokio::test]
async fn a_failing_lease_statement_is_reported_and_nothing_runs() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "acme", "e1", BASE_CREATED, "t");
    lock(&db).fail_on_call = Some(1);
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let round = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert!(matches!(round.leased, Err(SourceError::Store(_))) && round.outcomes.is_empty());
    let empty = SourceSettings {
        tenants: Vec::new(),
        ..settings.clone()
    };
    assert!(matches!(take_lease(&mut exec, &empty, "poller-a").await, Err(SourceError::NoTenants)));
    let unnamed = SourceSettings {
        tenants: vec!["bad name".to_owned()],
        ..settings.clone()
    };
    assert!(matches!(take_lease(&mut exec, &unnamed, "poller-a").await, Err(SourceError::Tenant(_))));
    let endless = SourceSettings {
        interval_seconds: u64::MAX,
        ..settings
    };
    assert!(matches!(take_lease(&mut exec, &endless, "poller-a").await, Err(SourceError::Store(_))));
    Ok(())
}


fn lease_calls(db: &Arc<Mutex<Db>>) -> usize {
    lock(db).calls.iter().filter(|sql| **sql == LEASE_SQL).count()
}


#[tokio::test]
async fn the_lease_is_renewed_before_every_further_tenant_and_before_the_purge() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let round = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert!(matches!(round.leased, Ok(true)) && round.outcomes.len() == settings.tenants.len());
    assert_eq!(lease_calls(&db), settings.tenants.len() + 1);
    Ok(())
}


#[tokio::test]
async fn a_round_that_loses_the_lease_midway_stops_before_the_next_tenant_and_the_purge() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    add(&source, "ghost", "g", BASE_CREATED, "ghost");
    add(&source, "other", "o", BASE_CREATED, "other");
    lock(&db).steal_on_lease = Some(TWICE);
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let round = poll_all(&alerts_exec, &mut exec, &settings, "poller-a", poll_time).await;
    assert!(matches!(round.leased, Ok(false)) && round.outcomes.len() == 1);
    assert!(matches!(&round.purged, Ok(counts) if counts.is_empty()));
    assert!(lock(&source.purge_scopes).is_empty() && count_for(&db, "other") == 0);
    assert_eq!(lease_calls(&db), TWICE);
    Ok(())
}


#[tokio::test]
async fn purged_rows_are_reported_per_tenant_and_audited_once_per_round() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..THREE).for_each(|index| add(&source, "ghost", &format!("g{index}"), BASE_CREATED + index as u64, "ghost"));
    add(&source, "phantom", "p", BASE_CREATED, "phantom");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let audited = Mutex::new(Vec::new());
    let record = |counts: &oncall::types::PurgedCounts| lock(&audited).push(counts.clone());
    let hooks = RoundHooks {
        now: poll_time,
        wait: instant,
        report: quiet,
        audit_purge: &record,
    };
    run_rounds(TWICE, &alerts_exec, &mut exec, &settings, "poller-a", &hooks).await;
    let expected = BTreeMap::from([("ghost".to_owned(), THREE), ("phantom".to_owned(), 1)]);
    assert_eq!(*lock(&audited), vec![expected]);
    Ok(())
}


#[test]
fn purge_rows_with_a_foreign_tenant_name_or_a_bad_count_are_refused() -> TestResult {
    assert!(purged_counts(&[vec!["bad name".to_owned(), "1".to_owned()]]).is_err());
    assert!(purged_counts(&[vec!["acme".to_owned()]]).is_err());
    assert!(purged_counts(&[vec!["acme".to_owned(), "many".to_owned()]]).is_err());
    assert!(purged_counts(&[Vec::new()]).is_err());
    assert_eq!(purged_counts(&[vec!["acme".to_owned(), "2".to_owned()]])?.get("acme"), Some(&TWICE));
    Ok(())
}


#[tokio::test]
async fn an_unusable_holder_id_never_reaches_the_lease_statement() -> TestResult {
    let db = new_db();
    let settings = settings()?;
    let mut exec = exec_for(&db);
    assert!(matches!(take_lease(&mut exec, &settings, "").await, Err(SourceError::Holder(_))));
    assert!(matches!(take_lease(&mut exec, &settings, "a b").await, Err(SourceError::Holder(_))));
    assert!(lock(&db).calls.is_empty());
    Ok(())
}

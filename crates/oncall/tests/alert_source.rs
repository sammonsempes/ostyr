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
    alert_notice, clean_text, map_severity, parse_source_settings, poll_all, poll_tenant, record_alert, run_rounds, source_details,
    validate_source_settings, SourceSettings, DETAILS_SQL, FINGERPRINT_PREFIX, RECORD_SQL, UNRECORDED_SQL,
};
use oncall::error::{OncallError, SourceError, StoreError};
use oncall::limits::MAX_SOURCE_TEXT_CHARS;
use oncall::model::{Channel, ChannelKind};
use oncall::render::render;
use oncall::store::MIGRATIONS;
use oncall::types::{Row, TenantOutcome};
use std::collections::BTreeMap;
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
}


#[derive(Default)]
struct Db {
    alerts: Vec<(String, i64, String)>,
    details: Vec<(String, i64, Vec<Param>)>,
    calls: Vec<&'static str>,
    fail_on_call: Option<usize>,
    record_rows: Option<Vec<Row>>,
    details_rows: Option<Vec<Row>>,
}


fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


fn poll_time() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH
}


fn quiet(_outcomes: &[TenantOutcome]) {}


fn instant(_interval: Duration) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(ready(()))
}


fn settings() -> Result<SourceSettings, OncallError> {
    parse_source_settings(VALID_SETTINGS, "source.yaml")
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


fn source_handle(
    db: &SourceDb,
    recorded: &Arc<Mutex<Db>>,
    scope: &TenantScope,
    sql: &'static str,
    params: &[String],
) -> Result<Vec<Vec<String>>, PgError> {
    lock(&db.reads).push(tenant_of(scope).to_owned());
    assert_eq!(sql, UNRECORDED_SQL);
    if *lock(&db.fail) {
        Err(PgError::InvalidTenant)
    } else {
        let limit = params.last().ok_or_else(malformed)?.parse::<usize>().map_err(|_bad| malformed())?;
        let done: Vec<String> = lock(recorded)
            .alerts
            .iter()
            .filter(|(owner, _id, _key)| owner == tenant_of(scope))
            .map(|(_owner, _id, key)| key.clone())
            .collect();
        let mut mine: Vec<SourceAlert> = lock(&db.alerts)
            .iter()
            .filter(|(owner, _alert)| owner == tenant_of(scope))
            .map(|(_owner, alert)| alert.clone())
            .filter(|alert| !done.contains(&format!("{FINGERPRINT_PREFIX}{}", alert.id)))
            .collect();
        mine.sort_by(|left, right| (left.created_micros, &left.id).cmp(&(right.created_micros, &right.id)));
        Ok(mine.iter().take(limit).map(source_row).collect())
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
    } else if statement.sql == RECORD_SQL {
        let params = &statement.params;
        let fingerprint = text(params, 0);
        let source_id = text(params, P_SOURCE_ID);
        let recorded = db
            .details
            .iter()
            .any(|(owner, _id, detail)| owner == tenant && text(detail, P_SOURCE_ID) == source_id);
        let known = recorded || db.alerts.iter().any(|(owner, _id, key)| owner == tenant && *key == fingerprint);
        let id = i64::try_from(db.alerts.len()).unwrap_or(0) + 1;
        if !known {
            db.alerts.push((tenant.to_owned(), id, fingerprint));
            db.details.push((tenant.to_owned(), id, params.clone()));
        }
        Ok(db.record_rows.clone().unwrap_or_else(|| vec![vec![Cell::Int(i64::from(!known))]]))
    } else if statement.sql == DETAILS_SQL {
        let wanted = match statement.params.first() {
            Some(Param::Int(value)) => *value,
            _ => 0,
        };
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


fn opened(outcomes: &[TenantOutcome], tenant: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let found = outcomes.iter().find(|(name, _result)| name == tenant).ok_or("tenant missing")?;
    match &found.1 {
        Ok(count) => Ok(*count),
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
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?, THREE);
    assert_eq!(count_for(&db, "acme"), THREE);
    let records_before = lock(&db).calls.iter().filter(|sql| **sql == RECORD_SQL).count();
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?, 0);
    assert_eq!(lock(&db).calls.iter().filter(|sql| **sql == RECORD_SQL).count(), records_before);
    add(&source, "acme", "late", BASE_CREATED + FLOOD, "late one");
    let mut restarted = exec_for(&db);
    assert_eq!(poll_tenant(&alerts_exec, &mut restarted, &wide, "acme", poll_time()).await?, 1);
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
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 1);
    let scope = tenant_scope("acme")?;
    let again = source_alert("acme", "e1", BASE_CREATED, "t");
    assert_eq!(record_alert(&mut exec, &scope, &settings, &again, poll_time()).await?, 0);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 0);
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
    let first = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?;
    let second = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?;
    let third = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?;
    let fourth = poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?;
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
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 1);
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
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, poll_time).await;
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
    poll_all(&alerts_exec, &mut exec, &only_acme, poll_time).await;
    assert_eq!(count_for(&db, "other"), before);
    Ok(())
}


#[tokio::test]
async fn a_failing_tenant_does_not_stop_the_others() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = SourceSettings {
        tenants: vec!["bad name".to_owned(), "acme".to_owned()],
        ..settings()?
    };
    add(&source, "acme", "e1", BASE_CREATED, "t");
    let alerts_exec = source_exec(&source, &db);
    let mut exec = exec_for(&db);
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, poll_time).await;
    assert!(matches!(outcomes.first().map(|(_n, result)| result), Some(Err(SourceError::Tenant(_)))));
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
    run_rounds(ROUNDS, &alerts_exec, &mut exec, &settings, poll_time, instant, quiet).await;
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
    assert!(details.title.chars().count() <= MAX_SOURCE_TEXT_CHARS);
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
    lock(&db).details_rows = Some(vec![vec![Cell::Int(1)]]);
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
        validate_source_settings(&copy).err().ok_or_else(|| "accepted".into())
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
    assert!(parse_source_settings(&format!("{VALID_SETTINGS}extra: 1\n"), "s.yaml").is_err());
    assert_eq!(clean_text("a\u{85}b\u{2029}c"), "a b c");
    assert_eq!(clean_text("x\u{202E}y\u{202A}\u{2066}z\u{2069}"), "x y  z ");
    assert_eq!(clean_text("\u{2029}\u{202F}\u{2065}\u{206A}"), " \u{202F}\u{2065}\u{206A}");
    Ok(())
}


#[test]
fn the_statements_are_tenant_scoped_and_the_migrations_valid() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    assert!(DETAILS_SQL.contains("WHERE tenant = $1"));
    assert!(UNRECORDED_SQL.contains("WHERE alerts.tenant = $1") && UNRECORDED_SQL.contains("d.tenant = $1 AND d.source_alert = alerts.id"));
    assert!(UNRECORDED_SQL.contains("ORDER BY alerts.created ASC, alerts.id ASC LIMIT"));
    assert!(!UNRECORDED_SQL.contains("(created, id) >"));
    let columns = GET_SQL.split(" FROM ").next().ok_or("no select list")?;
    assert!(UNRECORDED_SQL.starts_with(columns));
    assert!(RECORD_SQL.contains("ON CONFLICT (tenant, fingerprint) WHERE state <> 'resolved' DO NOTHING"));
    assert!(RECORD_SQL.contains("ON CONFLICT (tenant, source_alert) DO NOTHING"));
    assert!(!RECORD_SQL.contains("oncall_alert_cursors"));
    let last = MIGRATIONS.last().ok_or("no migration")?;
    assert!(last.sql.contains("UNIQUE (tenant, source_alert)") && last.sql.contains("SET NOT NULL"));
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
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 1);
    add(&source, "acme", "late", BASE_CREATED / TWICE as u64, "late commit with an old stamp");
    add(&source, "acme", "newer", BASE_CREATED * THREE as u64, "newer");
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, TWICE);
    assert_eq!(count_for(&db, "acme"), THREE);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 0);
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
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, poll_time).await;
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
    assert!(alerts_exec(scope.clone(), UNRECORDED_SQL, vec!["many".to_owned()]).await.is_err());
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

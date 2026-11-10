#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use alerts::model::{Alert as SourceAlert, Severity, Summary};
use alerts::store::{FIRST_ASC_SQL, NEXT_ASC_SQL};
use alerts::types::RowFuture;
use chrono::{DateTime, Utc};
use core_pg::error::PgError;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use oncall::alert::{Cell, Param, Statement};
use oncall::alert_source::{
    alert_notice, clean_text, map_severity, parse_source_settings, poll_all, poll_tenant, read_cursor, record_alert, run_rounds, source_details,
    validate_source_settings, SourceSettings, CURSOR_SQL, DETAILS_SQL, FINGERPRINT_PREFIX, RECORD_SQL,
};
use oncall::error::{OncallError, SourceError, StoreError};
use oncall::limits::MAX_SOURCE_TEXT_CHARS;
use oncall::model::{Channel, ChannelKind};
use oncall::render::render;
use oncall::store::MIGRATIONS;
use oncall::types::{Row, TenantOutcome};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;
use types::TestResult;


const P_CREATED: usize = 6;


const P_SOURCE_ID: usize = 7;


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


const FAIL_ON_SECOND_RECORD: usize = 3;


const VALID_SETTINGS: &str = "tenants: [acme, other]\nmax_per_poll: 2\ninterval_seconds: 30\nseverity_map:\n  informational: info\n  low: info\n  medium: ticket\n  high: page\n  critical: page-now\n";


#[derive(Default)]
struct SourceDb {
    alerts: RefCell<Vec<(String, SourceAlert)>>,
    fail: RefCell<bool>,
    reads: RefCell<Vec<String>>,
}


#[derive(Default)]
struct Db {
    cursors: BTreeMap<String, (i64, String)>,
    alerts: Vec<(String, i64, String)>,
    details: Vec<(String, i64, Vec<Param>)>,
    calls: Vec<&'static str>,
    fail_on_call: Option<usize>,
    cursor_row: Option<Row>,
    record_rows: Option<Vec<Row>>,
    details_rows: Option<Vec<Row>>,
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


fn source_handle(db: &SourceDb, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    db.reads.borrow_mut().push(tenant_of(scope).to_owned());
    if *db.fail.borrow() {
        Err(PgError::InvalidTenant)
    } else {
        let limit = params.last().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
        let position = if sql == NEXT_ASC_SQL {
            Some((
                params.first().and_then(|text| text.parse::<u64>().ok()).unwrap_or(0),
                params.get(1).map_or("", String::as_str).to_owned(),
            ))
        } else {
            None
        };
        assert!(sql == FIRST_ASC_SQL || sql == NEXT_ASC_SQL);
        let mut mine: Vec<SourceAlert> = db
            .alerts
            .borrow()
            .iter()
            .filter(|(owner, _alert)| owner == tenant_of(scope))
            .map(|(_owner, alert)| alert.clone())
            .collect();
        mine.sort_by(|left, right| (left.created_micros, &left.id).cmp(&(right.created_micros, &right.id)));
        Ok(mine
            .iter()
            .filter(|alert| {
                position
                    .as_ref()
                    .is_none_or(|(created, id)| (alert.created_micros, &alert.id) > (*created, id))
            })
            .take(limit)
            .map(source_row)
            .collect())
    }
}


fn source_exec<'a>(db: &'a SourceDb) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(source_handle(db, &scope, sql, &params))) }
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
    } else if statement.sql == CURSOR_SQL {
        Ok(db
            .cursor_row
            .clone()
            .or_else(|| {
                db.cursors
                    .get(tenant)
                    .map(|(created, id)| vec![Cell::Int(*created), Cell::Text(id.clone())])
            })
            .into_iter()
            .collect())
    } else if statement.sql == RECORD_SQL {
        let params = &statement.params;
        let fingerprint = text(params, 0);
        let created = match params.get(P_CREATED) {
            Some(Param::Int(value)) => *value,
            _ => -1,
        };
        let source_id = text(params, P_SOURCE_ID);
        let known = db.alerts.iter().any(|(owner, _id, key)| owner == tenant && *key == fingerprint);
        let id = i64::try_from(db.alerts.len()).unwrap_or(0) + 1;
        if !known {
            db.alerts.push((tenant.to_owned(), id, fingerprint));
            db.details.push((tenant.to_owned(), id, params.clone()));
        }
        let moves = db
            .cursors
            .get(tenant)
            .is_none_or(|(old_created, old_id)| (*old_created, old_id.clone()) < (created, source_id.clone()));
        if moves {
            db.cursors.insert(tenant.to_owned(), (created, source_id));
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


fn exec_for(db: &Rc<RefCell<Db>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(db);
    move |scope, statement| {
        let result = match shared.try_borrow_mut() {
            Ok(mut guard) => handle(&mut guard, tenant_of(scope), &statement),
            Err(_busy) => Err(StoreError::NotFound),
        };
        ready(result)
    }
}


fn new_db() -> Rc<RefCell<Db>> {
    Rc::new(RefCell::new(Db::default()))
}


fn count_for(db: &Rc<RefCell<Db>>, tenant: &str) -> usize {
    db.borrow().alerts.iter().filter(|(owner, _id, _key)| owner == tenant).count()
}


fn add(source: &SourceDb, tenant: &str, name: &str, created: u64, title: &str) {
    source
        .alerts
        .borrow_mut()
        .push((tenant.to_owned(), source_alert(tenant, name, created, title)));
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
    let alerts_exec = source_exec(&source);
    let mut exec = exec_for(&db);
    let wide = SourceSettings {
        max_per_poll: THREE + 1,
        ..settings.clone()
    };
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?, THREE);
    assert_eq!(count_for(&db, "acme"), THREE);
    let records_before = db.borrow().calls.iter().filter(|sql| **sql == RECORD_SQL).count();
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &wide, "acme", poll_time()).await?, 0);
    assert_eq!(db.borrow().calls.iter().filter(|sql| **sql == RECORD_SQL).count(), records_before);
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
    let alerts_exec = source_exec(&source);
    let mut exec = exec_for(&db);
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 1);
    db.borrow_mut().cursors.clear();
    assert_eq!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await?, 0);
    assert_eq!(count_for(&db, "acme"), 1);
    assert_eq!(db.borrow().details.len(), 1);
    assert!(db.borrow().cursors.contains_key("acme"));
    Ok(())
}


#[tokio::test]
async fn one_poll_records_at_most_the_cap() -> TestResult {
    let source = SourceDb::default();
    let db = new_db();
    let settings = settings()?;
    (0..CAP + THREE).for_each(|index| add(&source, "acme", &format!("e{index}"), BASE_CREATED + index as u64, "t"));
    let alerts_exec = source_exec(&source);
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
    let alerts_exec = source_exec(&source);
    let mut exec = exec_for(&db);
    *source.fail.borrow_mut() = true;
    assert!(matches!(
        poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await,
        Err(SourceError::Alerts(_))
    ));
    assert!(db.borrow().cursors.is_empty());
    *source.fail.borrow_mut() = false;
    db.borrow_mut().calls.clear();
    db.borrow_mut().fail_on_call = Some(1);
    assert!(matches!(
        poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await,
        Err(SourceError::Store(_))
    ));
    assert!(db.borrow().cursors.is_empty());
    db.borrow_mut().calls.clear();
    db.borrow_mut().fail_on_call = Some(FAIL_ON_SECOND_RECORD);
    assert!(poll_tenant(&alerts_exec, &mut exec, &settings, "acme", poll_time()).await.is_err());
    let after_failure = db.borrow().cursors.get("acme").cloned();
    assert_eq!(after_failure.map(|(created, _id)| created), Some(i64::try_from(BASE_CREATED)?));
    db.borrow_mut().fail_on_call = None;
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
    let alerts_exec = source_exec(&source);
    let mut exec = exec_for(&db);
    let outcomes = poll_all(&alerts_exec, &mut exec, &settings, poll_time).await;
    assert_eq!(opened(&outcomes, "acme")?, CAP);
    assert_eq!(opened(&outcomes, "other")?, 1);
    assert_eq!(count_for(&db, "other"), 1);
    let foreign_id = alert_id("other", "rule", &["x".to_owned()]);
    assert!(db
        .borrow()
        .alerts
        .iter()
        .filter(|(owner, _id, _key)| owner == "acme")
        .all(|(_o, _i, key)| *key != format!("{FINGERPRINT_PREFIX}{foreign_id}")));
    assert!(source.reads.borrow().iter().all(|tenant| tenant == "acme" || tenant == "other"));
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
    let alerts_exec = source_exec(&source);
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
    let alerts_exec = source_exec(&source);
    let mut exec = exec_for(&db);
    run_rounds(ROUNDS, &alerts_exec, &mut exec, &settings, poll_time, instant, quiet).await;
    assert_eq!(
        db.borrow().calls.iter().filter(|sql| **sql == CURSOR_SQL).count(),
        ROUNDS * settings.tenants.len()
    );
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
    source
        .alerts
        .borrow_mut()
        .iter_mut()
        .for_each(|(_owner, alert)| alert.user_name = Some("root\n".to_owned()));
    let alerts_exec = source_exec(&source);
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
    db.borrow_mut().cursor_row = Some(vec![Cell::Int(-1), Cell::Text("id".to_owned())]);
    assert!(matches!(read_cursor(&mut exec, &scope).await, Err(SourceError::BadCursor)));
    db.borrow_mut().cursor_row = Some(vec![Cell::Text("x".to_owned())]);
    assert!(matches!(read_cursor(&mut exec, &scope).await, Err(SourceError::Store(_))));
    db.borrow_mut().cursor_row = None;
    assert!(read_cursor(&mut exec, &scope).await?.is_none());
    let mut hostile = source_alert("acme", "e1", BASE_CREATED, "t");
    hostile.id = "bad\nid".to_owned();
    assert!(matches!(
        record_alert(&mut exec, &scope, &settings, &hostile, poll_time()).await,
        Err(SourceError::Store(StoreError::InvalidFingerprint { .. }))
    ));
    let mut huge = source_alert("acme", "e2", BASE_CREATED, "t");
    huge.created_micros = u64::MAX;
    assert!(matches!(
        record_alert(&mut exec, &scope, &settings, &huge, poll_time()).await,
        Err(SourceError::BadCursor)
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
    db.borrow_mut().record_rows = Some(Vec::new());
    assert!(matches!(
        record_alert(&mut exec, &scope, &settings, &fine, poll_time()).await,
        Err(SourceError::Store(StoreError::NotFound))
    ));
    assert!(matches!(
        poll_tenant(&source_exec(&source), &mut exec, &settings, "bad name", poll_time()).await,
        Err(SourceError::Tenant(_))
    ));
    db.borrow_mut().details_rows = Some(vec![vec![Cell::Int(1)]]);
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
    Ok(())
}


#[test]
fn the_statements_are_tenant_scoped_and_the_migrations_valid() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    assert!(CURSOR_SQL.contains("WHERE tenant = $1"));
    assert!(DETAILS_SQL.contains("WHERE tenant = $1"));
    assert!(RECORD_SQL.contains("ON CONFLICT (tenant, fingerprint) WHERE state <> 'resolved' DO NOTHING"));
    assert!(RECORD_SQL.contains("(oncall_alert_cursors.created, oncall_alert_cursors.id) < (EXCLUDED.created, EXCLUDED.id)"));
    assert!(MIGRATIONS.iter().any(|migration| migration.sql.contains("oncall_alert_cursors")));
    Ok(())
}

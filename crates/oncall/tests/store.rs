use chrono::{DateTime, TimeZone, Utc};
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use oncall::alert::{Alert, Cell, Event, Outcome, Param, Phase, Statement};
use oncall::error::{LifecycleError, StoreError};
use oncall::limits::{MAX_ALERT_LEVEL, MAX_CHANNEL_NAME_BYTES, MAX_FINGERPRINT_BYTES, MAX_OPEN_ALERTS, MAX_REASON_LEN};
use oncall::rows::phase_name;
use oncall::store::{
    apply_event, get_alert, open_alert, open_alerts, record_notification, GET_SQL, LIST_SQL, MIGRATIONS, NOTIFY_SQL, OPEN_SQL, UPDATE_SQL,
};
use oncall::types::Row;
use std::cell::RefCell;
use std::error::Error;
use std::future::{ready, Ready};
use std::rc::Rc;


const STAMP: i64 = 1_700_000_000;


const LATER: i64 = 60;


const P_LEVEL: usize = 2;


const P_ACK: usize = 3;


const P_RESOLVED: usize = 4;


const P_VERSION: usize = 5;


const P_OUTCOME: usize = 2;


const P_REASON: usize = 3;


const TWO_ALERTS: usize = 2;


const STATEMENTS: usize = 5;


const SECOND_SEQ: i64 = 2;


const THIRD_VERSION: i64 = 3;


const SECOND_LEVEL: u32 = 2;


struct Notification {
    tenant: String,
    seq: i64,
    alert: i64,
    channel: String,
    outcome: String,
    reason: Option<String>,
}


#[derive(Default)]
struct Db {
    alerts: Vec<(String, Alert)>,
    notifications: Vec<Notification>,
    log: Vec<(String, Statement)>,
    next_id: i64,
    bump_before_update: bool,
}


fn at(offset: i64) -> Result<DateTime<Utc>, Box<dyn Error>> {
    Ok(Utc.timestamp_opt(STAMP + offset, 0).single().ok_or("bad stamp")?)
}


fn bad(column: &'static str) -> StoreError {
    StoreError::BadRow { column }
}


fn int_param(params: &[Param], index: usize) -> Result<i64, StoreError> {
    match params.get(index) {
        Some(Param::Int(value)) => Ok(*value),
        _ => Err(bad("fake int")),
    }
}


fn text_param(params: &[Param], index: usize) -> Result<String, StoreError> {
    match params.get(index) {
        Some(Param::Text(value)) => Ok(value.clone()),
        _ => Err(bad("fake text")),
    }
}


fn time_param(params: &[Param], index: usize) -> Result<Option<DateTime<Utc>>, StoreError> {
    match params.get(index) {
        Some(Param::Time(value)) => Ok(*value),
        _ => Err(bad("fake time")),
    }
}


fn alert_row(alert: &Alert) -> Row {
    vec![
        Cell::Int(alert.id),
        Cell::Text(alert.fingerprint.clone()),
        Cell::Text(phase_name(alert.state.phase).to_owned()),
        Cell::Int(i64::from(alert.state.level)),
        Cell::Int(alert.occurrences),
        Cell::Int(alert.version),
        Cell::Time(Some(alert.opened_at)),
        Cell::Time(alert.acknowledged_at),
        Cell::Time(alert.resolved_at),
    ]
}


fn handle(db: &mut Db, tenant: &str, statement: &Statement) -> Result<Vec<Row>, StoreError> {
    db.log.push((tenant.to_owned(), statement.clone()));
    let params = &statement.params;
    match statement.sql {
        OPEN_SQL => {
            let fingerprint = text_param(params, 0)?;
            let opened_at = time_param(params, 1)?.ok_or(bad("fake time"))?;
            let live = db
                .alerts
                .iter_mut()
                .find(|(owner, alert)| owner == tenant && alert.fingerprint == fingerprint && alert.state.phase != Phase::Resolved);
            let (row, created) = match live {
                Some((_, alert)) => {
                    alert.occurrences += 1;
                    (alert_row(alert), false)
                }
                None => {
                    db.next_id += 1;
                    let alert = Alert {
                        id: db.next_id,
                        fingerprint,
                        state: oncall::alert::LifecycleState {
                            phase: Phase::Open,
                            level: 0,
                        },
                        occurrences: 1,
                        version: 0,
                        opened_at,
                        acknowledged_at: None,
                        resolved_at: None,
                    };
                    let row = alert_row(&alert);
                    db.alerts.push((tenant.to_owned(), alert));
                    (row, true)
                }
            };
            Ok(vec![[row, vec![Cell::Bool(created)]].concat()])
        }
        GET_SQL => {
            let id = int_param(params, 0)?;
            Ok(db
                .alerts
                .iter()
                .filter(|(owner, alert)| owner == tenant && alert.id == id)
                .map(|(_, alert)| alert_row(alert))
                .collect())
        }
        UPDATE_SQL => {
            let id = int_param(params, 0)?;
            let phase = text_param(params, 1)?;
            let level = int_param(params, P_LEVEL)?;
            let acknowledged = time_param(params, P_ACK)?;
            let resolved = time_param(params, P_RESOLVED)?;
            let expected = int_param(params, P_VERSION)?;
            let bump = db.bump_before_update;
            let found = db.alerts.iter_mut().find(|(owner, alert)| owner == tenant && alert.id == id);
            match found {
                Some((_, alert)) => {
                    if bump {
                        alert.version += 1;
                    }
                    if alert.version == expected {
                        alert.state.phase = oncall::rows::parse_phase(&phase).ok_or(bad("fake phase"))?;
                        alert.state.level = u32::try_from(level).map_err(|_overflow| bad("fake level"))?;
                        alert.acknowledged_at = acknowledged;
                        alert.resolved_at = resolved;
                        alert.version += 1;
                        Ok(vec![alert_row(alert)])
                    } else {
                        Ok(Vec::new())
                    }
                }
                None => Ok(Vec::new()),
            }
        }
        LIST_SQL => {
            let limit = usize::try_from(int_param(params, 0)?).map_err(|_overflow| bad("fake limit"))?;
            Ok(db
                .alerts
                .iter()
                .filter(|(owner, alert)| owner == tenant && alert.state.phase != Phase::Resolved)
                .take(limit)
                .map(|(_, alert)| alert_row(alert))
                .collect())
        }
        NOTIFY_SQL => {
            let id = int_param(params, 0)?;
            let channel = text_param(params, 1)?;
            let outcome = text_param(params, P_OUTCOME)?;
            let reason = match params.get(P_REASON) {
                Some(Param::OptText(value)) => Ok(value.clone()),
                _ => Err(bad("fake reason")),
            }?;
            let owned = db.alerts.iter().any(|(owner, alert)| owner == tenant && alert.id == id);
            if owned {
                let seq = i64::try_from(db.notifications.len()).map_err(|_overflow| bad("fake seq"))? + 1;
                db.notifications.push(Notification {
                    tenant: tenant.to_owned(),
                    seq,
                    alert: id,
                    channel,
                    outcome,
                    reason,
                });
                Ok(vec![vec![Cell::Int(seq)]])
            } else {
                Ok(Vec::new())
            }
        }
        _ => Err(bad("fake sql")),
    }
}


fn exec_for(db: &Rc<RefCell<Db>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(db);
    move |scope, statement| {
        let result = match shared.try_borrow_mut() {
            Ok(mut guard) => handle(&mut guard, tenant_of(scope), &statement),
            Err(_busy) => Err(bad("fake busy")),
        };
        ready(result)
    }
}


fn new_db() -> Rc<RefCell<Db>> {
    Rc::new(RefCell::new(Db::default()))
}


#[tokio::test]
async fn the_same_fingerprint_is_deduplicated_per_tenant() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let first = open_alert(&mut exec, &acme, "cpu-high", at(0)?).await?;
    let second = open_alert(&mut exec, &acme, "cpu-high", at(LATER)?).await?;
    let foreign = open_alert(&mut exec, &other, "cpu-high", at(LATER)?).await?;
    assert!(first.created && !second.created && foreign.created);
    assert_eq!(first.alert.id, second.alert.id);
    assert_eq!(second.alert.occurrences, SECOND_SEQ);
    assert_ne!(first.alert.id, foreign.alert.id);
    assert_eq!(foreign.alert.occurrences, 1);
    assert_eq!(second.alert.opened_at, at(0)?);
    Ok(())
}


#[tokio::test]
async fn a_resolved_alert_is_not_reused_and_an_acknowledged_one_is() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let first = open_alert(&mut exec, &scope, "disk", at(0)?).await?;
    apply_event(&mut exec, &scope, first.alert.id, Event::Acknowledge, at(1)?).await?;
    let reused = open_alert(&mut exec, &scope, "disk", at(SECOND_SEQ)?).await?;
    assert!(!reused.created);
    assert_eq!(reused.alert.state.phase, Phase::Acknowledged);
    let resolved = apply_event(&mut exec, &scope, first.alert.id, Event::Resolve, at(LATER)?).await?;
    assert_eq!(resolved.resolved_at, Some(at(LATER)?));
    assert_eq!(resolved.acknowledged_at, Some(at(1)?));
    let reopened = open_alert(&mut exec, &scope, "disk", at(LATER)?).await?;
    assert!(reopened.created);
    assert_ne!(reopened.alert.id, first.alert.id);
    assert_eq!(reopened.alert.occurrences, 1);
    Ok(())
}


#[tokio::test]
async fn events_walk_the_lifecycle_and_bump_the_version() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let opened = open_alert(&mut exec, &scope, "mem", at(0)?).await?.alert;
    let escalated = apply_event(&mut exec, &scope, opened.id, Event::Escalate { to_level: 1 }, at(1)?).await?;
    assert_eq!(
        (escalated.state.phase, escalated.state.level, escalated.version),
        (Phase::Escalated, 1, 1)
    );
    let acknowledged = apply_event(&mut exec, &scope, opened.id, Event::Acknowledge, at(LATER)?).await?;
    assert_eq!(acknowledged.acknowledged_at, Some(at(LATER)?));
    let again = apply_event(&mut exec, &scope, opened.id, Event::Escalate { to_level: SECOND_LEVEL }, at(LATER + 1)?).await?;
    assert_eq!(again.acknowledged_at, Some(at(LATER)?));
    assert_eq!(again.version, THIRD_VERSION);
    let refused = apply_event(&mut exec, &scope, opened.id, Event::Escalate { to_level: MAX_ALERT_LEVEL }, at(LATER)?).await;
    assert!(matches!(refused, Err(StoreError::Lifecycle(LifecycleError::WrongLevel { .. }))));
    let fetched = get_alert(&mut exec, &scope, opened.id).await?;
    assert_eq!(fetched, again);
    Ok(())
}


#[tokio::test]
async fn a_concurrent_change_is_a_conflict_not_a_lost_update() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let opened = open_alert(&mut exec, &scope, "net", at(0)?).await?.alert;
    db.borrow_mut().bump_before_update = true;
    let result = apply_event(&mut exec, &scope, opened.id, Event::Acknowledge, at(1)?).await;
    assert!(matches!(result, Err(StoreError::Conflict)));
    db.borrow_mut().bump_before_update = false;
    let stored = get_alert(&mut exec, &scope, opened.id).await?;
    assert_eq!(stored.state.phase, Phase::Open);
    assert_eq!(stored.acknowledged_at, None);
    Ok(())
}


#[tokio::test]
async fn another_tenant_cannot_read_or_change_an_alert() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let mine = open_alert(&mut exec, &acme, "same", at(0)?).await?.alert;
    let theirs = open_alert(&mut exec, &other, "same", at(0)?).await?.alert;
    assert!(matches!(
        get_alert(&mut exec, &other, mine.id + theirs.id + 1).await,
        Err(StoreError::NotFound)
    ));
    let other_view = open_alerts(&mut exec, &other, 1).await?;
    assert_eq!(other_view.len(), 1);
    assert_eq!(other_view.first().map(|alert| alert.id), Some(theirs.id));
    let foreign_change = apply_event(&mut exec, &other, mine.id + theirs.id + 1, Event::Resolve, at(1)?).await;
    assert!(matches!(foreign_change, Err(StoreError::NotFound)));
    let note = record_notification(&mut exec, &other, mine.id + theirs.id + 1, "mail", &Outcome::Sent, at(1)?).await;
    assert!(matches!(note, Err(StoreError::NotFound)));
    assert_eq!(get_alert(&mut exec, &acme, mine.id).await?.state.phase, Phase::Open);
    Ok(())
}


#[tokio::test]
async fn notifications_append_one_row_per_attempt() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let alert = open_alert(&mut exec, &scope, "n", at(0)?).await?.alert;
    let long = "x".repeat(MAX_REASON_LEN + 1);
    let first = record_notification(&mut exec, &scope, alert.id, "mail", &Outcome::Sent, at(1)?).await?;
    let second = record_notification(&mut exec, &scope, alert.id, "hook", &Outcome::Failed { reason: long }, at(LATER)?).await?;
    assert_eq!((first, second), (1, SECOND_SEQ));
    let rows = &db.borrow().notifications;
    let sent = rows.first().ok_or("no row")?;
    let failed = rows.get(1).ok_or("no row")?;
    assert_eq!(
        (sent.tenant.as_str(), sent.alert, sent.channel.as_str(), sent.outcome.as_str()),
        ("acme", alert.id, "mail", "sent")
    );
    assert_eq!((sent.reason.clone(), failed.outcome.as_str(), failed.seq), (None, "failed", SECOND_SEQ));
    assert_eq!(failed.reason.as_ref().map(String::len), Some(MAX_REASON_LEN));
    assert_eq!(failed.channel, "hook");
    Ok(())
}


#[tokio::test]
async fn inputs_are_bounded() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let long = "f".repeat(MAX_FINGERPRINT_BYTES + 1);
    for fingerprint in ["", "a\nb", long.as_str()] {
        let refused = open_alert(&mut exec, &scope, fingerprint, at(0)?).await;
        assert!(matches!(refused, Err(StoreError::InvalidFingerprint { .. })), "{fingerprint:?}");
    }
    let longest = "f".repeat(MAX_FINGERPRINT_BYTES);
    open_alert(&mut exec, &scope, &longest, at(0)?).await?;
    let alert = open_alert(&mut exec, &scope, "ok", at(0)?).await?.alert;
    let name = "c".repeat(MAX_CHANNEL_NAME_BYTES + 1);
    for channel in ["", "a\tb", name.as_str()] {
        let refused = record_notification(&mut exec, &scope, alert.id, channel, &Outcome::Sent, at(0)?).await;
        assert!(matches!(refused, Err(StoreError::InvalidChannel { .. })), "{channel:?}");
    }
    for limit in [0, MAX_OPEN_ALERTS + 1] {
        let refused = open_alerts(&mut exec, &scope, limit).await;
        assert!(matches!(refused, Err(StoreError::LimitOutOfRange { .. })), "{limit}");
    }
    assert_eq!(open_alerts(&mut exec, &scope, MAX_OPEN_ALERTS).await?.len(), TWO_ALERTS);
    Ok(())
}


#[tokio::test]
async fn open_alerts_skips_resolved_alerts() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let done = open_alert(&mut exec, &scope, "done", at(0)?).await?.alert;
    open_alert(&mut exec, &scope, "live", at(1)?).await?;
    apply_event(&mut exec, &scope, done.id, Event::Resolve, at(LATER)?).await?;
    let live = open_alerts(&mut exec, &scope, MAX_OPEN_ALERTS).await?;
    assert_eq!(live.iter().map(|alert| alert.fingerprint.as_str()).collect::<Vec<_>>(), ["live"]);
    Ok(())
}


#[tokio::test]
async fn every_statement_is_bound_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let db = new_db();
    let mut exec = exec_for(&db);
    let scope = tenant_scope("acme")?;
    let alert = open_alert(&mut exec, &scope, "t", at(0)?).await?.alert;
    apply_event(&mut exec, &scope, alert.id, Event::Acknowledge, at(1)?).await?;
    record_notification(&mut exec, &scope, alert.id, "mail", &Outcome::Sent, at(1)?).await?;
    open_alerts(&mut exec, &scope, 1).await?;
    let log = &db.borrow().log;
    assert_eq!(log.len(), STATEMENTS);
    log.iter().for_each(|(tenant, statement)| {
        assert_eq!(tenant, "acme");
        assert!(
            statement.sql.contains("tenant = $1") || statement.sql.contains("VALUES ($1"),
            "{}",
            statement.sql
        );
    });
    Ok(())
}


#[tokio::test]
async fn a_malformed_answer_is_an_error() -> Result<(), Box<dyn Error>> {
    let scope = tenant_scope("acme")?;
    let mut empty = |_scope: &TenantScope, _statement: Statement| ready(Ok::<Vec<Row>, StoreError>(Vec::new()));
    assert!(matches!(open_alert(&mut empty, &scope, "x", at(0)?).await, Err(StoreError::NotFound)));
    let stamp = at(0)?;
    let mut no_flag = |_scope: &TenantScope, _statement: Statement| {
        let row = vec![
            Cell::Int(1),
            Cell::Text("x".to_owned()),
            Cell::Text("open".to_owned()),
            Cell::Int(0),
            Cell::Int(1),
            Cell::Int(0),
            Cell::Time(Some(stamp)),
            Cell::Time(None),
            Cell::Time(None),
        ];
        ready(Ok::<Vec<Row>, StoreError>(vec![row]))
    };
    assert!(matches!(
        open_alert(&mut no_flag, &scope, "x", at(0)?).await,
        Err(StoreError::BadRow { .. })
    ));
    Ok(())
}


#[test]
fn the_migration_is_valid_tenant_first_and_the_log_is_append_only() -> Result<(), Box<dyn Error>> {
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("PRIMARY KEY (tenant, id)") && sql.contains("PRIMARY KEY (tenant, seq)"));
    let source = include_str!("../src/store.rs");
    assert!(!source.contains("UPDATE oncall_notifications") && !source.contains("DELETE FROM"));
    Ok(())
}

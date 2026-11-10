mod actions;
mod appends;
mod memory;
mod rows;
mod types;


use alerts::types::RowFuture;
use cases::error::CaseStoreError;
use cases::model::{
    Case, CaseEvent, CaseEventKind, CaseStatus, Comment, IocStatus, Observable, ObservableKind, Pap, Resolution, Severity, Task, TaskStatus, Tlp,
};
use cases::store::{
    add_comment, add_observable, apply_case_action, attach_alert, case_doc, create_case, get_case, list_cases, APPLY_SQL, ATTACH_SQL, COMMENT_SQL,
    FIRST_SQL, GET_SQL, INSERT_SQL, MAX_DESCRIPTION_CHARS, MAX_ID_CHARS, MAX_NAME_CHARS, MAX_PAGE_SIZE, MAX_TASKS, MAX_TASK_LOG, MAX_TITLE_CHARS,
    MIGRATIONS, MIGRATION_NAMESPACE, NEXT_SQL, OBSERVABLE_SQL,
};
use cases::stored::{CaseCursor, CasePage, Stored};
use cases::transition::CaseAction;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_scope, TenantScope};
use memory::{handle, lock, Db, Forced};
use std::future::ready;
use types::{Setter, TestResult};


const NOW: i64 = 1_700_000_000;


const ALERT: &str = "2d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const OTHER_ALERT: &str = "3d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const FIVE: usize = 5;


pub const TWO: usize = 2;


pub const THREE: usize = 3;


pub const FOUR: usize = 4;


const FAR_CREATED: i64 = 1_000;


const HALF: i64 = 2;


const OTHER_CREATED: i64 = 100;


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub fn case(tenant: &str, id: &str, created: i64) -> Case {
    Case {
        id: id.to_owned(),
        tenant: tenant.to_owned(),
        title: "Suspicious logon".to_owned(),
        description: Some("details".to_owned()),
        severity: Severity::High,
        status: CaseStatus::New,
        resolution: None,
        assignee: Some("alice".to_owned()),
        template: Some("incident".to_owned()),
        case_type: Some("malware".to_owned()),
        created_at: created,
        updated_at: created,
        tasks: vec![Task {
            title: "triage".to_owned(),
            status: TaskStatus::Todo,
            due: Some(NOW),
            log: Vec::new(),
        }],
        observables: Vec::new(),
        comments: Vec::new(),
        history: Vec::new(),
    }
}


pub fn observable(kind: ObservableKind, value: &str) -> Observable {
    Observable {
        kind,
        value: value.to_owned(),
        tlp: Tlp::Amber,
        pap: Pap::Green,
        ioc: IocStatus::Suspected,
        source: "analyst".to_owned(),
    }
}


pub fn comment(text: &str) -> Comment {
    Comment {
        author: "alice".to_owned(),
        at: NOW,
        text: text.to_owned(),
    }
}


pub fn know_alert(db: &Db, tenant: &str, id: &str) {
    lock(&db.known_alerts).entry(tenant.to_owned()).or_default().insert(id.to_owned());
}


pub fn sent(db: &Db) -> usize {
    lock(&db.statements).len()
}


pub fn force(db: &Db, forced: Forced) {
    lock(&db.forced).push_back(forced);
}


pub fn stored_case(db: &Db, tenant: &str, id: &str) -> Option<Case> {
    lock(&db.tenants)
        .get(tenant)
        .and_then(|table| table.get(id))
        .map(|entry| entry.case.clone())
}


#[test]
fn every_statement_is_scoped_to_the_tenant() -> TestResult {
    [FIRST_SQL, NEXT_SQL, GET_SQL, APPLY_SQL, COMMENT_SQL, OBSERVABLE_SQL, ATTACH_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("tenant = $1"), "{sql}"));
    assert!(INSERT_SQL.contains("SELECT $1::text, doc.id"));
    assert!(INSERT_SQL.contains("ON CONFLICT (tenant, id) DO NOTHING"));
    assert!(ATTACH_SQL.contains("FROM alerts WHERE tenant = $1"));
    [FIRST_SQL, NEXT_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("ORDER BY cases.created_at DESC, cases.id DESC")));
    check_embedded(&MIGRATIONS)?;
    check_namespace(MIGRATION_NAMESPACE)?;
    assert!(MIGRATIONS.iter().all(|migration| migration.sql.contains("PRIMARY KEY (tenant, id)")));
    assert!(MIGRATIONS
        .iter()
        .all(|migration| migration.sql.contains("cases (tenant, created_at DESC, id DESC)")));
    Ok(())
}


#[tokio::test]
async fn create_then_get_round_trips_and_refuses_a_duplicate() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let new = case("acme", "c1", NOW);
    create_case(&exec, &scope, &new).await?;
    let found = get_case(&exec, &scope, "c1").await?.ok_or("missing")?;
    assert_eq!(
        found,
        Stored {
            case: new.clone(),
            version: 1
        }
    );
    assert!(matches!(create_case(&exec, &scope, &new).await, Err(CaseStoreError::Exists)));
    assert!(get_case(&exec, &scope, "c2").await?.is_none());
    assert_eq!(case_doc(&new).get("tasks").map(|tasks| tasks.is_array()), Some(true));
    Ok(())
}


#[tokio::test]
async fn a_case_without_optional_fields_round_trips() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let mut bare = case("acme", "c1", NOW);
    bare.description = None;
    bare.assignee = None;
    bare.template = None;
    bare.case_type = None;
    bare.tasks.clear();
    create_case(&exec, &scope, &bare).await?;
    assert_eq!(get_case(&exec, &scope, "c1").await?.ok_or("missing")?.case, bare);
    Ok(())
}


#[tokio::test]
async fn another_tenant_cannot_read_list_change_or_attach_with_the_same_id() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    create_case(&exec, &acme, &case("acme", "c1", NOW)).await?;
    know_alert(&db, "acme", ALERT);
    know_alert(&db, "other", OTHER_ALERT);
    assert!(get_case(&exec, &other, "c1").await?.is_none());
    let page = CasePage { after: None, size: FIVE };
    assert!(list_cases(&exec, &other, &page).await?.cases.is_empty());
    let started = apply_case_action(&exec, &other, "c1", CaseAction::Start, "mallory", NOW).await;
    assert!(matches!(started, Err(CaseStoreError::NotFound)));
    assert!(matches!(
        add_comment(&exec, &other, "c1", &comment("x")).await,
        Err(CaseStoreError::NotFound)
    ));
    let seen = add_observable(&exec, &other, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await;
    assert!(matches!(seen, Err(CaseStoreError::NotFound)));
    assert!(matches!(
        attach_alert(&exec, &other, "c1", OTHER_ALERT).await,
        Err(CaseStoreError::NotFound)
    ));
    assert!(matches!(
        attach_alert(&exec, &acme, "c1", OTHER_ALERT).await,
        Err(CaseStoreError::AlertNotFound)
    ));
    assert!(matches!(attach_alert(&exec, &other, "c1", ALERT).await, Err(CaseStoreError::NotFound)));
    let untouched = stored_case(&db, "acme", "c1").ok_or("missing")?;
    assert_eq!(untouched, case("acme", "c1", NOW));
    let linked = lock(&db.tenants)
        .get("acme")
        .and_then(|table| table.get("c1"))
        .map(|entry| entry.alerts.len());
    assert_eq!(linked, Some(0));
    Ok(())
}


#[tokio::test]
async fn a_case_of_another_tenant_or_not_new_is_refused_before_any_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    assert!(matches!(
        create_case(&exec, &scope, &case("other", "c1", NOW)).await,
        Err(CaseStoreError::TenantMismatch)
    ));
    let mutations: Vec<fn(&mut Case)> = vec![
        |case| case.status = CaseStatus::Closed,
        |case| case.resolution = Some(Resolution::Benign),
        |case| case.observables.push(observable(ObservableKind::Ip, "10.0.0.1")),
        |case| case.comments.push(comment("x")),
        |case| {
            case.history.push(CaseEvent {
                kind: CaseEventKind::Started,
                at: NOW,
                actor: "a".to_owned(),
                from: CaseStatus::New,
                to: CaseStatus::InProgress,
            })
        },
    ];
    for mutate in &mutations {
        let mut bad = case("acme", "c1", NOW);
        mutate(&mut bad);
        assert!(matches!(create_case(&exec, &scope, &bad).await, Err(CaseStoreError::NotNew)));
    }
    assert_eq!(sent(&db), 0);
    Ok(())
}


#[tokio::test]
async fn every_text_field_is_bounded_and_refuses_nul_before_any_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let fields: Vec<(&str, usize, bool, Setter)> = vec![
        ("id", MAX_ID_CHARS, true, |case, text| case.id = text),
        ("title", MAX_TITLE_CHARS, true, |case, text| case.title = text),
        ("description", MAX_DESCRIPTION_CHARS, true, |case, text| case.description = Some(text)),
        ("assignee", MAX_NAME_CHARS, true, |case, text| case.assignee = Some(text)),
        ("template", MAX_NAME_CHARS, true, |case, text| case.template = Some(text)),
        ("case_type", MAX_NAME_CHARS, true, |case, text| case.case_type = Some(text)),
        ("task_title", MAX_TITLE_CHARS, true, |case, text| {
            if let Some(task) = case.tasks.first_mut() {
                task.title = text;
            }
        }),
        ("task_actor", MAX_NAME_CHARS, true, |case, text| {
            if let Some(task) = case.tasks.first_mut() {
                task.log.push(cases::model::TaskLogEntry {
                    at: NOW,
                    actor: text,
                    action: cases::model::TaskAction::Created,
                });
            }
        }),
    ];
    for (name, limit, required, set) in &fields {
        let attempt = |text: String| {
            let mut bad = case("acme", "c1", NOW);
            set(&mut bad, text);
            bad
        };
        let long = create_case(&exec, &scope, &attempt("a".repeat(limit + 1))).await;
        assert!(
            matches!(long, Err(CaseStoreError::FieldTooLong { field, .. }) if field.ends_with(name) || *name == "id"),
            "{name}"
        );
        let nul = create_case(&exec, &scope, &attempt("a\0b".to_owned())).await;
        assert!(matches!(nul, Err(CaseStoreError::NulByte { .. })), "{name}");
        let empty = create_case(&exec, &scope, &attempt(String::new())).await;
        assert!(!*required || matches!(empty, Err(CaseStoreError::FieldEmpty { .. })), "{name}");
    }
    assert_eq!(sent(&db), 0);
    let edge = "é".repeat(MAX_TITLE_CHARS);
    let mut fits = case("acme", "c1", NOW);
    fits.title = edge;
    create_case(&exec, &scope, &fits).await?;
    Ok(())
}


#[tokio::test]
async fn counts_and_times_are_checked_against_their_columns() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let mut many = case("acme", "c1", NOW);
    let task = many.tasks.first().cloned().ok_or("task")?;
    many.tasks = vec![task.clone(); MAX_TASKS + 1];
    assert!(matches!(create_case(&exec, &scope, &many).await, Err(CaseStoreError::TooMany { .. })));
    let mut log = task.clone();
    log.log = vec![
        cases::model::TaskLogEntry {
            at: NOW,
            actor: "a".to_owned(),
            action: cases::model::TaskAction::Created,
        };
        MAX_TASK_LOG + 1
    ];
    many.tasks = vec![log];
    assert!(matches!(create_case(&exec, &scope, &many).await, Err(CaseStoreError::TooMany { .. })));
    let mut early = case("acme", "c1", -1);
    assert!(matches!(
        create_case(&exec, &scope, &early).await,
        Err(CaseStoreError::BadTime { field: "created_at" })
    ));
    early.created_at = 0;
    early.updated_at = -1;
    assert!(matches!(
        create_case(&exec, &scope, &early).await,
        Err(CaseStoreError::BadTime { field: "updated_at" })
    ));
    assert_eq!(sent(&db), 0);
    let mut full = case("acme", "c1", 0);
    full.tasks = vec![task; MAX_TASKS];
    create_case(&exec, &scope, &full).await?;
    Ok(())
}


#[tokio::test]
async fn list_pages_newest_first_without_gaps_and_stays_in_the_tenant() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    create_case(&exec, &other, &case("other", "z", NOW + OTHER_CREATED)).await?;
    for index in 0..FIVE {
        create_case(&exec, &scope, &case("acme", &format!("c{index}"), NOW + (index as i64) / HALF)).await?;
    }
    let first = list_cases(&exec, &scope, &CasePage { after: None, size: TWO }).await?;
    let second = list_cases(
        &exec,
        &scope,
        &CasePage {
            after: first.next.clone(),
            size: TWO,
        },
    )
    .await?;
    let third = list_cases(
        &exec,
        &scope,
        &CasePage {
            after: second.next.clone(),
            size: TWO,
        },
    )
    .await?;
    let ids: Vec<String> = [&first, &second, &third]
        .iter()
        .flat_map(|page| page.cases.iter().map(|stored| stored.case.id.clone()))
        .collect();
    assert_eq!(ids, vec!["c4", "c3", "c2", "c1", "c0"]);
    assert!(first.next.is_some() && second.next.is_some() && third.next.is_none());
    let forged = CaseCursor {
        created_at: NOW + FAR_CREATED,
        id: "z".to_owned(),
    };
    let under_other = list_cases(
        &exec,
        &other,
        &CasePage {
            after: Some(forged),
            size: FIVE,
        },
    )
    .await?;
    assert_eq!(under_other.cases.len(), 1);
    assert!(under_other.cases.iter().all(|stored| stored.case.tenant == "other"));
    let exact = list_cases(&exec, &scope, &CasePage { after: None, size: FIVE }).await?;
    assert!(exact.next.is_none() && exact.cases.len() == FIVE);
    Ok(())
}


#[tokio::test]
async fn page_size_and_cursor_are_checked() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let zero = list_cases(&exec, &scope, &CasePage { after: None, size: 0 }).await;
    assert!(matches!(zero, Err(CaseStoreError::BadPageSize { .. })));
    let huge = list_cases(
        &exec,
        &scope,
        &CasePage {
            after: None,
            size: MAX_PAGE_SIZE + 1,
        },
    )
    .await;
    assert!(matches!(huge, Err(CaseStoreError::BadPageSize { .. })));
    let negative = CaseCursor {
        created_at: -1,
        id: "a".to_owned(),
    };
    assert!(matches!(
        list_cases(
            &exec,
            &scope,
            &CasePage {
                after: Some(negative),
                size: 1
            }
        )
        .await,
        Err(CaseStoreError::BadTime { .. })
    ));
    let nul = CaseCursor {
        created_at: 0,
        id: "a\0".to_owned(),
    };
    assert!(matches!(
        list_cases(&exec, &scope, &CasePage { after: Some(nul), size: 1 }).await,
        Err(CaseStoreError::NulByte { .. })
    ));
    assert_eq!(sent(&db), 0);
    list_cases(
        &exec,
        &scope,
        &CasePage {
            after: None,
            size: MAX_PAGE_SIZE,
        },
    )
    .await?;
    Ok(())
}

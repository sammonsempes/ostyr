use crate::case;
use crate::memory::{lock, Db, Forced};
use crate::types::TestResult;
use crate::{executor, force, know_alert, sent, stored_case, ALERT, NOW, OTHER_ALERT};
use cases::error::CaseStoreError;
use cases::model::{CaseEvent, CaseEventKind, CaseStatus};
use cases::store::{
    attach_alert, check_link_page, create_case, list_links, ATTACH_SQL, LINKS_AFTER_SQL, LINKS_SQL, MAX_HISTORY, MAX_ID_CHARS, MAX_NAME_CHARS,
    MAX_PAGE_SIZE,
};
use cases::stored::{AlertLinkItem, LinkPage};
use core_pg::scope::tenant_scope;


const ACTOR: &str = "analyst1";


const LATER: i64 = NOW + 5;


const TOTAL: usize = 120;


const PAGE: usize = 50;


const LAST_PAGE: usize = TOTAL - 2 * PAGE;


fn alert_number(index: usize) -> String {
    format!("{index:064x}")
}


fn first_page(size: usize) -> LinkPage {
    LinkPage { after: None, size }
}


#[tokio::test]
async fn a_new_link_is_attributed_on_its_row_and_a_replay_keeps_the_first() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    know_alert(&db, "acme", ALERT);
    assert!(attach_alert(&exec, &scope, "c1", ALERT, (ACTOR, LATER)).await?);
    assert!(!attach_alert(&exec, &scope, "c1", ALERT, ("other", LATER + 1)).await?);
    let listed = list_links(&exec, &scope, "c1", &first_page(PAGE)).await?;
    assert_eq!(
        listed.alerts,
        vec![AlertLinkItem {
            alert_id: ALERT.to_owned(),
            linked_by: Some(ACTOR.to_owned()),
            linked_at: Some(LATER),
        }]
    );
    assert!(stored_case(&db, "acme", "c1").ok_or("missing")?.history.is_empty());
    let version = lock(&db.tenants).get("acme").and_then(|table| table.get("c1")).map(|entry| entry.version);
    assert_eq!(version, Some(1));
    Ok(())
}


#[tokio::test]
async fn a_full_history_does_not_refuse_a_link() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    know_alert(&db, "acme", ALERT);
    know_alert(&db, "acme", OTHER_ALERT);
    let filler = CaseEvent {
        kind: CaseEventKind::AlertLinked,
        at: NOW,
        actor: ACTOR.to_owned(),
        from: CaseStatus::New,
        to: CaseStatus::New,
        alert_id: None,
    };
    lock(&db.tenants)
        .get_mut("acme")
        .and_then(|table| table.get_mut("c1"))
        .ok_or("missing")?
        .case
        .history
        .resize(MAX_HISTORY, filler);
    assert!(attach_alert(&exec, &scope, "c1", OTHER_ALERT, (ACTOR, NOW)).await?);
    assert_eq!(stored_case(&db, "acme", "c1").ok_or("missing")?.history.len(), MAX_HISTORY);
    Ok(())
}


#[tokio::test]
async fn an_unattributed_row_lists_as_unknown_and_a_bad_time_cell_is_a_typed_error() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    lock(&db.tenants)
        .get_mut("acme")
        .and_then(|table| table.get_mut("c1"))
        .ok_or("missing")?
        .alerts
        .insert(ALERT.to_owned(), None);
    let listed = list_links(&exec, &scope, "c1", &first_page(PAGE)).await?;
    assert_eq!(
        listed.alerts.first().map(|link| (link.linked_by.clone(), link.linked_at)),
        Some((None, None))
    );
    force(&db, Forced::Rows(vec![["c1", ALERT, "alice", "soon"].map(str::to_owned).to_vec()]));
    assert!(matches!(
        list_links(&exec, &scope, "c1", &first_page(1)).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    Ok(())
}


#[tokio::test]
async fn a_lost_race_on_a_new_link_reads_as_not_added() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    know_alert(&db, "acme", ALERT);
    force(&db, Forced::Rows(vec![["1", "1", "0", "0", "0"].map(str::to_owned).to_vec()]));
    assert!(!attach_alert(&exec, &scope, "c1", ALERT, (ACTOR, NOW)).await?);
    Ok(())
}


#[tokio::test]
async fn the_actor_and_the_time_are_checked_before_any_statement() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    know_alert(&db, "acme", ALERT);
    let before = sent(&db);
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, ("", NOW)).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, (&"a".repeat(MAX_NAME_CHARS + 1), NOW)).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, (ACTOR, -1)).await,
        Err(CaseStoreError::BadTime { .. })
    ));
    assert_eq!(sent(&db), before);
    Ok(())
}


#[tokio::test]
async fn links_page_by_alert_id_without_duplicate_or_gap() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    for index in (0..TOTAL).rev() {
        know_alert(&db, "acme", &alert_number(index));
        assert!(attach_alert(&exec, &scope, "c1", &alert_number(index), (ACTOR, NOW)).await?);
    }
    let first = list_links(&exec, &scope, "c1", &first_page(PAGE)).await?;
    let second = list_links(
        &exec,
        &scope,
        "c1",
        &LinkPage {
            after: first.next.clone(),
            size: PAGE,
        },
    )
    .await?;
    let third = list_links(
        &exec,
        &scope,
        "c1",
        &LinkPage {
            after: second.next.clone(),
            size: PAGE,
        },
    )
    .await?;
    assert_eq!((first.alerts.len(), second.alerts.len(), third.alerts.len()), (PAGE, PAGE, LAST_PAGE));
    assert!(first.next.is_some() && second.next.is_some() && third.next.is_none());
    let all: Vec<String> = [first, second, third]
        .into_iter()
        .flat_map(|page| page.alerts)
        .map(|link| link.alert_id)
        .collect();
    assert_eq!(all, (0..TOTAL).map(alert_number).collect::<Vec<String>>());
    Ok(())
}


#[tokio::test]
async fn an_empty_case_lists_nothing_and_a_missing_or_foreign_case_is_not_found() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("globex")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let empty = list_links(&exec, &scope, "c1", &first_page(PAGE)).await?;
    assert!(empty.alerts.is_empty() && empty.next.is_none());
    let past_end = list_links(
        &exec,
        &scope,
        "c1",
        &LinkPage {
            after: Some(ALERT.to_owned()),
            size: PAGE,
        },
    )
    .await?;
    assert!(past_end.alerts.is_empty());
    assert!(matches!(
        list_links(&exec, &scope, "none", &first_page(PAGE)).await,
        Err(CaseStoreError::NotFound)
    ));
    assert!(matches!(
        list_links(&exec, &other, "c1", &first_page(PAGE)).await,
        Err(CaseStoreError::NotFound)
    ));
    Ok(())
}


#[tokio::test]
async fn a_bad_page_or_id_is_refused_before_any_statement() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let before = sent(&db);
    assert!(matches!(
        list_links(&exec, &scope, "c1", &first_page(0)).await,
        Err(CaseStoreError::BadPageSize { .. })
    ));
    assert!(matches!(
        list_links(&exec, &scope, "c1", &first_page(MAX_PAGE_SIZE + 1)).await,
        Err(CaseStoreError::BadPageSize { .. })
    ));
    assert!(matches!(
        list_links(
            &exec,
            &scope,
            "c1",
            &LinkPage {
                after: Some("A".repeat(MAX_ID_CHARS)),
                size: 1
            }
        )
        .await,
        Err(CaseStoreError::BadCursor)
    ));
    assert!(matches!(
        list_links(&exec, &scope, "", &first_page(1)).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert!(check_link_page(&first_page(MAX_PAGE_SIZE)).is_ok());
    assert_eq!(sent(&db), before);
    Ok(())
}


#[tokio::test]
async fn a_failing_or_malformed_store_answer_is_a_typed_error() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    force(&db, Forced::Fail);
    assert!(matches!(
        list_links(&exec, &scope, "c1", &first_page(1)).await,
        Err(CaseStoreError::Pg(_))
    ));
    force(&db, Forced::Rows(vec![vec!["c1".to_owned()]]));
    assert!(matches!(
        list_links(&exec, &scope, "c1", &first_page(1)).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    Ok(())
}


#[test]
fn every_link_statement_is_scoped_to_the_tenant_and_the_case() -> TestResult {
    [LINKS_SQL, LINKS_AFTER_SQL].iter().for_each(|sql| {
        assert!(sql.contains("cases.tenant = $1 AND cases.id = $2::text"), "{sql}");
        assert!(
            sql.contains("case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id"),
            "{sql}"
        );
        assert!(sql.contains("ORDER BY case_alerts.alert_id"), "{sql}");
    });
    assert!(LINKS_AFTER_SQL.contains("case_alerts.alert_id > $3::text"));
    [LINKS_SQL, LINKS_AFTER_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("case_alerts.linked_by") && sql.contains("case_alerts.linked_at")));
    assert!(ATTACH_SQL.contains("INSERT INTO case_alerts (tenant, case_id, alert_id, linked_by, linked_at)"));
    assert!(ATTACH_SQL.contains("SELECT $1::text, $2::text, $3::text, $6::text, $5::text::bigint"));
    assert!(!ATTACH_SQL.contains("history"));
    Ok(())
}

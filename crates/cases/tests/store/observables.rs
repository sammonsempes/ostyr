use crate::case;
use crate::memory::{Db, Forced};
use crate::types::TestResult;
use crate::{executor, force, observable, sent, NOW, TWO};
use cases::error::CaseStoreError;
use cases::model::ObservableKind;
use cases::store::{
    add_observable, create_case, list_observables, record_seen, MAX_ID_CHARS, MIGRATIONS, OBSERVABLES_SQL, OBSERVABLE_SQL, SEEN_IN_LIMIT, SEEN_IN_SQL,
};
use cases::stored::SeenObservable;
use core_pg::scope::tenant_scope;


const INDEXED: usize = 4;


fn empty_item() -> SeenObservable {
    SeenObservable {
        observable: observable(ObservableKind::Domain, "example.com"),
        seen_in: Vec::new(),
        seen_in_truncated: false,
    }
}


fn row(ordinal: &str, other: &str) -> Vec<String> {
    ["c1", ordinal, other].map(str::to_owned).to_vec()
}


#[test]
fn the_seen_in_statements_are_scoped_to_the_tenant_and_use_containment() -> TestResult {
    assert!(SEEN_IN_SQL.contains("found.tenant = $1 AND found.kind = mine.item->>'kind'"));
    assert!(SEEN_IN_SQL.contains("found.case_id <> me.id"));
    assert!(SEEN_IN_SQL.contains("me.tenant = $1 AND me.id = $2::text"));
    assert!(SEEN_IN_SQL.contains("ORDER BY found.case_id LIMIT $3::text::bigint"));
    assert!(!SEEN_IN_SQL.contains("@>"));
    assert!(OBSERVABLES_SQL.contains("tenant = $1 AND id = $2::text"));
    assert!(OBSERVABLE_SQL.contains("INSERT INTO case_observable_index (tenant, kind, value_digest, case_id)"));
    assert!(OBSERVABLE_SQL.contains("SELECT $1, ($3::text::jsonb)->>'kind'"));
    assert!(OBSERVABLE_SQL.contains("$2::text FROM added"));
    assert!(MIGRATIONS
        .iter()
        .any(|migration| migration.sql.contains("PRIMARY KEY (tenant, kind, value_digest, case_id)")));
    assert!(MIGRATIONS.iter().all(|migration| !migration.sql.contains("USING gin")));
    Ok(())
}


#[tokio::test]
async fn the_seen_in_list_names_the_other_cases_of_the_tenant_only() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("globex")?;
    for id in ["c1", "c2", "c3", "c4"] {
        create_case(&exec, &scope, &case("acme", id, NOW)).await?;
    }
    create_case(&exec, &other, &case("globex", "g1", NOW)).await?;
    let shared = observable(ObservableKind::Domain, "example.com");
    for id in ["c1", "c2", "c3"] {
        add_observable(&exec, &scope, id, &shared).await?;
    }
    add_observable(&exec, &other, "g1", &shared).await?;
    add_observable(&exec, &scope, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await?;
    add_observable(&exec, &scope, "c4", &observable(ObservableKind::Url, "example.com")).await?;
    let listed = list_observables(&exec, &scope, "c1").await?;
    let seen: Vec<(&str, Vec<&str>)> = listed
        .iter()
        .map(|item| (item.observable.value.as_str(), item.seen_in.iter().map(String::as_str).collect()))
        .collect();
    assert_eq!(seen, vec![("example.com", vec!["c2", "c3"]), ("10.0.0.1", vec![])]);
    assert!(listed.iter().all(|item| !item.seen_in_truncated));
    assert!(list_observables(&exec, &other, "g1").await?.iter().all(|item| item.seen_in.is_empty()));
    Ok(())
}


#[tokio::test]
async fn twenty_one_cases_holding_one_value_list_twenty_and_truncate() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let shared = observable(ObservableKind::Domain, "example.com");
    for index in 0..=SEEN_IN_LIMIT + 1 {
        let id = format!("c{index:03}");
        create_case(&exec, &scope, &case("acme", &id, NOW)).await?;
        add_observable(&exec, &scope, &id, &shared).await?;
    }
    let listed = list_observables(&exec, &scope, "c000").await?;
    let item = listed.first().ok_or("no item")?;
    assert_eq!(item.seen_in.len(), SEEN_IN_LIMIT);
    assert!(item.seen_in_truncated);
    assert_eq!(item.seen_in.first().map(String::as_str), Some("c001"));
    Ok(())
}


#[tokio::test]
async fn exactly_twenty_others_is_not_truncated() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let shared = observable(ObservableKind::Domain, "example.com");
    for index in 0..=SEEN_IN_LIMIT {
        let id = format!("c{index:03}");
        create_case(&exec, &scope, &case("acme", &id, NOW)).await?;
        add_observable(&exec, &scope, &id, &shared).await?;
    }
    let listed = list_observables(&exec, &scope, "c000").await?;
    let item = listed.first().ok_or("no item")?;
    assert_eq!((item.seen_in.len(), item.seen_in_truncated), (SEEN_IN_LIMIT, false));
    Ok(())
}


#[tokio::test]
async fn a_case_without_observables_costs_one_statement_and_a_missing_case_is_not_found() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let before = sent(&db);
    assert!(list_observables(&exec, &scope, "c1").await?.is_empty());
    assert_eq!(sent(&db), before + 1);
    assert!(matches!(list_observables(&exec, &scope, "none").await, Err(CaseStoreError::NotFound)));
    add_observable(&exec, &scope, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await?;
    let again = sent(&db);
    list_observables(&exec, &scope, "c1").await?;
    assert_eq!(sent(&db), again + TWO);
    Ok(())
}


#[tokio::test]
async fn a_bad_id_is_refused_before_any_sql_and_store_failures_propagate() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    add_observable(&exec, &scope, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await?;
    let before = sent(&db);
    assert!(matches!(
        list_observables(&exec, &scope, "").await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert!(matches!(
        list_observables(&exec, &scope, &"x".repeat(MAX_ID_CHARS + 1)).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    assert_eq!(sent(&db), before);
    force(&db, Forced::Fail);
    assert!(matches!(list_observables(&exec, &scope, "c1").await, Err(CaseStoreError::Pg(_))));
    force(&db, Forced::Rows(vec![vec!["{".to_owned()]]));
    assert!(matches!(list_observables(&exec, &scope, "c1").await, Err(CaseStoreError::BadDocument(_))));
    force(&db, Forced::Rows(vec![Vec::new()]));
    assert!(matches!(list_observables(&exec, &scope, "c1").await, Err(CaseStoreError::BadRow { .. })));
    let one = serde_json::to_string(&[observable(ObservableKind::Ip, "10.0.0.1")])?;
    force(&db, Forced::Rows(vec![vec![one]]));
    force(&db, Forced::Fail);
    assert!(matches!(list_observables(&exec, &scope, "c1").await, Err(CaseStoreError::Pg(_))));
    Ok(())
}


#[test]
fn a_seen_row_is_filed_under_its_ordinal_and_odd_rows_change_nothing() -> TestResult {
    let mut items = vec![empty_item()];
    record_seen(&mut items, &row("1", "c2"))?;
    record_seen(&mut items, &row("0", "c3"))?;
    record_seen(&mut items, &row("2", "c3"))?;
    record_seen(&mut items, &row("1", ""))?;
    assert_eq!(items.first().map(|item| item.seen_in.clone()), Some(vec!["c2".to_owned()]));
    assert!(matches!(record_seen(&mut items, &row("x", "c2")), Err(CaseStoreError::BadNumber { .. })));
    assert!(matches!(
        record_seen(&mut items, &["c1".to_owned()].to_vec()),
        Err(CaseStoreError::BadRow { .. })
    ));
    assert!(matches!(
        record_seen(&mut items, &["c1".to_owned(), "1".to_owned()].to_vec()),
        Err(CaseStoreError::BadRow { .. })
    ));
    Ok(())
}


fn answer(found: &str, added: &str, size: &str, same: &str) -> Forced {
    Forced::Rows(vec![[found, added, size, same].map(str::to_owned).to_vec()])
}


#[tokio::test]
async fn a_write_that_lost_a_race_is_retried_once_and_never_reads_as_a_duplicate() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let new = observable(ObservableKind::Ip, "10.0.0.1");
    force(&db, answer("1", "0", "499", "0"));
    force(&db, answer("1", "1", "499", "0"));
    assert!(add_observable(&exec, &scope, "c1", &new).await?);
    force(&db, answer("1", "0", "499", "0"));
    force(&db, answer("1", "0", "500", "0"));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &new).await,
        Err(CaseStoreError::Full { what: "observables", .. })
    ));
    force(&db, answer("1", "0", "499", "0"));
    force(&db, answer("1", "0", "499", "1"));
    assert!(!add_observable(&exec, &scope, "c1", &new).await?);
    force(&db, answer("1", "0", "499", "0"));
    force(&db, answer("1", "0", "499", "0"));
    assert!(matches!(add_observable(&exec, &scope, "c1", &new).await, Err(CaseStoreError::Conflict)));
    force(&db, answer("1", "0", "500", "1"));
    assert!(!add_observable(&exec, &scope, "c1", &new).await?);
    force(&db, answer("0", "0", "0", "0"));
    assert!(matches!(add_observable(&exec, &scope, "c1", &new).await, Err(CaseStoreError::NotFound)));
    force(&db, Forced::Rows(vec![["1", "0", "1"].map(str::to_owned).to_vec()]));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &new).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    Ok(())
}


#[tokio::test]
async fn the_lookup_index_agrees_with_the_stored_arrays_through_adds_duplicates_and_refusals() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("globex")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    create_case(&exec, &scope, &case("acme", "c2", NOW)).await?;
    create_case(&exec, &other, &case("globex", "c1", NOW)).await?;
    let shared = observable(ObservableKind::Domain, "example.com");
    add_observable(&exec, &scope, "c1", &shared).await?;
    add_observable(&exec, &scope, "c1", &shared).await?;
    add_observable(&exec, &scope, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await?;
    add_observable(&exec, &scope, "c2", &shared).await?;
    add_observable(&exec, &other, "c1", &shared).await?;
    assert!(add_observable(&exec, &scope, "none", &shared).await.is_err());
    let indexed = db.index.lock().map_err(|_source| "poisoned")?.len();
    let stored: usize = db
        .tenants
        .lock()
        .map_err(|_source| "poisoned")?
        .values()
        .flat_map(|table| table.values())
        .map(|entry| entry.case.observables.len())
        .sum();
    assert_eq!((indexed, stored), (INDEXED, INDEXED));
    Ok(())
}

use crate::memory::{row_of, Db, Entry, Forced};
use crate::types::TestResult;
use crate::{case, comment, executor, force, observable, ALERT, NOW, SIX};
use alerts::types::Row;
use cases::error::CaseStoreError;
use cases::model::ObservableKind;
use cases::store::{add_comment, add_observable, attach_alert, create_case, get_case, list_cases, SEVERITY_COLUMN, TASKS_COLUMN, VERSION_COLUMN};
use cases::stored::CasePage;
use cases::transition::CaseAction;
use core_pg::scope::tenant_scope;
use std::collections::BTreeSet;


pub fn good_row() -> Result<Row, Box<dyn std::error::Error>> {
    let entry = Entry {
        case: case("acme", "c1", NOW),
        version: 1,
        alerts: BTreeSet::new(),
    };
    Ok(row_of(&entry)?)
}


pub fn with(column: usize, value: &str) -> Result<Row, Box<dyn std::error::Error>> {
    let mut row = good_row()?;
    *row.get_mut(column).ok_or("column")? = value.to_owned();
    Ok(row)
}


#[tokio::test]
async fn a_malformed_stored_row_is_a_typed_error() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let short: Row = good_row()?.into_iter().take(TASKS_COLUMN).collect();
    force(&db, Forced::Rows(vec![short]));
    assert!(matches!(get_case(&exec, &scope, "c1").await, Err(CaseStoreError::BadRow { .. })));
    force(&db, Forced::Rows(vec![with(VERSION_COLUMN, "x")?]));
    assert!(matches!(get_case(&exec, &scope, "c1").await, Err(CaseStoreError::BadNumber { .. })));
    force(&db, Forced::Rows(vec![with(SEVERITY_COLUMN, "bogus")?]));
    assert!(matches!(get_case(&exec, &scope, "c1").await, Err(CaseStoreError::BadLabels(_))));
    force(&db, Forced::Rows(vec![with(TASKS_COLUMN, "oops")?]));
    assert!(matches!(get_case(&exec, &scope, "c1").await, Err(CaseStoreError::BadDocument(_))));
    force(&db, Forced::Rows(vec![with(TASKS_COLUMN, "[]")?, with(TASKS_COLUMN, "[")?]));
    let page = CasePage { after: None, size: 1 };
    assert!(matches!(list_cases(&exec, &scope, &page).await, Err(CaseStoreError::BadDocument(_))));
    Ok(())
}


#[tokio::test]
async fn a_malformed_answer_is_a_typed_error() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let new = observable(ObservableKind::Ip, "10.0.0.1");
    force(&db, Forced::Rows(Vec::new()));
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &comment("x")).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    force(&db, Forced::Rows(vec![vec!["1".to_owned(), "x".to_owned(), "0".to_owned()]]));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &new).await,
        Err(CaseStoreError::BadNumber { .. })
    ));
    force(&db, Forced::Rows(vec![vec!["1".to_owned()]]));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &new).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    force(&db, Forced::Rows(Vec::new()));
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::BadRow { .. })
    ));
    force(
        &db,
        Forced::Rows(vec![vec!["1".to_owned(); SIX]
            .into_iter()
            .enumerate()
            .map(|(index, cell)| if index == 1 { "x".to_owned() } else { cell })
            .collect()]),
    );
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::BadNumber { .. })
    ));
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let snapshot = get_case(&exec, &scope, "c1").await?.ok_or("missing")?;
    force(&db, Forced::Rows(vec![vec!["x".to_owned()]]));
    let applied = cases::store::apply_to_stored(&exec, &scope, &snapshot, CaseAction::Start, "a", NOW).await;
    assert!(matches!(applied, Err(CaseStoreError::BadNumber { .. })));
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_typed_error_for_every_operation() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    force(&db, Forced::Fail);
    assert!(matches!(
        create_case(&exec, &scope, &case("acme", "c1", NOW)).await,
        Err(CaseStoreError::Pg(_))
    ));
    force(&db, Forced::Fail);
    assert!(matches!(get_case(&exec, &scope, "c1").await, Err(CaseStoreError::Pg(_))));
    force(&db, Forced::Fail);
    assert!(matches!(
        list_cases(&exec, &scope, &CasePage { after: None, size: 1 }).await,
        Err(CaseStoreError::Pg(_))
    ));
    force(&db, Forced::Fail);
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &comment("x")).await,
        Err(CaseStoreError::Pg(_))
    ));
    force(&db, Forced::Fail);
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::Pg(_))
    ));
    Ok(())
}

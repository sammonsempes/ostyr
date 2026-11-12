use crate::case;
use crate::memory::Db;
use crate::types::TestResult;
use crate::{comment, executor, know_alert, observable, sent, stored_case, ALERT, NOW, OTHER_ALERT};
use cases::error::CaseStoreError;
use cases::model::ObservableKind;
use cases::store::{
    add_comment, add_observable, attach_alert, create_case, MAX_ALERTS_PER_CASE, MAX_COMMENTS, MAX_COMMENT_CHARS, MAX_NAME_CHARS, MAX_OBSERVABLES,
    MAX_OBSERVABLE_CHARS,
};
use core_pg::scope::tenant_scope;


#[tokio::test]
async fn comments_are_appended_in_order_and_bounded() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    add_comment(&exec, &scope, "c1", &comment("first")).await?;
    add_comment(&exec, &scope, "c1", &comment("second")).await?;
    let texts: Vec<String> = stored_case(&db, "acme", "c1")
        .ok_or("missing")?
        .comments
        .into_iter()
        .map(|found| found.text)
        .collect();
    assert_eq!(texts, vec!["first", "second"]);
    let sent_before = sent(&db);
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &comment(&"a".repeat(MAX_COMMENT_CHARS + 1))).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &comment("a\0")).await,
        Err(CaseStoreError::NulByte { .. })
    ));
    let mut anonymous = comment("x");
    anonymous.author = "a".repeat(MAX_NAME_CHARS + 1);
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &anonymous).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    let mut early = comment("x");
    early.at = -1;
    assert!(matches!(
        add_comment(&exec, &scope, "c1", &early).await,
        Err(CaseStoreError::BadTime { .. })
    ));
    assert!(matches!(
        add_comment(&exec, &scope, "", &comment("x")).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert!(matches!(
        add_comment(&exec, &scope, "none", &comment("x")).await,
        Err(CaseStoreError::NotFound)
    ));
    assert_eq!(sent(&db), sent_before + 1);
    Ok(())
}


#[tokio::test]
async fn comments_stop_at_the_cap() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    for _round in 0..MAX_COMMENTS {
        add_comment(&exec, &scope, "c1", &comment("x")).await?;
    }
    let over = add_comment(&exec, &scope, "c1", &comment("x")).await;
    assert!(matches!(over, Err(CaseStoreError::Full { what: "comments", .. })));
    assert_eq!(stored_case(&db, "acme", "c1").ok_or("missing")?.comments.len(), MAX_COMMENTS);
    Ok(())
}


#[tokio::test]
async fn observables_dedupe_on_kind_and_normalised_value() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    assert!(add_observable(&exec, &scope, "c1", &observable(ObservableKind::Domain, "example.com")).await?);
    assert!(!add_observable(&exec, &scope, "c1", &observable(ObservableKind::Domain, " EXAMPLE.com. ")).await?);
    assert!(add_observable(&exec, &scope, "c1", &observable(ObservableKind::Url, "example.com")).await?);
    assert!(add_observable(&exec, &scope, "c1", &observable(ObservableKind::Url, "Example.com")).await?);
    let values: Vec<String> = stored_case(&db, "acme", "c1")
        .ok_or("missing")?
        .observables
        .into_iter()
        .map(|found| found.value)
        .collect();
    assert_eq!(values, vec!["example.com", "example.com", "Example.com"]);
    assert!(matches!(
        add_observable(&exec, &scope, "none", &observable(ObservableKind::Ip, "10.0.0.1")).await,
        Err(CaseStoreError::NotFound)
    ));
    Ok(())
}


#[tokio::test]
async fn observable_text_is_bounded_before_and_after_normalisation() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let sent_before = sent(&db);
    let too_long = observable(ObservableKind::Url, &"a".repeat(MAX_OBSERVABLE_CHARS + 1));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &too_long).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    let nul = observable(ObservableKind::Url, "a\0b");
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &nul).await,
        Err(CaseStoreError::NulByte { .. })
    ));
    let blank = observable(ObservableKind::Ip, "   ");
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &blank).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    let expands = observable(ObservableKind::Ip, &"\u{130}".repeat(MAX_OBSERVABLE_CHARS));
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &expands).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    let mut sourceless = observable(ObservableKind::Ip, "10.0.0.1");
    sourceless.source = "s".repeat(MAX_NAME_CHARS + 1);
    assert!(matches!(
        add_observable(&exec, &scope, "c1", &sourceless).await,
        Err(CaseStoreError::FieldTooLong { .. })
    ));
    assert!(matches!(
        add_observable(&exec, &scope, "", &observable(ObservableKind::Ip, "10.0.0.1")).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert_eq!(sent(&db), sent_before);
    Ok(())
}


#[tokio::test]
async fn observables_stop_at_the_cap_and_a_duplicate_is_not_full() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    for index in 0..MAX_OBSERVABLES {
        assert!(add_observable(&exec, &scope, "c1", &observable(ObservableKind::Other, &format!("v{index}"))).await?);
    }
    let over = add_observable(&exec, &scope, "c1", &observable(ObservableKind::Other, "extra")).await;
    assert!(matches!(over, Err(CaseStoreError::Full { what: "observables", .. })));
    Ok(())
}


#[tokio::test]
async fn an_alert_attaches_once_and_only_from_the_same_tenant() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    know_alert(&db, "acme", ALERT);
    know_alert(&db, "other", OTHER_ALERT);
    assert!(attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await?);
    assert!(!attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await?);
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", OTHER_ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::AlertNotFound)
    ));
    assert!(matches!(
        attach_alert(&exec, &scope, "none", ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::NotFound)
    ));
    let before = sent(&db);
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", &ALERT.to_uppercase(), ("tester", NOW)).await,
        Err(CaseStoreError::BadAlertId)
    ));
    assert!(matches!(
        attach_alert(&exec, &scope, "c1", "a\0", ("tester", NOW)).await,
        Err(CaseStoreError::BadAlertId)
    ));
    assert!(matches!(
        attach_alert(&exec, &scope, "", ALERT, ("tester", NOW)).await,
        Err(CaseStoreError::FieldEmpty { .. })
    ));
    assert_eq!(sent(&db), before);
    Ok(())
}


#[tokio::test]
async fn alerts_stop_at_the_cap() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    for index in 0..=MAX_ALERTS_PER_CASE {
        know_alert(&db, "acme", &format!("{index:064x}"));
    }
    for index in 0..MAX_ALERTS_PER_CASE {
        assert!(attach_alert(&exec, &scope, "c1", &format!("{index:064x}"), ("tester", NOW)).await?);
    }
    let over = attach_alert(&exec, &scope, "c1", &format!("{MAX_ALERTS_PER_CASE:064x}"), ("tester", NOW)).await;
    assert!(matches!(over, Err(CaseStoreError::Full { what: "alerts", .. })));
    Ok(())
}

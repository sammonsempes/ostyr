use crate::memory::{Db, Forced};
use crate::types::TestResult;
use crate::{case, executor, force, sent, stored_case, FOUR, NOW, THREE, TWO};
use cases::error::{CaseStoreError, TransitionError};
use cases::model::{CaseEvent, CaseEventKind, CaseStatus, Resolution};
use cases::store::{apply_case_action, apply_to_stored, create_case, get_case, MAX_HISTORY, MAX_NAME_CHARS};
use cases::stored::Stored;
use cases::transition::CaseAction;
use core_pg::scope::tenant_scope;


#[tokio::test]
async fn the_lifecycle_is_stored_with_its_events_and_versions() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let started = apply_case_action(&exec, &scope, "c1", CaseAction::Start, "alice", NOW + 1).await?;
    assert_eq!((started.case.status, started.version), (CaseStatus::InProgress, TWO as i64));
    let closed = apply_case_action(
        &exec,
        &scope,
        "c1",
        CaseAction::Close(Some(Resolution::TruePositive)),
        "alice",
        NOW + TWO as i64,
    )
    .await?;
    assert_eq!((closed.case.resolution, closed.version), (Some(Resolution::TruePositive), THREE as i64));
    let reopened = apply_case_action(&exec, &scope, "c1", CaseAction::Reopen, "bob", NOW + THREE as i64).await?;
    assert_eq!(
        (reopened.case.status, reopened.case.resolution, reopened.version),
        (CaseStatus::InProgress, None, FOUR as i64)
    );
    let read = get_case(&exec, &scope, "c1").await?.ok_or("missing")?;
    assert_eq!(read, reopened);
    let kinds: Vec<CaseEventKind> = read.case.history.iter().map(|event| event.kind).collect();
    assert_eq!(kinds, vec![CaseEventKind::Started, CaseEventKind::Closed, CaseEventKind::Reopened]);
    assert_eq!(read.case.updated_at, NOW + THREE as i64);
    Ok(())
}


#[tokio::test]
async fn a_refused_action_changes_nothing() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let no_resolution = apply_case_action(&exec, &scope, "c1", CaseAction::Close(None), "alice", NOW).await;
    assert!(matches!(
        no_resolution,
        Err(CaseStoreError::Transition(TransitionError::ResolutionRequired))
    ));
    let reopen = apply_case_action(&exec, &scope, "c1", CaseAction::Reopen, "alice", NOW).await;
    assert!(matches!(reopen, Err(CaseStoreError::Transition(TransitionError::NotAllowed { .. }))));
    let missing = apply_case_action(&exec, &scope, "nope", CaseAction::Start, "alice", NOW).await;
    assert!(matches!(missing, Err(CaseStoreError::NotFound)));
    assert_eq!(stored_case(&db, "acme", "c1"), Some(case("acme", "c1", NOW)));
    Ok(())
}


#[tokio::test]
async fn two_actions_on_one_snapshot_give_one_winner_and_one_event() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let snapshot = get_case(&exec, &scope, "c1").await?.ok_or("missing")?;
    let winner = apply_to_stored(&exec, &scope, &snapshot, CaseAction::Start, "alice", NOW + 1).await?;
    let loser = apply_to_stored(
        &exec,
        &scope,
        &snapshot,
        CaseAction::Close(Some(Resolution::Benign)),
        "bob",
        NOW + TWO as i64,
    )
    .await;
    assert!(matches!(loser, Err(CaseStoreError::Conflict)));
    let read = get_case(&exec, &scope, "c1").await?.ok_or("missing")?;
    assert_eq!(read, winner);
    assert_eq!(read.case.history.len(), 1);
    assert_eq!(read.case.status, CaseStatus::InProgress);
    Ok(())
}


#[tokio::test]
async fn history_actor_and_time_are_bounded_before_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let event = CaseEvent {
        kind: CaseEventKind::Started,
        at: NOW,
        actor: "a".to_owned(),
        from: CaseStatus::New,
        to: CaseStatus::InProgress,
    };
    let mut crowded = case("acme", "c1", NOW);
    crowded.history = vec![event; MAX_HISTORY];
    let snapshot = Stored { case: crowded, version: 1 };
    let full = apply_to_stored(&exec, &scope, &snapshot, CaseAction::Close(Some(Resolution::Other)), "alice", NOW).await;
    assert!(matches!(full, Err(CaseStoreError::Full { what: "history", .. })));
    let calm = Stored {
        case: case("acme", "c1", NOW),
        version: 1,
    };
    let long = apply_to_stored(&exec, &scope, &calm, CaseAction::Start, &"a".repeat(MAX_NAME_CHARS + 1), NOW).await;
    assert!(matches!(long, Err(CaseStoreError::FieldTooLong { .. })));
    let nul = apply_to_stored(&exec, &scope, &calm, CaseAction::Start, "a\0", NOW).await;
    assert!(matches!(nul, Err(CaseStoreError::NulByte { .. })));
    let early = apply_to_stored(&exec, &scope, &calm, CaseAction::Start, "alice", -1).await;
    assert!(matches!(early, Err(CaseStoreError::BadTime { .. })));
    assert_eq!(sent(&db), 0);
    force(&db, Forced::Fail);
    let broken = apply_to_stored(&exec, &scope, &calm, CaseAction::Start, "alice", NOW).await;
    assert!(matches!(broken, Err(CaseStoreError::Pg(_))));
    Ok(())
}

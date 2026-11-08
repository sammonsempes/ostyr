mod common;


use cases::error::TransitionError;
use cases::model::{Case, CaseEventKind, CaseStatus, Resolution, Severity};
use cases::transition::{action_label, apply_action, transition, CaseAction};
use common::types::TestResult;


const OPENED: i64 = 1_000;


const LATER: i64 = 2_000;


const ALL_STATUSES: [CaseStatus; 3] = [CaseStatus::New, CaseStatus::InProgress, CaseStatus::Closed];


fn case_in(status: CaseStatus) -> Case {
    Case {
        id: "c1".to_string(),
        tenant: "acme".to_string(),
        title: "t".to_string(),
        description: None,
        severity: Severity::High,
        status,
        resolution: None,
        assignee: None,
        template: None,
        case_type: None,
        created_at: OPENED,
        updated_at: OPENED,
        tasks: Vec::new(),
        observables: Vec::new(),
        comments: Vec::new(),
        history: Vec::new(),
    }
}


fn close_with_resolution() -> CaseAction {
    CaseAction::Close(Some(Resolution::TruePositive))
}


#[test]
fn every_transition_is_decided() -> TestResult {
    let actions = [CaseAction::Start, close_with_resolution(), CaseAction::Close(None), CaseAction::Reopen];
    let expected = [
        [
            Ok(CaseStatus::InProgress),
            Ok(CaseStatus::Closed),
            Err(TransitionError::ResolutionRequired),
            Err(TransitionError::NotAllowed {
                status: CaseStatus::New,
                action: "reopen",
            }),
        ],
        [
            Err(TransitionError::NotAllowed {
                status: CaseStatus::InProgress,
                action: "start",
            }),
            Ok(CaseStatus::Closed),
            Err(TransitionError::ResolutionRequired),
            Err(TransitionError::NotAllowed {
                status: CaseStatus::InProgress,
                action: "reopen",
            }),
        ],
        [
            Err(TransitionError::NotAllowed {
                status: CaseStatus::Closed,
                action: "start",
            }),
            Err(TransitionError::NotAllowed {
                status: CaseStatus::Closed,
                action: "close",
            }),
            Err(TransitionError::NotAllowed {
                status: CaseStatus::Closed,
                action: "close",
            }),
            Ok(CaseStatus::InProgress),
        ],
    ];
    let actual: Vec<Vec<_>> = ALL_STATUSES
        .iter()
        .map(|status| actions.iter().map(|action| transition(*status, *action)).collect())
        .collect();
    let wanted: Vec<Vec<_>> = expected.into_iter().map(Vec::from).collect();
    assert_eq!(actual, wanted);
    Ok(())
}


#[test]
fn labels_name_the_actions() -> TestResult {
    assert_eq!(action_label(CaseAction::Start), "start");
    assert_eq!(action_label(CaseAction::Reopen), "reopen");
    assert_eq!(action_label(CaseAction::Close(None)), "close");
    Ok(())
}


#[test]
fn error_messages_are_readable() -> TestResult {
    assert_eq!(TransitionError::ResolutionRequired.to_string(), "closing a case needs a resolution");
    assert!(TransitionError::NotAllowed {
        status: CaseStatus::Closed,
        action: "start"
    }
    .to_string()
    .contains("start"));
    Ok(())
}


#[test]
fn closing_then_reopening_is_audited_as_its_own_event() -> TestResult {
    let mut case = case_in(CaseStatus::New);
    apply_action(&mut case, CaseAction::Start, "alice", OPENED)?;
    let closed = apply_action(&mut case, close_with_resolution(), "alice", LATER)?;
    assert_eq!(closed.kind, CaseEventKind::Closed);
    assert_eq!(case.resolution, Some(Resolution::TruePositive));
    let reopened = apply_action(&mut case, CaseAction::Reopen, "bob", LATER)?;
    assert_eq!(reopened.kind, CaseEventKind::Reopened);
    assert_eq!(
        (reopened.from, reopened.to, reopened.actor.as_str()),
        (CaseStatus::Closed, CaseStatus::InProgress, "bob")
    );
    assert_eq!(case.resolution, None);
    assert_eq!(case.status, CaseStatus::InProgress);
    assert_eq!(case.updated_at, LATER);
    let kinds: Vec<CaseEventKind> = case.history.iter().map(|event| event.kind).collect();
    assert_eq!(kinds, [CaseEventKind::Started, CaseEventKind::Closed, CaseEventKind::Reopened]);
    Ok(())
}


#[test]
fn a_refused_action_leaves_the_case_untouched() -> TestResult {
    let mut case = case_in(CaseStatus::New);
    let before = case.clone();
    assert_eq!(
        apply_action(&mut case, CaseAction::Close(None), "alice", LATER),
        Err(TransitionError::ResolutionRequired)
    );
    assert_eq!(case, before);
    Ok(())
}

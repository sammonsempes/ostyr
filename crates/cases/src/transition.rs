use crate::error::TransitionError;
use crate::model::{Case, CaseEvent, CaseEventKind, CaseStatus, Resolution};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseAction {
    Start,
    Close(Option<Resolution>),
    Reopen,
}


pub fn action_label(action: CaseAction) -> &'static str {
    match action {
        CaseAction::Start => "start",
        CaseAction::Close(_) => "close",
        CaseAction::Reopen => "reopen",
    }
}


/// The status after `action`, or why it is refused; closing needs a resolution.
pub fn transition(status: CaseStatus, action: CaseAction) -> Result<CaseStatus, TransitionError> {
    match (status, action) {
        (CaseStatus::New, CaseAction::Start) | (CaseStatus::Closed, CaseAction::Reopen) => Ok(CaseStatus::InProgress),
        (CaseStatus::New | CaseStatus::InProgress, CaseAction::Close(Some(_))) => Ok(CaseStatus::Closed),
        (CaseStatus::New | CaseStatus::InProgress, CaseAction::Close(None)) => Err(TransitionError::ResolutionRequired),
        _ => Err(TransitionError::NotAllowed {
            status,
            action: action_label(action),
        }),
    }
}


/// A reopening is its own event kind, so the audit never reads it as a plain start.
pub fn event_kind(action: CaseAction) -> CaseEventKind {
    match action {
        CaseAction::Start => CaseEventKind::Started,
        CaseAction::Close(_) => CaseEventKind::Closed,
        CaseAction::Reopen => CaseEventKind::Reopened,
    }
}


pub fn resolution_after(action: CaseAction, current: Option<Resolution>) -> Option<Resolution> {
    match action {
        CaseAction::Close(resolution) => resolution,
        CaseAction::Reopen => None,
        CaseAction::Start => current,
    }
}


/// Applies `action` to the case and records the event; a refused action leaves the case untouched.
pub fn apply_action(case: &mut Case, action: CaseAction, actor: &str, now: i64) -> Result<CaseEvent, TransitionError> {
    let next = transition(case.status, action)?;
    let event = CaseEvent {
        kind: event_kind(action),
        at: now,
        actor: actor.to_string(),
        from: case.status,
        to: next,
        alert_id: None,
    };
    case.resolution = resolution_after(action, case.resolution);
    case.status = next;
    case.updated_at = now;
    case.history.push(event.clone());
    Ok(event)
}

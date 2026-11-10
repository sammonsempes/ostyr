use crate::alert::{Event, LifecycleState, Phase};
use crate::error::LifecycleError;
use crate::limits::MAX_ALERT_LEVEL;


pub fn escalate(state: LifecycleState, to_level: u32) -> Result<LifecycleState, LifecycleError> {
    let expected = state.level.saturating_add(1);
    if to_level != expected {
        Err(LifecycleError::WrongLevel {
            expected,
            requested: to_level,
        })
    } else if to_level > MAX_ALERT_LEVEL {
        Err(LifecycleError::LevelLimit {
            requested: to_level,
            max: MAX_ALERT_LEVEL,
        })
    } else {
        Ok(LifecycleState {
            phase: Phase::Escalated,
            level: to_level,
        })
    }
}


/// Pure lifecycle: a resolved alert accepts nothing, escalation goes to level n+1 only.
pub fn transition(state: LifecycleState, event: Event) -> Result<LifecycleState, LifecycleError> {
    match (state.phase, event) {
        (Phase::Resolved, _) => Err(LifecycleError::Resolved),
        (Phase::Acknowledged, Event::Acknowledge) => Err(LifecycleError::AlreadyAcknowledged),
        (_, Event::Acknowledge) => Ok(LifecycleState {
            phase: Phase::Acknowledged,
            level: state.level,
        }),
        (_, Event::Escalate { to_level }) => escalate(state, to_level),
        (_, Event::Resolve) => Ok(LifecycleState {
            phase: Phase::Resolved,
            level: state.level,
        }),
    }
}

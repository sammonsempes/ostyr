use crate::model::Rule;
use crate::types::Timestamp;


/// `since` is the start of the current breach (pending and firing); `at` is when the alert resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlertState {
    #[default]
    Inactive,
    Pending {
        since: Timestamp,
    },
    Firing {
        since: Timestamp,
    },
    Resolved {
        at: Timestamp,
    },
    Closed,
}


pub fn phase_name(state: &AlertState) -> &'static str {
    match state {
        AlertState::Inactive => "inactive",
        AlertState::Pending { .. } => "pending",
        AlertState::Firing { .. } => "firing",
        AlertState::Resolved { .. } => "resolved",
        AlertState::Closed => "closed",
    }
}


/// Start of the breach an active (pending or firing) state is tracking.
pub fn active_since(state: &AlertState) -> Option<Timestamp> {
    match state {
        AlertState::Pending { since } | AlertState::Firing { since } => Some(*since),
        AlertState::Inactive | AlertState::Resolved { .. } | AlertState::Closed => None,
    }
}


/// `held` is the breach start when the condition holds now; a breach fires after `for`, a resolved alert closes after `close_after`.
pub fn next_state(previous: &AlertState, held: Option<Timestamp>, rule: &Rule, now: Timestamp) -> AlertState {
    match (held, previous) {
        (Some(start), _) if now.saturating_sub(start) >= rule.hold_for => AlertState::Firing { since: start },
        (Some(start), _) => AlertState::Pending { since: start },
        (None, AlertState::Firing { .. }) => AlertState::Resolved { at: now },
        (None, AlertState::Resolved { at }) if now.saturating_sub(*at) >= rule.close_after => AlertState::Closed,
        (None, AlertState::Resolved { at }) => AlertState::Resolved { at: *at },
        (None, AlertState::Pending { .. } | AlertState::Inactive) => AlertState::Inactive,
        (None, AlertState::Closed) => AlertState::Closed,
    }
}

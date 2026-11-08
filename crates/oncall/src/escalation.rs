use crate::model::{EscalationState, Policy};
use chrono::{DateTime, Utc};


/// The level reached `now` for an alert opened at `opened_at`; delays add up level after level; an acknowledged alert never escalates.
pub fn escalation_due(policy: &Policy, opened_at: DateTime<Utc>, acknowledged: bool, now: DateTime<Utc>) -> EscalationState {
    let elapsed = now.signed_duration_since(opened_at).num_seconds();
    let reached = policy
        .levels
        .iter()
        .scan(0, |total, level| {
            *total += i64::from(level.delay_seconds);
            Some(*total)
        })
        .take_while(|total| *total <= elapsed)
        .count();
    if acknowledged {
        EscalationState::Acknowledged
    } else {
        reached.checked_sub(1).map_or(EscalationState::Waiting, EscalationState::Level)
    }
}

use crate::breakers::{Breakers, MODULE};
use crate::config::{limits_for, Limits};
use crate::error::StoreError;
use crate::model::{ActionKind, Counter, LimitName, ProposedAction, Reason, Verdict, Violation};
use crate::store::{count_in_window, is_overridden, persist, prune, Event, StoreState, DAY_SECONDS, HOUR_SECONDS};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::reload::current_config;
use std::collections::BTreeMap;
use std::sync::PoisonError;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::error;


pub const PERCENT: u64 = 100;


pub const DAY_SECONDS_UNSIGNED: u64 = DAY_SECONDS.unsigned_abs();


pub const NEEDS_APPROVAL_ACTION: &str = "breaker.needs_approval";


pub fn counter_of(kind: &ActionKind) -> Option<Counter> {
    match kind {
        ActionKind::IsolateEndpoint { .. } => Some(Counter::Isolation),
        ActionKind::DisableAccount => Some(Counter::Disabling),
        ActionKind::BlockIp { .. } | ActionKind::BlockDomain { .. } => Some(Counter::Block),
        ActionKind::RmmScript { .. } => None,
    }
}


pub fn action_label(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::IsolateEndpoint { .. } => "isolate_endpoint",
        ActionKind::DisableAccount => "disable_account",
        ActionKind::BlockIp { .. } => "block_ip",
        ActionKind::BlockDomain { .. } => "block_domain",
        ActionKind::RmmScript { .. } => "rmm_script",
    }
}


/// A limit of `max` events is reached once `current` equals it: the next event is the one that needs approval.
pub fn rate_violation(limit: LimitName, current: u64, max: u64) -> Option<Violation> {
    (current >= max).then_some(Violation { limit, current, max })
}


fn window_violation(
    limits_max: u64,
    limit: LimitName,
    state: &StoreState,
    action: &ProposedAction,
    window: (Counter, i64, i64),
) -> Option<Violation> {
    let (counter, seconds, now) = window;
    rate_violation(limit, count_in_window(state, &action.tenant, counter, now, seconds), limits_max)
}


pub fn duration_violation(limits: &Limits, duration: Duration) -> Option<Violation> {
    let max = Duration::from_secs(limits.block_max_days.saturating_mul(DAY_SECONDS_UNSIGNED));
    (duration > max).then_some(Violation {
        limit: LimitName::BlockDuration,
        current: duration.as_secs(),
        max: max.as_secs(),
    })
}


/// At most `max_isolated_percent` of the fleet (rounded down) may be isolated at once, the action included.
pub fn fleet_violation(limits: &Limits, fleet_size: u64, isolated_now: u64) -> Option<Violation> {
    let allowed = fleet_size.saturating_mul(limits.max_isolated_percent) / PERCENT;
    rate_violation(LimitName::FleetIsolatedPercent, isolated_now, allowed)
}


pub fn violations(limits: &Limits, state: &StoreState, action: &ProposedAction, now: i64) -> Vec<Violation> {
    match &action.kind {
        ActionKind::IsolateEndpoint { fleet_size, isolated_now } => [
            window_violation(
                limits.isolations_per_hour,
                LimitName::IsolationsPerHour,
                state,
                action,
                (Counter::Isolation, HOUR_SECONDS, now),
            ),
            window_violation(
                limits.isolations_per_day,
                LimitName::IsolationsPerDay,
                state,
                action,
                (Counter::Isolation, DAY_SECONDS, now),
            ),
            fleet_violation(limits, *fleet_size, *isolated_now),
        ]
        .into_iter()
        .flatten()
        .collect(),
        ActionKind::DisableAccount => window_violation(
            limits.disablings_per_hour,
            LimitName::DisablingsPerHour,
            state,
            action,
            (Counter::Disabling, HOUR_SECONDS, now),
        )
        .into_iter()
        .collect(),
        ActionKind::BlockIp { duration, .. } | ActionKind::BlockDomain { duration } => [
            window_violation(
                limits.blocks_per_hour,
                LimitName::BlocksPerHour,
                state,
                action,
                (Counter::Block, HOUR_SECONDS, now),
            ),
            duration_violation(limits, *duration),
        ]
        .into_iter()
        .flatten()
        .collect(),
        ActionKind::RmmScript { machines } => (*machines > limits.rmm_max_machines)
            .then_some(Violation {
                limit: LimitName::RmmMachines,
                current: *machines,
                max: limits.rmm_max_machines,
            })
            .into_iter()
            .collect(),
    }
}


/// Protected targets are never allowed automatically, whatever the counters say and whatever an override lifts.
pub fn protected_reason(limits: &Limits, action: &ProposedAction) -> Option<Reason> {
    let tagged = |protected: &[String]| {
        action
            .target
            .tags
            .iter()
            .find(|tag| protected.contains(tag))
            .map(|tag| Reason::ProtectedTag { tag: tag.clone() })
    };
    match &action.kind {
        ActionKind::DisableAccount => tagged(&limits.protected_account_tags),
        ActionKind::IsolateEndpoint { .. } | ActionKind::RmmScript { .. } => tagged(&limits.protected_host_tags),
        ActionKind::BlockIp { address, .. } => {
            let canonical = address.to_canonical();
            limits
                .reserved_ranges
                .iter()
                .find(|range| range.contains(&canonical))
                .map(|range| Reason::ReservedRange { range: range.to_string() })
        }
        ActionKind::BlockDomain { .. } => None,
    }
}


pub fn needs_approval(reason: Reason) -> Verdict {
    Verdict::NeedsApproval { reason, alert_on_call: true }
}


/// Pure decision: protected target first, then the limits; a limit lifted by an unexpired override no longer blocks but is reported.
pub fn evaluate(limits: &Limits, state: &StoreState, action: &ProposedAction, now: i64) -> Verdict {
    match protected_reason(limits, action) {
        Some(reason) => needs_approval(reason),
        None => {
            let (lifted, blocking): (Vec<Violation>, Vec<Violation>) = violations(limits, state, action, now)
                .into_iter()
                .partition(|violation| is_overridden(state, &action.tenant, violation.limit, now));
            match blocking.into_iter().next() {
                Some(violation) => needs_approval(Reason::LimitReached {
                    limit: violation.limit,
                    current: violation.current,
                    max: violation.max,
                }),
                None => Verdict::Allowed {
                    overridden: lifted.iter().map(|violation| violation.limit).collect(),
                },
            }
        }
    }
}


/// Writes the event durably before returning; the in-memory state follows only a successful write.
pub fn record(breakers: &Breakers, state: &mut StoreState, action: &ProposedAction, counter: Counter, now: i64) -> Result<(), StoreError> {
    let mut next = prune(state, now);
    next.events.push(Event {
        at: now,
        tenant: action.tenant.clone(),
        counter,
    });
    persist(&breakers.store.path, &next, breakers.store.sync)?;
    *state = next;
    Ok(())
}


/// Evaluates and records under one lock, so two concurrent checks cannot both take the last slot.
pub fn decide(breakers: &Breakers, limits: &Limits, action: &ProposedAction, now: i64) -> Verdict {
    let mut state = breakers.store.state.lock().unwrap_or_else(PoisonError::into_inner);
    let verdict = evaluate(limits, &state, action, now);
    let recordable = counter_of(&action.kind).filter(|_| matches!(verdict, Verdict::Allowed { .. }));
    match recordable {
        Some(counter) => record(breakers, &mut state, action, counter, now).map_or_else(
            |failure| {
                error!(%failure, "cannot record the action, failing closed");
                needs_approval(Reason::RecordFailed {
                    message: failure.to_string(),
                })
            },
            |()| verdict,
        ),
        None => verdict,
    }
}


pub fn needs_approval_entry(action: &ProposedAction, reason: &Reason, now: OffsetDateTime) -> NewEntry {
    NewEntry {
        timestamp: now,
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: action.tenant.clone(),
        module: MODULE.to_owned(),
        action: NEEDS_APPROVAL_ACTION.to_owned(),
        target: action.target.id.clone(),
        outcome: Outcome::Denied,
        request_id: action.request_id.clone(),
        justification: None,
        parameters: BTreeMap::from([
            ("proposed".to_owned(), action_label(&action.kind).to_owned()),
            ("reason".to_owned(), reason.to_string()),
            ("alert_on_call".to_owned(), "true".to_owned()),
        ]),
    }
}


/// A failing audit is logged and never turns the verdict into an allowance.
pub fn audit_verdict(breakers: &Breakers, action: &ProposedAction, verdict: &Verdict, now: OffsetDateTime) {
    if let Verdict::NeedsApproval { reason, .. } = verdict {
        if let Err(audit_error) = (breakers.audit)(needs_approval_entry(action, reason, now)) {
            error!(%audit_error, "cannot audit the needs-approval verdict");
        }
    }
}


/// The one entry point of a playbook action: limits are read at call time, so a reload applies to the next check.
pub fn check(breakers: &Breakers, action: &ProposedAction) -> Verdict {
    let limits = limits_for(&current_config(&breakers.engine), &action.tenant);
    let now = (breakers.clock)();
    let verdict = decide(breakers, &limits, action, now.unix_timestamp());
    audit_verdict(breakers, action, &verdict, now);
    verdict
}

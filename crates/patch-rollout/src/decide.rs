use crate::error::RolloutError;
use crate::limits::{RolloutLimits, PERCENT};
use crate::model::{
    Action, Decision, DeferReason, Deferred, DevicePhase, DeviceState, GroupPolicy, Issue, Outcome, RingPolicy, RingState, RingStatus, RolloutPolicy,
    Step, StepKind, Stop, StopReason,
};
use response_breakers::model::{ActionKind, ProposedAction, Target};
use std::collections::{BTreeMap, BTreeSet};
use time::{Duration, OffsetDateTime};


/// The first ring that is not cleared: it stops the rollout, is still soaking, or is the one to work on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker<'policy> {
    Stop(Stop),
    Waiting { ring: &'policy str, until: OffsetDateTime },
    Active(&'policy RingPolicy),
}


pub fn check_tenants(policy: &RolloutPolicy, ring_states: &[RingState], device_states: &[DeviceState]) -> Result<(), RolloutError> {
    ring_states
        .iter()
        .map(|state| &state.tenant)
        .chain(device_states.iter().map(|state| &state.tenant))
        .find(|tenant| **tenant != policy.tenant)
        .map_or(Ok(()), |found| {
            Err(RolloutError::TenantMismatch {
                expected: policy.tenant.clone(),
                found: found.clone(),
            })
        })
}


pub fn check_states(policy: &RolloutPolicy, ring_states: &[RingState], device_states: &[DeviceState]) -> Result<(), RolloutError> {
    ring_states.iter().try_fold(BTreeSet::<&str>::new(), |mut seen, state| {
        if !policy.rings.iter().any(|ring| ring.name == state.ring) {
            Err(RolloutError::UnknownRingState { ring: state.ring.clone() })
        } else if seen.insert(state.ring.as_str()) {
            Ok(seen)
        } else {
            Err(RolloutError::DuplicateRingState { ring: state.ring.clone() })
        }
    })?;
    device_states.iter().try_fold(BTreeSet::<&str>::new(), |mut seen, state| {
        if seen.insert(state.device.as_str()) {
            Ok(seen)
        } else {
            Err(RolloutError::DuplicateDeviceState {
                device: state.device.clone(),
            })
        }
    })?;
    Ok(())
}


pub fn ring_devices<'policy>(policy: &'policy RolloutPolicy, ring: &RingPolicy) -> BTreeMap<&'policy str, &'policy GroupPolicy> {
    ring.groups
        .iter()
        .filter_map(|group| policy.groups.get(group))
        .flat_map(|group| group.devices.iter().map(move |device| (device.as_str(), group)))
        .collect()
}


pub fn ring_status(ring_states: &[RingState], ring: &str) -> RingStatus {
    ring_states
        .iter()
        .find(|state| state.ring == ring)
        .map_or(RingStatus::NotStarted, |state| state.status)
}


pub fn stop_reason(failed: usize, total: usize, ring: &RingPolicy) -> Option<StopReason> {
    if failed > ring.max_failures {
        Some(StopReason::FailureCount {
            failed,
            max: ring.max_failures,
        })
    } else if failed.saturating_mul(PERCENT) > ring.max_failure_percent.saturating_mul(total) {
        Some(StopReason::FailurePercent {
            failed,
            total,
            max_percent: ring.max_failure_percent,
        })
    } else {
        None
    }
}


pub fn breaker_input(policy: &RolloutPolicy, ring: &RingPolicy, machines: usize) -> ProposedAction {
    ProposedAction {
        tenant: policy.tenant.clone(),
        request_id: format!("patch-rollout-stop-{}", ring.name),
        kind: ActionKind::RmmScript { machines: machines as u64 },
        target: Target {
            id: ring.name.clone(),
            tags: Vec::new(),
        },
    }
}


pub fn ring_blocker<'policy>(
    policy: &'policy RolloutPolicy,
    ring: &'policy RingPolicy,
    status: RingStatus,
    failed: &BTreeSet<&str>,
    now: OffsetDateTime,
) -> Option<Blocker<'policy>> {
    let devices = ring_devices(policy, ring);
    let failures = devices.keys().filter(|device| failed.contains(**device)).count();
    match (stop_reason(failures, devices.len(), ring), status) {
        (Some(reason), _) => Some(Blocker::Stop(Stop {
            ring: ring.name.clone(),
            reason,
            breaker_input: breaker_input(policy, ring, devices.len()),
        })),
        (None, RingStatus::Finished { at }) => {
            let until = at.saturating_add(Duration::seconds(i64::from(ring.soak_seconds)));
            (now < until).then_some(Blocker::Waiting { ring: &ring.name, until })
        }
        (None, RingStatus::NotStarted | RingStatus::Running) => Some(Blocker::Active(ring)),
    }
}


pub fn gate(allowed: bool, state: &DeviceState, kind: StepKind) -> Step {
    if allowed {
        Step::Act(Action {
            device: state.device.clone(),
            kind,
        })
    } else {
        Step::Defer(Deferred {
            subject: state.device.clone(),
            reason: DeferReason::OutsideWindow,
        })
    }
}


/// A reboot of a workstation (or of a group asking for it) goes through a prompt first; install and reboot need the window, a reboot also the policy flag.
pub fn step_for(policy: &RolloutPolicy, group: &GroupPolicy, state: &DeviceState) -> Step {
    let reboot_allowed = state.in_window || policy.reboot_outside_window;
    let first_reboot_step = if group.workstation || group.prompt_before_reboot {
        StepKind::PromptReboot
    } else {
        StepKind::Reboot
    };
    match state.phase {
        DevicePhase::Pending => gate(state.in_window, state, StepKind::Install),
        DevicePhase::NeedsReboot => gate(reboot_allowed, state, first_reboot_step),
        DevicePhase::RebootPrompted => gate(reboot_allowed, state, StepKind::Reboot),
        DevicePhase::Failed | DevicePhase::Done => Step::Nothing,
    }
}


pub fn ring_steps(policy: &RolloutPolicy, ring: &RingPolicy, considered: &[&DeviceState]) -> Vec<Step> {
    let devices = ring_devices(policy, ring);
    considered
        .iter()
        .filter_map(|state| devices.get(state.device.as_str()).map(|group| step_for(policy, group, state)))
        .collect()
}


/// Decides which ring works next. Failures are counted over every device state; only the first `max_devices` states get an action, the rest are deferred.
pub fn next_actions(
    policy: &RolloutPolicy,
    ring_states: &[RingState],
    device_states: &[DeviceState],
    now: OffsetDateTime,
    limits: &RolloutLimits,
) -> Result<Decision, RolloutError> {
    check_tenants(policy, ring_states, device_states)?;
    check_states(policy, ring_states, device_states)?;
    let considered: Vec<&DeviceState> = device_states.iter().take(limits.max_devices).collect();
    let failed: BTreeSet<&str> = device_states
        .iter()
        .filter(|state| state.phase == DevicePhase::Failed)
        .map(|state| state.device.as_str())
        .collect();
    let known: BTreeSet<&str> = policy
        .groups
        .values()
        .flat_map(|group| group.devices.iter().map(String::as_str))
        .collect();
    let blocker = policy
        .rings
        .iter()
        .take(limits.max_rings)
        .find_map(|ring| ring_blocker(policy, ring, ring_status(ring_states, &ring.name), &failed, now));
    let steps = match &blocker {
        Some(Blocker::Active(ring)) => ring_steps(policy, ring, &considered),
        _ => Vec::new(),
    };
    let actions = steps
        .iter()
        .filter_map(|step| match step {
            Step::Act(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rings_capped = policy.rings.len() > limits.max_rings;
    let outcome = match blocker {
        Some(Blocker::Stop(stop)) => Outcome::Stop(stop),
        Some(Blocker::Waiting { ring, until }) => Outcome::Waiting {
            ring: ring.to_owned(),
            until,
        },
        Some(Blocker::Active(ring)) => Outcome::Proceed {
            ring: ring.name.clone(),
            actions,
        },
        None if rings_capped => Outcome::Capped,
        None => Outcome::Complete,
    };
    let deferred = steps
        .into_iter()
        .filter_map(|step| match step {
            Step::Defer(deferred) => Some(deferred),
            _ => None,
        })
        .chain(device_states.iter().skip(limits.max_devices).map(|state| Deferred {
            subject: state.device.clone(),
            reason: DeferReason::DeviceCap,
        }))
        .chain(policy.rings.iter().skip(limits.max_rings).map(|ring| Deferred {
            subject: ring.name.clone(),
            reason: DeferReason::RingCap,
        }))
        .collect();
    let issues = considered
        .iter()
        .filter(|state| !known.contains(state.device.as_str()))
        .map(|state| Issue::UnknownDevice(state.device.clone()))
        .collect();
    Ok(Decision { outcome, deferred, issues })
}

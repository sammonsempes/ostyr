//! The round runner as a library: per-check state, fair scheduling, pending outages and the reload diff (T856B); no I/O.

use crate::alerting::{alert_of, outage_alerts, Outage};
use crate::decision::should_alert;
use crate::error::CheckError;
use crate::load::{count_within, runner_location_ok};
use crate::model::{failure_run_len, Check, LocationHistory, MAX_CHECKS, MAX_LOCATION_LEN};
use crate::types::{Clock, Probe, Stopped, Store, WallClock};
use core_pg::scope::{tenant_of, TenantScope};
use std::collections::BTreeSet;
use std::time::Duration;


pub const MAX_PROBES_PER_ROUND: usize = 64;


/// Shared slots for pending outages that are not the newest of a current check; that newest one has its own reserved slot on top.
pub const MAX_PENDING_OUTAGES: usize = 256;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Runs,
    NeedsOtherLocations,
    OtherLocation,
}


/// One check and what this runner remembers of it: the last results, the first failure of the current run and whether its outage was stored.
#[derive(Debug, Clone)]
pub struct CheckState {
    pub check: Check,
    pub ring: Vec<bool>,
    pub run_started: Option<u64>,
    pub raised: bool,
    pub last_start: Option<Duration>,
    pub placement: Placement,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub probes: u64,
    pub deferred: u64,
    pub outages_stored: u64,
    pub outage_already_stored: u64,
    pub store_failures: u64,
    pub pending_dropped: u64,
    pub outages_rejected: u64,
}


#[derive(Debug, Clone)]
pub struct Runner {
    pub tenant: String,
    pub location: String,
    pub states: Vec<CheckState>,
    pub pending: Vec<Outage>,
    pub counters: Counters,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReloadReport {
    pub kept: usize,
    pub added: usize,
    pub reset: usize,
    pub removed: usize,
    pub needs_other_locations: usize,
    pub other_location: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundReport {
    pub due: usize,
    pub probed: usize,
    pub deferred: usize,
    pub largest_overdue: Duration,
    pub never_run: usize,
    pub stored: usize,
    pub store_failed: bool,
    pub pending: usize,
    pub pending_dropped: usize,
}


/// The injected clock, wall clock, probe, store and stop flag of a round.
pub struct RoundContext<'a> {
    pub scope: &'a TenantScope,
    pub clock: &'a Clock<'a>,
    pub wall: &'a WallClock<'a>,
    pub probe: &'a Probe<'a>,
    pub store: &'a Store<'a>,
    pub stopped: &'a Stopped<'a>,
}


/// An empty runner for the scope's tenant; the location must be ASCII and pass the checks file's text grammar.
pub fn new_runner(scope: &TenantScope, location: &str) -> Result<Runner, CheckError> {
    runner_location_ok(location)
        .then(|| Runner {
            tenant: tenant_of(scope).to_owned(),
            location: location.to_owned(),
            states: Vec::new(),
            pending: Vec::new(),
            counters: Counters::default(),
        })
        .ok_or(CheckError::BadText {
            field: "location",
            max: MAX_LOCATION_LEN,
        })
}


/// A check with no location equal to the runner's is another runner's; one with several locations needs aggregation this runner cannot do.
pub fn placement_of(check: &Check, location: &str) -> Placement {
    if !check.locations.iter().any(|declared| declared == location) {
        Placement::OtherLocation
    } else if check.locations.len() > 1 {
        Placement::NeedsOtherLocations
    } else {
        Placement::Runs
    }
}


/// True when the two checks differ in no field other than the interval and the timeout.
pub fn same_but_timing(old: &Check, new: &Check) -> bool {
    let aligned = Check {
        interval_seconds: old.interval_seconds,
        timeout_seconds: old.timeout_seconds,
        ..new.clone()
    };
    aligned == *old
}


pub fn fresh_state(check: &Check, location: &str) -> CheckState {
    CheckState {
        check: check.clone(),
        ring: Vec::new(),
        run_started: None,
        raised: false,
        last_start: None,
        placement: placement_of(check, location),
    }
}


pub fn next_state(old: Option<&CheckState>, check: &Check, location: &str) -> CheckState {
    match old {
        Some(previous) if same_but_timing(&previous.check, check) => CheckState {
            check: check.clone(),
            ..previous.clone()
        },
        _ => fresh_state(check, location),
    }
}


/// Swaps in the new checks by name (a duplicate name is refused and nothing changes): a kept check keeps its state when only its timing changed, any other change resets it; pending outages stay.
pub fn reload_checks(runner: &mut Runner, checks: &[Check]) -> Result<ReloadReport, CheckError> {
    count_within("checks", checks.len(), 0, MAX_CHECKS)?;
    let mut names = BTreeSet::new();
    checks.iter().try_for_each(|check| {
        names
            .insert(check.name.as_str())
            .then_some(())
            .ok_or(CheckError::Duplicate { field: "name" })
    })?;
    let old = std::mem::take(&mut runner.states);
    let states: Vec<CheckState> = checks
        .iter()
        .map(|check| next_state(old.iter().find(|state| state.check.name == check.name), check, &runner.location))
        .collect();
    let existing = states
        .iter()
        .filter(|state| old.iter().any(|previous| previous.check.name == state.check.name))
        .count();
    let kept = states
        .iter()
        .filter(|state| old.iter().any(|previous| same_but_timing(&previous.check, &state.check)))
        .count();
    let needs_other_locations = states.iter().filter(|state| state.placement == Placement::NeedsOtherLocations).count();
    let other_location = states.iter().filter(|state| state.placement == Placement::OtherLocation).count();
    let report = ReloadReport {
        kept,
        added: states.len() - existing,
        reset: existing - kept,
        removed: old.len() - existing,
        needs_other_locations,
        other_location,
    };
    runner.states = states;
    tracing::info!(needs_other_locations, other_location, "checks reloaded");
    Ok(report)
}


pub fn is_due(state: &CheckState, now: Duration) -> bool {
    state.placement == Placement::Runs && overdue_of(state, now).is_some()
}


/// How long past its interval the check is, or `None` while it is not yet due; a check never run is due at once.
pub fn overdue_of(state: &CheckState, now: Duration) -> Option<Duration> {
    let interval = Duration::from_secs(state.check.interval_seconds);
    state.last_start.map_or(Some(now), |started| {
        now.checked_sub(started).and_then(|elapsed| elapsed.checked_sub(interval))
    })
}


/// The overdue time of a check that has run before; a never-run check has no start to measure from.
pub fn overdue_since_run(state: &CheckState, now: Duration) -> Option<Duration> {
    state.last_start.and_then(|_started| overdue_of(state, now))
}


/// Probes one check and updates its ring and run; answers the outage to store when one is now due and not yet raised.
pub fn probe_state(state: &mut CheckState, tenant: &str, location: &str, ctx: &RoundContext) -> Option<Outage> {
    state.last_start = Some((ctx.clock)());
    let succeeded = (ctx.probe)(&state.check);
    let wall = (ctx.wall)();
    state.ring.push(succeeded);
    let excess = state.ring.len().saturating_sub(failure_run_len(state.check.consecutive_failures));
    state.ring.drain(..excess);
    state.run_started = if succeeded { None } else { state.run_started.or(Some(wall)) };
    state.raised = state.raised && !succeeded;
    let history = LocationHistory {
        location: location.to_owned(),
        results: state.ring.clone(),
    };
    let alerting = !succeeded && !state.raised && should_alert(&state.check, &[history]);
    state.run_started.filter(|_started| alerting).map(|since| Outage {
        tenant: tenant.to_owned(),
        check: state.check.name.clone(),
        kind: state.check.kind,
        failing_locations: vec![location.to_owned()],
        since,
    })
}


/// Keeps one pending outage per check, kind and run; the cap is applied by `trim_pending`.
pub fn add_pending(runner: &mut Runner, outage: Outage) {
    let known = runner
        .pending
        .iter()
        .any(|pending| pending.check == outage.check && pending.kind == outage.kind && pending.since == outage.since);
    if !known {
        runner.pending.push(outage);
    }
}


/// For each pending outage, true when it is the newest of a check still in `states`: its reserved slot, never evicted by another check.
pub fn reserved_flags(states: &[CheckState], pending: &[Outage]) -> Vec<bool> {
    pending
        .iter()
        .enumerate()
        .map(|(index, outage)| {
            let present = states.iter().any(|state| state.check.name == outage.check);
            present && !pending.iter().skip(index + 1).any(|newer| newer.check == outage.check)
        })
        .collect()
}


/// Drops the oldest unreserved pending outages beyond `MAX_PENDING_OUTAGES`, counted and warned; answers the number dropped. The newest outage of each current check is never dropped.
pub fn trim_pending(runner: &mut Runner) -> usize {
    let reserved = reserved_flags(&runner.states, &runner.pending);
    let shared = reserved.iter().filter(|is_reserved| !**is_reserved).count();
    let excess = shared.saturating_sub(MAX_PENDING_OUTAGES);
    let mut to_drop = excess;
    runner.pending = std::mem::take(&mut runner.pending)
        .into_iter()
        .zip(reserved)
        .filter(|(_outage, is_reserved)| {
            let drop_it = !*is_reserved && to_drop > 0;
            to_drop -= usize::from(drop_it);
            !drop_it
        })
        .map(|(outage, _is_reserved)| outage)
        .collect();
    runner.counters.pending_dropped += excess as u64;
    if excess > 0 {
        tracing::warn!(excess, "pending outages dropped: the shared pending cap was reached");
    }
    excess
}


/// Marks the outage of each stored pending entry as raised on the check that still holds that run.
pub fn mark_raised(runner: &mut Runner, stored: Vec<Outage>) {
    stored.iter().for_each(|outage| {
        runner
            .states
            .iter_mut()
            .filter(|state| state.check.name == outage.check && state.check.kind == outage.kind && state.run_started == Some(outage.since))
            .for_each(|state| state.raised = true);
    });
}


/// Stores the pending outages through the injected store: `Ok` raises and clears them, an error keeps them for the next round. Answers (new rows, failed).
pub fn flush_pending(runner: &mut Runner, ctx: &RoundContext) -> (usize, bool) {
    let now = (ctx.wall)();
    let (valid, rejected): (Vec<Outage>, Vec<Outage>) = std::mem::take(&mut runner.pending)
        .into_iter()
        .partition(|outage| alert_of(ctx.scope, outage, now).is_some());
    let rejected_count = rejected.len();
    runner.counters.outages_rejected += rejected_count as u64;
    if rejected_count > 0 {
        tracing::warn!(rejected_count, "outages rejected: a time the store cannot hold");
    }
    runner.pending = valid;
    let alerts = outage_alerts(ctx.scope, &runner.pending, now);
    let answer = (!runner.pending.is_empty()).then(|| (ctx.store)(&alerts));
    match answer {
        None => (0, false),
        Some(Err(_refused)) => {
            runner.counters.store_failures += 1;
            tracing::warn!("outage alerts not stored, kept for the next round");
            (0, true)
        }
        Some(Ok(inserted)) => {
            let outages = std::mem::take(&mut runner.pending);
            if inserted == 0 {
                runner.counters.outage_already_stored += outages.len() as u64;
                tracing::warn!("outage_already_stored: the store held every pending outage");
            }
            runner.counters.outages_stored += inserted as u64;
            mark_raised(runner, outages);
            (inserted, false)
        }
    }
}


/// One round: the due checks most overdue first (ties by name) up to `MAX_PROBES_PER_ROUND`, the stop flag read between probes, then the pending outages are stored.
pub fn run_round(runner: &mut Runner, ctx: &RoundContext) -> RoundReport {
    let now = (ctx.clock)();
    let mut due: Vec<(Option<Duration>, String)> = runner
        .states
        .iter()
        .filter(|state| is_due(state, now))
        .map(|state| (state.last_start, state.check.name.clone()))
        .collect();
    due.sort();
    let largest_overdue = runner
        .states
        .iter()
        .filter(|state| is_due(state, now))
        .filter_map(|state| overdue_since_run(state, now))
        .fold(Duration::ZERO, Duration::max);
    let never_run = runner
        .states
        .iter()
        .filter(|state| is_due(state, now) && state.last_start.is_none())
        .count();
    let (outages, probed) = due.iter().take(MAX_PROBES_PER_ROUND).take_while(|_name| !(ctx.stopped)()).fold(
        (Vec::new(), usize::default()),
        |(mut found, count), (_started, name)| {
            let outage = runner
                .states
                .iter_mut()
                .find(|state| state.check.name == *name)
                .and_then(|state| probe_state(state, &runner.tenant, &runner.location, ctx));
            found.extend(outage);
            (found, count + 1)
        },
    );
    outages.into_iter().for_each(|outage| add_pending(runner, outage));
    let pending_dropped = trim_pending(runner);
    let (stored, store_failed) = flush_pending(runner, ctx);
    runner.counters.probes += probed as u64;
    let deferred = due.len().saturating_sub(probed);
    runner.counters.deferred += deferred as u64;
    let overdue_seconds = largest_overdue.as_secs();
    tracing::info!(probed, deferred, overdue_seconds, never_run, "round done");
    RoundReport {
        due: due.len(),
        probed,
        deferred,
        largest_overdue,
        never_run,
        stored,
        store_failed,
        pending: runner.pending.len(),
        pending_dropped,
    }
}

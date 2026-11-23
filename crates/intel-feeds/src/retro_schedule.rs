//! The retro match on a schedule: one round at a time, the window ends now and covers the interval plus a margin, the settings are read again each pass.

use crate::config::{retro_settings, RetroSection};
use crate::retro::{RetroError, RetroSummary};
use crate::retro_alerts::{store_run, AlertsError, StoreReport};
use crate::types::{AlertInsertFn, ClockFn, RunRetroFn, SnapshotFn, StopFn, WaitFn};
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const WAIT_SLICE_SECONDS: u64 = 5;


/// `previous_end` moves only after a round whose run and insert both succeeded, so a failed round shows as a `gap` in the next summary when its span is not covered again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScheduleState {
    pub previous_end: Option<OffsetDateTime>,
    pub last_started: Option<OffsetDateTime>,
}


#[derive(Debug, Error)]
pub enum RoundFailure {
    #[error("the window start is outside the supported range")]
    Window,
    #[error("the retro run failed")]
    Run(#[source] RetroError),
    #[error("the alerts could not be stored")]
    Store(#[source] AlertsError),
}


#[derive(Debug)]
pub enum RoundOutcome {
    Failed(RoundFailure),
    Done { summary: RetroSummary, report: StoreReport },
}


/// The window ends at `now` and starts `window_seconds` before it.
pub fn window_of(section: &RetroSection, now: OffsetDateTime) -> Option<(OffsetDateTime, OffsetDateTime)> {
    i64::try_from(section.window_seconds)
        .ok()
        .and_then(|seconds| now.checked_sub(time::Duration::seconds(seconds)))
        .map(|start| (start, now))
}


/// What is left of the interval since the last round started, `None` when a round is due.
pub fn due_in(section: &RetroSection, state: &ScheduleState, now: OffsetDateTime) -> Option<Duration> {
    state
        .last_started
        .and_then(|started| {
            i64::try_from(section.interval_seconds)
                .ok()
                .and_then(|seconds| started.checked_add(time::Duration::seconds(seconds)))
        })
        .map(|due| due - now)
        .filter(|left| left.is_positive())
        .map(time::Duration::unsigned_abs)
}


/// One run and one insert; the state moves on only when both succeeded. A `gap` of the summary is logged here.
pub fn round(
    section: &RetroSection,
    state: ScheduleState,
    now: OffsetDateTime,
    run: &RunRetroFn,
    insert: &AlertInsertFn,
) -> (ScheduleState, RoundOutcome) {
    let settings = retro_settings(section);
    let started = ScheduleState {
        last_started: Some(now),
        ..state
    };
    let done = window_of(section, now).ok_or(RoundFailure::Window).and_then(|(start, end)| {
        let found = run(&settings, start, end, state.previous_end).map_err(RoundFailure::Run)?;
        let report = store_run(&settings, &found, now, insert).map_err(RoundFailure::Store)?;
        Ok((end, found.summary, report))
    });
    match done {
        Ok((end, summary, report)) => {
            summary.gap.iter().for_each(|gap| warn!(from = %gap.from, to = %gap.to, "retro gap"));
            let (groups, inserted, known) = (summary.groups, report.inserted, report.known);
            info!(groups, inserted, known, "retro round done");
            (
                ScheduleState {
                    previous_end: Some(end),
                    ..started
                },
                RoundOutcome::Done { summary, report },
            )
        }
        Err(failure) => {
            warn!(%failure, "retro round failed");
            (started, RoundOutcome::Failed(failure))
        }
    }
}


/// The injected edges of the schedule: settings snapshot, clock, wait, stop test, retro run and alert insert.
pub struct Hooks<'a> {
    pub snapshot: &'a SnapshotFn<'a>,
    pub clock: &'a ClockFn<'a>,
    pub wait: &'a WaitFn<'a>,
    pub stop: &'a StopFn<'a>,
    pub run: &'a RunRetroFn<'a>,
    pub insert: &'a AlertInsertFn<'a>,
}


/// One pass: the settings snapshot is taken now (a reload applies at the next pass), then a wait of at most `WAIT_SLICE_SECONDS` or one round. Rounds never overlap: one thread.
pub fn pass(hooks: &Hooks, state: ScheduleState) -> (ScheduleState, Option<RoundOutcome>) {
    let now = (hooks.clock)();
    match (hooks.snapshot)().and_then(|config| config.retro.clone()) {
        None => {
            (hooks.wait)(Duration::from_secs(WAIT_SLICE_SECONDS));
            (state, None)
        }
        Some(section) => match due_in(&section, &state, now) {
            Some(left) => {
                (hooks.wait)(left.min(Duration::from_secs(WAIT_SLICE_SECONDS)));
                (state, None)
            }
            None => {
                let (next, outcome) = round(&section, state, now, hooks.run, hooks.insert);
                (next, Some(outcome))
            }
        },
    }
}


/// At most `max_passes` passes, stopping at the first one where `stop` answers true; every round outcome goes to `report`.
pub fn run_schedule(hooks: &Hooks, max_passes: u64, report: &mut dyn FnMut(&RoundOutcome)) -> ScheduleState {
    let stopped = (0..max_passes).try_fold(ScheduleState::default(), |state, _| {
        if (hooks.stop)() {
            Err(state)
        } else {
            let (next, outcome) = pass(hooks, state);
            outcome.iter().for_each(&mut *report);
            Ok(next)
        }
    });
    stopped.unwrap_or_else(|state| state)
}

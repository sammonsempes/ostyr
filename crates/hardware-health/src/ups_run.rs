//! Reads each configured UPS with `upsc <ups>@<host>[:<port>]` (Unix only: the same trusted-program run as smartctl).

use crate::limits::{default_limits, DEFAULT_MAX_UPS_LINES, MAX_DEADLINE_SECONDS};
use crate::model::{BlindReason, FailureClass, Health, UpsFailure, UpsReport, UpsRunReport, UpsSettings, UpsTarget};
use crate::smart_run::system_clock;
use crate::types::{ClockFn, Context, RunnerFn};
use crate::ups::parse_upsc;
use crate::ups_target::{parse_target, target_key};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use tracing::debug;


pub const UPSC_PROGRAM: &str = "/usr/bin/upsc";


pub const EXIT_OK: i32 = 0;


struct UpsRound {
    report: UpsRunReport,
    spent: Duration,
    seen: BTreeSet<(String, String)>,
}


/// Maps a failure of the shared runner; the classes only the smartctl reader produces cannot occur here.
pub fn ups_failure_of(class: FailureClass) -> UpsFailure {
    match class {
        FailureClass::TimedOut => UpsFailure::TimedOut,
        FailureClass::TooLarge => UpsFailure::TooLarge,
        FailureClass::Spawn => UpsFailure::Spawn,
        FailureClass::Unwaitable => UpsFailure::Unwaitable,
        FailureClass::Signalled => UpsFailure::Signalled,
        FailureClass::ProgramRefused => UpsFailure::ProgramRefused,
        FailureClass::Deferred => UpsFailure::Deferred,
        FailureClass::CommandLine | FailureClass::OpenFailed => UpsFailure::CommandFailed,
        FailureClass::Unparsable => UpsFailure::Unparsable,
        FailureClass::Io | FailureClass::TooManyDevices => UpsFailure::Io,
    }
}


/// A target that could not be read is a blind spot, whatever the reason: never healthy, never dropped.
pub fn ups_failure_health(_failure: UpsFailure) -> Health {
    Health::BlindSpot(BlindReason::NoVerdict)
}


fn one_target(program: &Path, runner: RunnerFn, deadline: Duration, target: &UpsTarget) -> Result<UpsReport, UpsFailure> {
    let limits = default_limits();
    let output = runner(program, &[target.text.as_str()], limits.max_bytes, deadline).map_err(ups_failure_of)?;
    match output.exit_code {
        None => Err(UpsFailure::Signalled),
        Some(EXIT_OK) => parse_upsc(output.bytes.as_slice(), limits.max_bytes, DEFAULT_MAX_UPS_LINES).map_err(|error| {
            debug!(%error, "upsc output refused");
            UpsFailure::Unparsable
        }),
        Some(_) => Err(UpsFailure::CommandFailed),
    }
}


fn read_target(context: &Context, mut round: UpsRound, target: UpsTarget) -> UpsRound {
    let ((settings, program), (runner, clock)) = *context;
    let budget = Duration::from_secs(settings.round_deadline_seconds);
    let remaining = budget.saturating_sub(round.spent);
    if remaining.is_zero() {
        round.report.failed.push((target, UpsFailure::Deferred));
    } else {
        let deadline = remaining
            .min(Duration::from_secs(settings.deadline_seconds))
            .min(Duration::from_secs(MAX_DEADLINE_SECONDS));
        let started = clock(program);
        let outcome = one_target(program, runner, deadline, &target);
        round.spent += clock(program).saturating_duration_since(started);
        match outcome {
            Ok(found) => round.report.reports.push((target, found)),
            Err(class) => round.report.failed.push((target, class)),
        }
    }
    round
}


fn admit(context: &Context, mut round: UpsRound, (index, text): (usize, &String)) -> UpsRound {
    match parse_target(text) {
        Some(target) if round.seen.insert(target_key(&target)) => read_target(context, round, target),
        _ => {
            round.report.refused_targets.push(index);
            round
        }
    }
}


/// Reads every accepted target within the round budget, charging the wall time of each run; a refused or duplicate target is listed by index and the others run.
pub fn run_ups_with(settings: &UpsSettings, program: &Path, runner: RunnerFn, clock: ClockFn) -> UpsRunReport {
    let context: Context = ((settings, program), (runner, clock));
    let start = UpsRound {
        report: UpsRunReport::default(),
        spent: Duration::ZERO,
        seen: BTreeSet::new(),
    };
    settings
        .ups_targets
        .iter()
        .enumerate()
        .fold(start, |round, entry| admit(&context, round, entry))
        .report
}


/// `run_ups_with` on `UPSC_PROGRAM` and the real clock; production passes `run_smartctl` as the runner.
pub fn run_ups(settings: &UpsSettings, runner: RunnerFn) -> UpsRunReport {
    run_ups_with(settings, Path::new(UPSC_PROGRAM), runner, system_clock)
}

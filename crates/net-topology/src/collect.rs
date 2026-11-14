use crate::error::ParseError;
use crate::limits::{Limits, MAX_HOST_SECONDS_CEILING, MAX_PORT_TIMEOUT_SECONDS, MIN_PORT_TIMEOUT_SECONDS};
use crate::lldp::{check_host, check_port_bytes, parse_lldpd_port};
use crate::model::{Observation, Parsed, RunFailure, Skipped};
use crate::ports::valid_port;
use crate::types::{ClockFn, RunPortFn};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};


/// Why one port's read produced no observations; a category only, never input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFailure {
    Io,
    TimedOut,
    Failed,
    Spawn,
    TooLarge,
    TooMany,
    Malformed,
    WrongPort,
    Rejected,
}


/// The result of one host: the observations of every port that read well, and what did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRead {
    pub observations: Vec<Observation>,
    pub skipped: Skipped,
    pub failed_ports: Vec<(String, PortFailure)>,
    pub ports_run: usize,
    pub skipped_budget: usize,
    pub skipped_time: usize,
    pub refused_ports: usize,
    pub excess_ports: usize,
}


struct Progress<'a> {
    read: HostRead,
    consumed: u64,
    started: Instant,
    clock: ClockFn<'a>,
}


struct Context<'a> {
    local_host: &'a str,
    now: i64,
    limits: &'a Limits,
    run: RunPortFn,
}


/// Maps a per-port parse error to its category.
pub fn failure_of(error: &ParseError) -> PortFailure {
    match error {
        ParseError::Read(_) => PortFailure::Io,
        ParseError::TooLarge { .. } => PortFailure::TooLarge,
        ParseError::TooMany { .. } => PortFailure::TooMany,
        ParseError::Malformed { .. } => PortFailure::Malformed,
        ParseError::WrongPort { .. } => PortFailure::WrongPort,
        _ => PortFailure::Rejected,
    }
}


fn add_skipped(left: &Skipped, right: &Skipped) -> Skipped {
    Skipped {
        unparsable: left.unparsable + right.unparsable,
        bad_field: left.bad_field + right.bad_field,
        dropped_display: left.dropped_display + right.dropped_display,
        control_bytes: left.control_bytes + right.control_bytes,
    }
}


/// Maps a failed runner call to its category.
pub fn run_failure_category(failure: &RunFailure) -> PortFailure {
    match failure {
        RunFailure::TimedOut => PortFailure::TimedOut,
        RunFailure::TooLarge => PortFailure::TooLarge,
        RunFailure::Failed { .. } => PortFailure::Failed,
        RunFailure::Spawn => PortFailure::Spawn,
        RunFailure::Io | RunFailure::Unwaitable => PortFailure::Io,
        RunFailure::Refused => PortFailure::Rejected,
    }
}


/// Bytes charged to the host budget for a failed run: the worst case when the output is unknown, what was read after a bad exit, nothing when nothing ran.
pub fn charge_of(failure: &RunFailure, max_port_bytes: u64) -> u64 {
    match failure {
        RunFailure::Failed { read, .. } => *read,
        RunFailure::Spawn | RunFailure::Refused => 0,
        RunFailure::TooLarge | RunFailure::TimedOut | RunFailure::Io | RunFailure::Unwaitable => max_port_bytes,
    }
}


fn read_port(port: &str, context: &Context) -> (Result<Parsed, PortFailure>, u64) {
    let timeout = Duration::from_secs(context.limits.port_timeout_seconds);
    match (context.run)(port, context.limits.max_port_bytes, timeout) {
        Err(failure) => (Err(run_failure_category(&failure)), charge_of(&failure, context.limits.max_port_bytes)),
        Ok(bytes) => {
            let charged = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let parsed = parse_lldpd_port(bytes.as_slice(), context.local_host, port, context.now, context.limits);
            (parsed.map_err(|error| failure_of(&error)), charged)
        }
    }
}


fn run_port<'a>(mut progress: Progress<'a>, port: &str, context: &Context) -> Progress<'a> {
    let (outcome, charged) = read_port(port, context);
    progress.read.ports_run += 1;
    progress.consumed = progress.consumed.saturating_add(charged);
    match outcome {
        Ok(parsed) => {
            progress.read.skipped = add_skipped(&progress.read.skipped, &parsed.skipped);
            progress.read.observations.extend(parsed.observations);
        }
        Err(failure) => progress.read.failed_ports.push((port.to_string(), failure)),
    }
    progress
}


fn step<'a>(mut progress: Progress<'a>, port: &str, context: &Context) -> Progress<'a> {
    let elapsed = (progress.clock)().saturating_duration_since(progress.started);
    if progress.consumed >= context.limits.max_host_read_bytes {
        progress.read.skipped_budget += 1;
        progress
    } else if elapsed > Duration::from_secs(context.limits.max_host_seconds) {
        progress.read.skipped_time += 1;
        progress
    } else {
        run_port(progress, port, context)
    }
}


/// Refuses a per-port deadline outside its range, or a host time budget below it or above its ceiling.
pub fn check_times(limits: &Limits) -> Result<(), ParseError> {
    let port_range = MIN_PORT_TIMEOUT_SECONDS..=MAX_PORT_TIMEOUT_SECONDS;
    if !port_range.contains(&limits.port_timeout_seconds) {
        Err(ParseError::InvalidPortSeconds {
            value: limits.port_timeout_seconds,
            min: MIN_PORT_TIMEOUT_SECONDS,
            max: MAX_PORT_TIMEOUT_SECONDS,
        })
    } else if limits.max_host_seconds < limits.port_timeout_seconds || limits.max_host_seconds > MAX_HOST_SECONDS_CEILING {
        Err(ParseError::InvalidHostSeconds {
            budget: limits.max_host_seconds,
            per_port: limits.port_timeout_seconds,
            ceiling: MAX_HOST_SECONDS_CEILING,
        })
    } else {
        Ok(())
    }
}


/// Runs `run` once per distinct valid port (at most `max_interfaces`), stopping at `max_host_read_bytes` or `max_host_seconds` on `clock`; a failed port never fails the host.
pub fn collect_host(local_host: &str, ports: &[String], now: i64, limits: &Limits, run: RunPortFn, clock: ClockFn) -> Result<HostRead, ParseError> {
    check_host(local_host, limits)?;
    check_port_bytes(limits)?;
    check_times(limits)?;
    let mut seen = BTreeSet::new();
    let distinct = ports.iter().filter(|port| seen.insert(port.as_str())).collect::<Vec<_>>();
    let valid = distinct.iter().filter(|port| valid_port(port)).collect::<Vec<_>>();
    let selected = valid.iter().take(limits.max_interfaces).collect::<Vec<_>>();
    let context = Context {
        local_host,
        now,
        limits,
        run,
    };
    let started = clock();
    let start = Progress {
        read: HostRead {
            observations: Vec::new(),
            skipped: Skipped::default(),
            failed_ports: Vec::new(),
            ports_run: 0,
            skipped_budget: 0,
            skipped_time: 0,
            refused_ports: distinct.len() - valid.len(),
            excess_ports: valid.len() - selected.len(),
        },
        consumed: 0,
        started,
        clock,
    };
    let read = selected.into_iter().fold(start, |progress, port| step(progress, port, &context)).read;
    let failed = read.failed_ports.len();
    let skipped = read.skipped_budget + read.skipped_time;
    if failed + skipped > 0 {
        tracing::warn!(failed, skipped, "port reads failed or skipped");
    }
    Ok(read)
}

use crate::error::ParseError;
use crate::limits::Limits;
use crate::lldp::{check_host, check_port_bytes, parse_lldpd_port};
use crate::model::{Observation, Parsed, Skipped};
use crate::ports::valid_port;
use crate::types::RunPortFn;
use std::collections::BTreeSet;


/// Why one port's read produced no observations; a category only, never input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFailure {
    Io,
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
    pub refused_ports: usize,
}


struct Progress {
    read: HostRead,
    consumed: u64,
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


fn read_port(port: &str, context: &Context) -> (Result<Parsed, PortFailure>, u64) {
    match (context.run)(port, context.limits.max_port_bytes) {
        Err(_) => (Err(PortFailure::Io), 0),
        Ok(bytes) => {
            let charged = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let parsed = parse_lldpd_port(bytes.as_slice(), context.local_host, port, context.now, context.limits);
            (parsed.map_err(|error| failure_of(&error)), charged)
        }
    }
}


fn step(mut progress: Progress, port: &str, context: &Context) -> Progress {
    if progress.consumed >= context.limits.max_host_read_bytes {
        progress.read.skipped_budget += 1;
    } else {
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
    }
    progress
}


/// Runs `run` once per distinct valid port (at most `max_interfaces`), stopping at `max_host_read_bytes`; a failed port never fails the host.
pub fn collect_host(local_host: &str, ports: &[String], now: i64, limits: &Limits, run: RunPortFn) -> Result<HostRead, ParseError> {
    check_host(local_host, limits)?;
    check_port_bytes(limits)?;
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
    let start = Progress {
        read: HostRead {
            observations: Vec::new(),
            skipped: Skipped::default(),
            failed_ports: Vec::new(),
            ports_run: 0,
            skipped_budget: 0,
            refused_ports: distinct.len() - selected.len(),
        },
        consumed: 0,
    };
    let read = selected.into_iter().fold(start, |progress, port| step(progress, port, &context)).read;
    let failed = read.failed_ports.len();
    let skipped_budget = read.skipped_budget;
    if failed + skipped_budget > 0 {
        tracing::warn!(failed, skipped_budget, "port reads failed or skipped");
    }
    Ok(read)
}

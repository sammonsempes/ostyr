//! One scan tick: EVE lines in, stored files read under the caps and scanned, ECS events and counters out.


use crate::error::NdrError;
use crate::event::{match_event, parse_line, Parsed};
use crate::exec::{run_bounded, Captured};
use crate::model::{Limits, Loaded, Scanned, Sighting, TickOutcome, Yr};
use crate::reader::load_stored;
use crate::rules::{describe, Rules};
use crate::types::Groups;
use serde::Deserialize;
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use time::OffsetDateTime;


const MAX_IDENTIFIER_CHARS: usize = 128;


#[derive(Debug, Deserialize)]
pub struct YrLine {
    pub rules: Vec<YrRule>,
}


#[derive(Debug, Deserialize)]
pub struct YrRule {
    pub identifier: String,
}


/// A YARA identifier: ASCII letters, digits and `_`, at most `MAX_IDENTIFIER_CHARS`.
pub fn is_identifier(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_IDENTIFIER_CHARS && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}


/// The `yr scan` arguments: rules compiled, NDJSON, one thread, no warnings and no console output; `--` so no path can read as an option.
pub fn scan_args(compiled: &Path, target: &Path) -> Vec<OsString> {
    let head = [
        "scan",
        "--compiled-rules",
        "--output-format",
        "ndjson",
        "--threads",
        "1",
        "--no-mmap",
        "--disable-console-logs",
        "--disable-warnings",
        "--",
    ];
    head.iter()
        .map(OsString::from)
        .chain([compiled.as_os_str().to_os_string(), target.as_os_str().to_os_string()])
        .collect()
}


/// Logs the class of a bad result line, never its text.
pub fn log_bad_line(error: &serde_json::Error) {
    let kind = error.classify();
    tracing::debug!(kind = ?kind, "a yr line is not a result");
}


/// The rule names of the NDJSON lines; any line that is not a result line (an error or a warning of `yr`) or any bad identifier gives `None`.
pub fn parse_matches(bytes: &[u8]) -> Option<Vec<String>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .try_fold(Vec::new(), |mut names, line| {
            let parsed = serde_json::from_slice::<YrLine>(line).inspect_err(log_bad_line).ok()?;
            names.extend(parsed.rules.into_iter().map(|rule| rule.identifier));
            Some(names)
        })
        .filter(|names| names.iter().all(|name| is_identifier(name)))
}


/// Turns one run into a verdict; the deadline and the output bound win over the exit status, and an exit other than success is a failure.
pub fn classify(run: &Captured) -> Scanned {
    match (run.timed_out, run.cut, run.exited_ok) {
        (true, _, _) => Scanned::TimedOut,
        (_, true, _) => Scanned::OutputCut,
        (_, _, false) => Scanned::Failed,
        _ => parse_matches(&run.bytes).map_or(Scanned::Failed, Scanned::Names),
    }
}


/// Scans a private copy of `content` with `yr scan`; the copy is removed when this returns, whatever the outcome.
pub fn matched_rules(yr: &Yr, rules: &Rules, content: &[u8], limits: &Limits) -> Result<Scanned, NdrError> {
    let mut copy = NamedTempFile::new_in(rules.workspace.path()).map_err(NdrError::Workspace)?;
    copy.write_all(content).map_err(NdrError::Workspace)?;
    copy.flush().map_err(NdrError::Workspace)?;
    let run = run_bounded(yr, &scan_args(&rules.compiled, copy.path()), limits.max_output_bytes, limits.scan_timeout)?;
    Ok(classify(&run))
}


/// The fixed inputs of one tick.
pub struct Context<'a> {
    pub yr: &'a Yr,
    pub rules: &'a Rules,
    pub root: &'a Path,
    pub limits: &'a Limits,
}


/// Counts one scan result and turns every matching rule into one event per sighting of the file.
pub fn record_scan(outcome: &mut TickOutcome, scanned: Result<Scanned, NdrError>, sightings: &[Sighting], size: u64, now: OffsetDateTime) {
    match scanned {
        Ok(Scanned::Names(names)) => {
            outcome.counts.scanned += 1;
            outcome.counts.matched += u64::from(!names.is_empty());
            let events = sightings
                .iter()
                .flat_map(|sighting| names.iter().map(|name| match_event(sighting, size, name, now)));
            outcome.events.extend(events);
        }
        Ok(Scanned::TimedOut) => outcome.counts.timed_out += 1,
        Ok(Scanned::OutputCut) => outcome.counts.output_cut += 1,
        Ok(Scanned::Failed) => {
            tracing::warn!("yr gave an unexpected result");
            outcome.counts.failed += 1;
        }
        Err(error) => {
            let cause = describe(&error);
            tracing::warn!(cause = %cause, "scan failed");
            outcome.counts.failed += 1;
        }
    }
}


/// Reads and scans one stored file once, whatever the number of `fileinfo` lines that name it.
pub fn scan_group(context: &Context, sha256: &str, sightings: &[Sighting], now: OffsetDateTime, outcome: &mut TickOutcome) {
    match load_stored(context.root, sha256, context.limits.max_file_bytes) {
        Ok(Loaded::Content(content)) => {
            let size = content.len() as u64;
            record_scan(
                outcome,
                matched_rules(context.yr, context.rules, &content, context.limits),
                sightings,
                size,
                now,
            );
        }
        Ok(Loaded::TooLarge) => outcome.counts.too_large += 1,
        Ok(Loaded::Refused) => outcome.counts.refused += 1,
        Ok(Loaded::Missing) => outcome.counts.missing += 1,
        Err(error) => {
            let kind = error.kind();
            tracing::warn!(kind = ?kind, "filestore read failed");
            outcome.counts.failed += 1;
        }
    }
}


/// Keeps at most `max_sightings_per_file` lines per hash; the rest is counted `sightings_omitted`.
pub fn add_sighting(groups: &mut Groups, sighting: Sighting, limits: &Limits, outcome: &mut TickOutcome) {
    let sightings = groups.entry(sighting.sha256.clone()).or_default();
    if sightings.len() < limits.max_sightings_per_file {
        sightings.push(sighting);
    } else {
        outcome.counts.sightings_omitted += 1;
    }
}


/// Counts one line and files its sighting under its hash.
pub fn read_line(groups: &mut Groups, line: &str, limits: &Limits, outcome: &mut TickOutcome) {
    outcome.counts.lines += 1;
    match parse_line(line, limits.max_line_bytes) {
        Parsed::Ignored => {}
        Parsed::Malformed => outcome.counts.malformed += 1,
        Parsed::Stored(sighting) => add_sighting(groups, sighting, limits, outcome),
    }
}


/// Scans one hash, or defers it once `max_files_per_tick` files are in this tick.
pub fn handle_group(context: &Context, sha256: &str, sightings: &[Sighting], now: OffsetDateTime, outcome: &mut TickOutcome) {
    match file_total(outcome) >= context.limits.max_files_per_tick as u64 {
        true => defer(outcome, sha256),
        false => scan_group(context, sha256, sightings, now, outcome),
    }
}


/// Counts a hash as deferred and keeps it for the caller.
pub fn defer(outcome: &mut TickOutcome, sha256: &str) {
    outcome.counts.deferred += 1;
    outcome.deferred_hashes.push(sha256.to_string());
}


/// Files that have taken a slot of the tick so far.
pub fn file_total(outcome: &TickOutcome) -> u64 {
    let counts = &outcome.counts;
    counts.scanned + counts.too_large + counts.refused + counts.timed_out + counts.output_cut + counts.missing + counts.failed
}


/// Reads at most `max_lines_per_tick` lines, groups them by hash and scans each of at most `max_files_per_tick` hashes once.
pub fn scan_tick<'a>(yr: &Yr, rules: &Rules, root: &Path, lines: impl Iterator<Item = &'a str>, limits: &Limits, now: OffsetDateTime) -> TickOutcome {
    let mut outcome = TickOutcome::default();
    let mut groups = Groups::new();
    lines
        .take(limits.max_lines_per_tick)
        .for_each(|line| read_line(&mut groups, line, limits, &mut outcome));
    let context = Context { yr, rules, root, limits };
    groups
        .iter()
        .for_each(|(sha256, sightings)| handle_group(&context, sha256, sightings, now, &mut outcome));
    outcome
}

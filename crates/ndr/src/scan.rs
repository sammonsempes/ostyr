//! One scan tick: EVE lines in, stored files read under the caps and scanned, ECS events and counters out.


use crate::event::{match_event, parse_line, Parsed};
use crate::model::{Limits, Loaded, Sighting, TickOutcome};
use crate::reader::load_stored;
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use yara_x::errors::ScanError;
use yara_x::{Rules, Scanner};


/// Names of the rules that match `content`; a scanner is built per file so a timeout leaves nothing behind.
pub fn matched_rules(rules: &Rules, content: &[u8], timeout: Duration) -> Result<Vec<String>, ScanError> {
    let mut scanner = Scanner::new(rules);
    scanner.set_timeout(timeout);
    let results = scanner.scan(content)?;
    Ok(results.matching_rules().map(|rule| rule.identifier().to_string()).collect())
}


/// Counts one scan result and turns every matching rule into an event.
pub fn record_scan(outcome: &mut TickOutcome, scanned: Result<Vec<String>, ScanError>, sighting: &Sighting, size: u64, now: OffsetDateTime) {
    match scanned {
        Ok(names) => {
            outcome.counts.scanned += 1;
            outcome.counts.matched += u64::from(!names.is_empty());
            outcome.events.extend(names.iter().map(|name| match_event(sighting, size, name, now)));
        }
        Err(ScanError::Timeout) => outcome.counts.timed_out += 1,
        Err(error) => {
            let kind = format!("{error}");
            tracing::warn!(kind = %kind, "scan failed");
            outcome.counts.failed += 1;
        }
    }
}


/// Reads and scans one sighting.
pub fn scan_sighting(rules: &Rules, root: &Path, sighting: &Sighting, limits: &Limits, now: OffsetDateTime, outcome: &mut TickOutcome) {
    match load_stored(root, &sighting.sha256, limits.max_file_bytes) {
        Ok(Loaded::Content(content)) => {
            let size = content.len() as u64;
            record_scan(outcome, matched_rules(rules, &content, limits.scan_timeout), sighting, size, now);
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


/// Counts one line and either scans its file or defers it once `max_files_per_tick` files are in this tick.
pub fn handle_line(rules: &Rules, root: &Path, line: &str, limits: &Limits, now: OffsetDateTime, outcome: &mut TickOutcome) {
    outcome.counts.lines += 1;
    match parse_line(line, limits.max_line_bytes) {
        Parsed::Ignored => {}
        Parsed::Malformed => outcome.counts.malformed += 1,
        Parsed::Stored(_) if file_total(outcome) >= limits.max_files_per_tick as u64 => outcome.counts.deferred += 1,
        Parsed::Stored(sighting) => scan_sighting(rules, root, &sighting, limits, now, outcome),
    }
}


/// Files that have taken a slot of the tick so far.
pub fn file_total(outcome: &TickOutcome) -> u64 {
    let counts = &outcome.counts;
    counts.scanned + counts.too_large + counts.refused + counts.timed_out + counts.missing + counts.failed
}


/// Reads at most `max_lines_per_tick` lines, scans at most `max_files_per_tick` of the stored files they name; the rest of the lines is never read.
pub fn scan_tick<'a>(rules: &Rules, root: &Path, lines: impl Iterator<Item = &'a str>, limits: &Limits, now: OffsetDateTime) -> TickOutcome {
    let mut outcome = TickOutcome::default();
    lines
        .take(limits.max_lines_per_tick)
        .for_each(|line| handle_line(rules, root, line, limits, now, &mut outcome));
    outcome
}

use crate::atomic::write_atomic;
use crate::error::RpzError;
use crate::model::{Entry, RunSummary, SkipReason};
use crate::policy::Policy;
use crate::select::{compile_allow, decide, reason_key, Allow};
use crate::serial::advance;
use crate::types::Counts;
use crate::zone::{apply_cap, render_zone};
use intel_feeds::lines::{numbered_lines, NumberedLine};
use intel_feeds::model::Ioc;
use std::collections::btree_map::Entry as Slot;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use time::OffsetDateTime;
use tracing::{debug, warn};


pub fn count(counts: &mut Counts, key: &'static str) {
    *counts.entry(key).or_insert(0) += 1;
}


pub fn open_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    Ok(Box::new(BufReader::new(File::open(path)?)))
}


/// A blank line is nothing; a line that is not valid UTF-8, too long or not an IOC is malformed.
pub fn parse_line(line: NumberedLine) -> Option<Result<Ioc, SkipReason>> {
    match line.text {
        Err(error) => {
            warn!(line = line.number, %error, "IOC line unreadable");
            Some(Err(SkipReason::MalformedLine))
        }
        Ok(text) if text.trim().is_empty() => None,
        Ok(text) => Some(serde_json::from_str::<Ioc>(&text).map_err(|error| {
            warn!(line = line.number, %error, "IOC line is not an IOC");
            SkipReason::MalformedLine
        })),
    }
}


/// Two IOCs with one owner name: the more confident one stays, the other is a counted duplicate.
pub fn insert_entry(entries: &mut BTreeMap<String, Entry>, entry: Entry, skipped: &mut Counts) {
    match entries.entry(entry.owner.clone()) {
        Slot::Vacant(slot) => {
            slot.insert(entry);
        }
        Slot::Occupied(mut slot) => {
            count(skipped, reason_key(SkipReason::Duplicate));
            if slot.get().confidence < entry.confidence {
                slot.insert(entry);
            }
        }
    }
}


/// Reads the JSON lines, decides each IOC, counts every skip; a read failure ends the run before anything is written.
pub fn collect_entries(
    input: &mut dyn BufRead,
    policy: &Policy,
    allow: &Allow,
    now: OffsetDateTime,
    skipped: &mut Counts,
) -> io::Result<BTreeMap<String, Entry>> {
    let mut entries = BTreeMap::new();
    numbered_lines(input).try_for_each(|line| {
        if let Some(parsed) = parse_line(line?) {
            match parsed.and_then(|ioc| decide(&ioc, policy, allow, now)) {
                Ok(entry) => insert_entry(&mut entries, entry, skipped),
                Err(reason) => count(skipped, reason_key(reason)),
            }
        }
        Ok::<(), io::Error>(())
    })?;
    Ok(entries)
}


/// Generates the zone: the serial is persisted first, then the zone replaces the previous file atomically.
pub fn generate(policy: &Policy, input: &mut dyn BufRead, now: OffsetDateTime, counter: &Path, output: &Path) -> Result<RunSummary, RpzError> {
    let allow = compile_allow(&policy.allowlist)?;
    let mut summary = RunSummary::default();
    let entries = collect_entries(input, policy, &allow, now, &mut summary.skipped)?;
    let (kept, dropped) = apply_cap(entries.into_values().collect(), policy.max_records);
    if dropped > 0 {
        warn!(dropped, "zone size cap reached, lowest confidence entries dropped");
    }
    summary.dropped_by_cap = dropped;
    kept.iter().for_each(|entry| count(&mut summary.published, entry.action));
    summary.records = kept.iter().map(|entry| crate::zone::record_count(entry) as u64).sum();
    summary.serial = advance(counter, now)?;
    let mut zone = Vec::new();
    render_zone(policy, summary.serial, &kept, &mut zone)?;
    write_atomic(output, &zone)?;
    debug!(serial = summary.serial, records = summary.records, "zone written");
    Ok(summary)
}

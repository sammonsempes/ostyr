use crate::atomic::write_atomic;
use crate::error::RpzError;
use crate::limits::{MAX_IOC_LINES, MAX_IOC_SOURCE_BYTES};
use crate::model::{Entry, RunSummary, SkipReason};
use crate::policy::Policy;
use crate::select::{compile_allow, decide, reason_key, Allow};
use crate::serial::advance;
use crate::types::{Counts, Opened};
use crate::zone::{apply_cap, render_zone};
use core_config::error::ConfigError;
use core_config::parse::open_regular;
use intel_feeds::lines::{numbered_lines, NumberedLine};
use intel_feeds::model::Ioc;
use std::collections::btree_map::Entry as Slot;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use time::OffsetDateTime;
use tracing::{debug, warn};


pub fn count(counts: &mut Counts, key: &'static str) {
    *counts.entry(key).or_insert(0) += 1;
}


/// A refused source keeps its own label, not the one core-config's helper gives a watched file.
pub fn source_refusal(error: ConfigError) -> io::Error {
    match error {
        ConfigError::WatchedFile { file, reason } => io::Error::other(format!("IOC source `{file}` refused: {reason}")),
        other => io::Error::other(other),
    }
}


/// Opens a regular file only (a FIFO or device is refused without blocking) of at most `MAX_IOC_SOURCE_BYTES`, with the length `fstat` gave.
pub fn open_file_sized(path: &Path) -> io::Result<Opened> {
    let handle = open_regular(path, &path.display().to_string()).map_err(source_refusal)?;
    let length = handle.metadata()?.len();
    if length > MAX_IOC_SOURCE_BYTES {
        Err(io::Error::other(format!("IOC source larger than {MAX_IOC_SOURCE_BYTES} bytes")))
    } else {
        Ok((Box::new(BufReader::new(handle.take(MAX_IOC_SOURCE_BYTES + 1))), Some(length)))
    }
}


/// The reader of `open_file_sized` alone.
pub fn open_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    open_file_sized(path).map(|(reader, _length)| reader)
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
    expected: Option<u64>,
    policy: &Policy,
    allow: &Allow,
    now: OffsetDateTime,
    skipped: &mut Counts,
) -> io::Result<BTreeMap<String, Entry>> {
    let mut entries = BTreeMap::new();
    let mut capped = Read::take(&mut *input, MAX_IOC_SOURCE_BYTES);
    numbered_lines(&mut capped).try_for_each(|line| {
        let numbered = line?;
        if numbered.number > MAX_IOC_LINES {
            Err(io::Error::other(format!("IOC source has more than {MAX_IOC_LINES} lines")))
        } else {
            if let Some(parsed) = parse_line(numbered) {
                match parsed.and_then(|ioc| decide(&ioc, policy, allow, now)) {
                    Ok(entry) => insert_entry(&mut entries, entry, skipped),
                    Err(reason) => count(skipped, reason_key(reason)),
                }
            }
            Ok::<(), io::Error>(())
        }
    })?;
    let consumed = MAX_IOC_SOURCE_BYTES - capped.limit();
    if expected.is_some_and(|length| consumed < length) {
        Err(io::Error::other("IOC source shrank while it was read"))
    } else if capped.into_inner().fill_buf()?.is_empty() {
        Ok(entries)
    } else {
        Err(io::Error::other(format!(
            "IOC source grew past {MAX_IOC_SOURCE_BYTES} bytes while it was read"
        )))
    }
}


/// Generates the zone: the serial is persisted first, then the zone replaces the previous file atomically.
pub fn generate(policy: &Policy, input: &mut dyn BufRead, now: OffsetDateTime, counter: &Path, output: &Path) -> Result<RunSummary, RpzError> {
    generate_sized(policy, input, None, now, counter, output)
}


/// `generate` for a source whose opened length is known: a read shorter than it is a failed round.
pub fn generate_sized(
    policy: &Policy,
    input: &mut dyn BufRead,
    expected: Option<u64>,
    now: OffsetDateTime,
    counter: &Path,
    output: &Path,
) -> Result<RunSummary, RpzError> {
    let allow = compile_allow(&policy.allowlist)?;
    let mut summary = RunSummary::default();
    let entries = collect_entries(input, expected, policy, &allow, now, &mut summary.skipped)?;
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

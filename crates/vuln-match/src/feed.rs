//! OSV archive loader: checksum, sequential bounded zip reading, per-source licences.

use crate::error::FeedError;
use crate::limits::{
    CENTRAL_SIGNATURE, DESCRIPTOR_FLAG, DESCRIPTOR_LENGTHS, DESCRIPTOR_SIGNATURE, ENCRYPTED_FLAG, EOCD_SIGNATURE, LOCAL_COMPRESSED_AT,
    LOCAL_EXTRA_AT, LOCAL_FIXED_BYTES, LOCAL_FLAGS_AT, LOCAL_METHOD_AT, LOCAL_NAME_AT, LOCAL_SIGNATURE, MAGIC_BYTES, MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_LOGGED_NAME_CHARS, MAX_RETAINED_ITEMS, MAX_TOTAL_BYTES, METHOD_DEFLATED,
    METHOD_STORED, RATIO_FLOOR_BYTES, ZIP64_EOCD_SIGNATURE,
};
use crate::model::{FeedLimits, FeedReport, FeedSettings, LoadedRecord, LocalHeader, OsvRecord, ScanState};
use crate::osv::parse_record;
use flate2::bufread::DeflateDecoder;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub fn default_limits() -> FeedLimits {
    FeedLimits {
        max_archive_bytes: MAX_ARCHIVE_BYTES,
        max_entries: MAX_ARCHIVE_ENTRIES,
        max_entry_bytes: MAX_ENTRY_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
        max_ratio: MAX_COMPRESSION_RATIO,
        ratio_floor_bytes: RATIO_FLOOR_BYTES,
        max_retained_items: MAX_RETAINED_ITEMS,
    }
}


pub fn load_feed(path: &Path, settings: &FeedSettings, limits: &FeedLimits) -> Result<FeedReport, FeedError> {
    load_feed_reader(File::open(path)?, settings, limits)
}


/// The bytes are read once, checksummed, then walked entry by entry through their local headers from that same buffer.
pub fn load_feed_reader<Source: Read>(reader: Source, settings: &FeedSettings, limits: &FeedLimits) -> Result<FeedReport, FeedError> {
    (!settings.allowed_licences.is_empty())
        .then_some(())
        .ok_or(FeedError::NoAllowedLicences)?;
    let mut bytes = Vec::new();
    reader.take(limits.max_archive_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    (bytes.len() as u64 <= limits.max_archive_bytes)
        .then_some(())
        .ok_or(FeedError::ArchiveTooLarge {
            max: limits.max_archive_bytes,
        })?;
    let actual = format!("{:x}", Sha256::digest(&bytes));
    actual
        .eq_ignore_ascii_case(settings.sha256.trim())
        .then_some(())
        .ok_or(FeedError::ChecksumMismatch {
            expected: settings.sha256.clone(),
            actual,
        })?;
    let mut input = bytes.as_slice();
    let state = (0..=limits.max_entries).try_fold(ScanState::default(), |state, _| scan_step(&mut input, settings, limits, state))?;
    Ok(state.report)
}


/// Splits `length` bytes off the front of the input.
pub fn take_bytes<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], FeedError> {
    let (head, tail) = (*input).split_at_checked(length).ok_or(FeedError::Truncated)?;
    *input = tail;
    Ok(head)
}


fn field<const WIDTH: usize>(bytes: &[u8], at: usize) -> Result<[u8; WIDTH], FeedError> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<WIDTH>().copied())
        .ok_or(FeedError::Truncated)
}


/// Fields of a local header; nothing is read from the central directory.
pub fn parse_local(fixed: &[u8]) -> Result<LocalHeader, FeedError> {
    Ok(LocalHeader {
        flags: u16::from_le_bytes(field(fixed, LOCAL_FLAGS_AT)?),
        method: u16::from_le_bytes(field(fixed, LOCAL_METHOD_AT)?),
        compressed: u32::from_le_bytes(field(fixed, LOCAL_COMPRESSED_AT)?) as usize,
        name_len: u16::from_le_bytes(field(fixed, LOCAL_NAME_AT)?) as usize,
        extra_len: u16::from_le_bytes(field(fixed, LOCAL_EXTRA_AT)?) as usize,
    })
}


fn scan_step(input: &mut &[u8], settings: &FeedSettings, limits: &FeedLimits, mut state: ScanState) -> Result<ScanState, FeedError> {
    if state.done {
        Ok(state)
    } else {
        let magic = field::<MAGIC_BYTES>(take_bytes(input, MAGIC_BYTES)?, 0)?;
        if magic == LOCAL_SIGNATURE {
            scan_entry(input, settings, limits, state)
        } else if [CENTRAL_SIGNATURE, EOCD_SIGNATURE, ZIP64_EOCD_SIGNATURE].contains(&magic) {
            state.done = true;
            Ok(state)
        } else {
            Err(FeedError::BadHeader)
        }
    }
}


/// Every element a record keeps in memory: aliases, affected entries, ranges, versions and events.
pub fn retained_items(record: &OsvRecord) -> u64 {
    let affected: usize = record
        .affected
        .iter()
        .map(|entry| 1 + entry.versions.len() + entry.ranges.iter().map(|range| 1 + range.events.len()).sum::<usize>())
        .sum();
    (record.aliases.len() + affected) as u64
}


pub fn is_safe_name(raw: &[u8]) -> bool {
    let name = String::from_utf8_lossy(raw);
    let drive = raw.get(1) == Some(&b':');
    !name.chars().any(char::is_control) && !drive && !name.starts_with(['/', '\\']) && !name.split(['/', '\\']).any(|part| part == "..")
}


/// Licence of the longest configured id prefix matching the record id, if any.
pub fn licence_of(settings: &FeedSettings, record_id: &str) -> Option<String> {
    settings
        .prefix_licences
        .iter()
        .filter(|(prefix, _)| record_id.starts_with(prefix.as_str()))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, licence)| licence.clone())
}


/// Inflates from the front of the source; returns the content and the compressed bytes the decoder really consumed.
fn inflate(source: &mut &[u8], cap: u64) -> Result<(Vec<u8>, u64), FeedError> {
    let before = source.len();
    let mut bytes = Vec::new();
    DeflateDecoder::new(&mut *source).take(cap).read_to_end(&mut bytes)?;
    Ok((bytes, (before - source.len()) as u64))
}


/// Skips the data descriptor after a deflate stream: optional signature, then 32-bit or 64-bit sizes, followed by a known record.
fn skip_descriptor(input: &mut &[u8]) -> Result<(), FeedError> {
    let lead = if input.starts_with(&DESCRIPTOR_SIGNATURE) { MAGIC_BYTES } else { 0 };
    let length = DESCRIPTOR_LENGTHS
        .iter()
        .map(|width| width + lead)
        .find(|length| {
            input
                .get(*length..)
                .and_then(|after| after.first_chunk::<MAGIC_BYTES>())
                .is_some_and(|magic| [LOCAL_SIGNATURE, CENTRAL_SIGNATURE, EOCD_SIGNATURE, ZIP64_EOCD_SIGNATURE].contains(magic))
        })
        .ok_or(FeedError::BadDescriptor)?;
    take_bytes(input, length)?;
    Ok(())
}


/// Content of one entry and the compressed bytes it really occupied; the sizes of the local header are never trusted.
fn read_content(input: &mut &[u8], header: &LocalHeader, name: &str, limits: &FeedLimits) -> Result<(Vec<u8>, u64), FeedError> {
    let unsupported = || FeedError::UnsupportedMethod { name: name.to_string() };
    (header.flags & ENCRYPTED_FLAG == 0).then_some(()).ok_or_else(unsupported)?;
    let cap = limits.max_entry_bytes.saturating_add(1);
    let descriptor = header.flags & DESCRIPTOR_FLAG != 0;
    let (bytes, consumed) = match (header.method, descriptor) {
        (METHOD_STORED, false) => {
            let data = take_bytes(input, header.compressed)?;
            (data.iter().take(cap as usize).copied().collect(), data.len() as u64)
        }
        (METHOD_DEFLATED, false) => {
            let mut data = take_bytes(input, header.compressed)?;
            inflate(&mut data, cap)?
        }
        (METHOD_DEFLATED, true) => inflate(input, cap)?,
        _ => Err(unsupported())?,
    };
    (bytes.len() as u64 <= limits.max_entry_bytes)
        .then_some(())
        .ok_or(FeedError::EntryTooLarge {
            name: name.to_string(),
            max: limits.max_entry_bytes,
        })?;
    if descriptor {
        skip_descriptor(input)?;
    }
    Ok((bytes, consumed))
}


fn scan_entry(input: &mut &[u8], settings: &FeedSettings, limits: &FeedLimits, mut state: ScanState) -> Result<ScanState, FeedError> {
    (state.entries < limits.max_entries).then_some(()).ok_or(FeedError::TooManyEntries {
        count: state.entries as u64 + 1,
        max: limits.max_entries,
    })?;
    let header = parse_local(take_bytes(input, LOCAL_FIXED_BYTES)?)?;
    let raw_name = take_bytes(input, header.name_len)?;
    take_bytes(input, header.extra_len)?;
    let name: String = String::from_utf8_lossy(raw_name).chars().take(MAX_LOGGED_NAME_CHARS).collect();
    is_safe_name(raw_name).then_some(()).ok_or(FeedError::UnsafeName { name: name.clone() })?;
    state.entries += 1;
    if raw_name.ends_with(b"/") {
        take_bytes(input, header.compressed)?;
        Ok(state)
    } else {
        let (bytes, consumed) = read_content(input, &header, &name, limits)?;
        let size = bytes.len() as u64;
        let over_ratio = size > limits.ratio_floor_bytes && size > limits.max_ratio.saturating_mul(consumed.max(1));
        (!over_ratio).then_some(()).ok_or(FeedError::RatioExceeded {
            name: name.clone(),
            max: limits.max_ratio,
        })?;
        state.total = state.total.saturating_add(size);
        (state.total <= limits.max_total_bytes)
            .then_some(())
            .ok_or(FeedError::TotalTooLarge { max: limits.max_total_bytes })?;
        match String::from_utf8(bytes).ok().and_then(|text| parse_record(&text).ok()) {
            Some(record) => match licence_of(settings, &record.id).filter(|licence| settings.allowed_licences.contains(licence)) {
                Some(licence) => {
                    state.report.retained_items = state.report.retained_items.saturating_add(retained_items(&record));
                    (state.report.retained_items <= limits.max_retained_items)
                        .then_some(())
                        .ok_or(FeedError::TooManyRetained {
                            max: limits.max_retained_items,
                        })?;
                    state.report.records.push(LoadedRecord { record, licence });
                }
                None => state.report.dropped_by_licence += 1,
            },
            None => {
                state.report.bad_entries += 1;
                tracing::warn!(entry = ?name, "skipped an unparsable feed entry");
            }
        }
        Ok(state)
    }
}

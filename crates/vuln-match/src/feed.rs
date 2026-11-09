//! OSV archive loader: checksum, bounded zip reading, per-source licences.

use crate::error::FeedError;
use crate::limits::{
    MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_LOGGED_NAME_CHARS, MAX_TOTAL_BYTES, RATIO_FLOOR_BYTES,
};
use crate::model::{FeedLimits, FeedReport, FeedSettings, LoadedRecord};
use crate::osv::parse_record;
use crate::types::Archive;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;


pub fn default_limits() -> FeedLimits {
    FeedLimits {
        max_archive_bytes: MAX_ARCHIVE_BYTES,
        max_entries: MAX_ARCHIVE_ENTRIES,
        max_entry_bytes: MAX_ENTRY_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
        max_ratio: MAX_COMPRESSION_RATIO,
        ratio_floor_bytes: RATIO_FLOOR_BYTES,
    }
}


pub fn load_feed(path: &Path, settings: &FeedSettings, limits: &FeedLimits) -> Result<FeedReport, FeedError> {
    load_feed_reader(File::open(path)?, settings, limits)
}


/// The bytes are read once, checksummed, then parsed from that same buffer.
pub fn load_feed_reader<Source: Read>(reader: Source, settings: &FeedSettings, limits: &FeedLimits) -> Result<FeedReport, FeedError> {
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
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    (archive.len() <= limits.max_entries).then_some(()).ok_or(FeedError::TooManyEntries {
        count: archive.len(),
        max: limits.max_entries,
    })?;
    let (report, _total) = (0..archive.len()).try_fold((FeedReport::default(), u64::MIN), |state, index| {
        scan_entry(&mut archive, index, settings, limits, state)
    })?;
    Ok(report)
}


pub fn is_safe_name(raw: &[u8]) -> bool {
    let name = String::from_utf8_lossy(raw);
    let drive = raw.get(1) == Some(&b':');
    !raw.contains(&0) && !drive && !name.starts_with(['/', '\\']) && !name.split(['/', '\\']).any(|part| part == "..")
}


pub fn licence_of(settings: &FeedSettings, record_id: &str) -> String {
    settings
        .prefix_licences
        .iter()
        .find(|(prefix, _)| record_id.starts_with(prefix.as_str()))
        .map_or_else(|| settings.default_licence.clone(), |(_, licence)| licence.clone())
}


fn scan_entry(
    archive: &mut Archive,
    index: usize,
    settings: &FeedSettings,
    limits: &FeedLimits,
    (mut report, total): (FeedReport, u64),
) -> Result<(FeedReport, u64), FeedError> {
    let mut entry = archive.by_index(index)?;
    let name: String = String::from_utf8_lossy(entry.name_raw()).chars().take(MAX_LOGGED_NAME_CHARS).collect();
    is_safe_name(entry.name_raw())
        .then_some(())
        .ok_or(FeedError::UnsafeName { name: name.clone() })?;
    if entry.is_dir() {
        Ok((report, total))
    } else {
        let mut bytes = Vec::new();
        (&mut entry).take(limits.max_entry_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
        let size = bytes.len() as u64;
        (size <= limits.max_entry_bytes).then_some(()).ok_or(FeedError::EntryTooLarge {
            name: name.clone(),
            max: limits.max_entry_bytes,
        })?;
        let over_ratio = size > limits.ratio_floor_bytes && size > limits.max_ratio.saturating_mul(entry.compressed_size().max(1));
        (!over_ratio).then_some(()).ok_or(FeedError::RatioExceeded {
            name: name.clone(),
            max: limits.max_ratio,
        })?;
        let new_total = total.saturating_add(size);
        (new_total <= limits.max_total_bytes)
            .then_some(())
            .ok_or(FeedError::TotalTooLarge { max: limits.max_total_bytes })?;
        match String::from_utf8(bytes).ok().and_then(|text| parse_record(&text).ok()) {
            Some(record) => {
                let licence = licence_of(settings, &record.id);
                if settings.denied_licences.contains(&licence) {
                    report.dropped_by_licence += 1;
                } else {
                    report.records.push(LoadedRecord { record, licence });
                }
            }
            None => {
                report.bad_entries += 1;
                tracing::warn!(entry = %name, "skipped an unparsable feed entry");
            }
        }
        Ok((report, new_total))
    }
}

//! OSV archive loader: checksum, bounded zip reading, per-source licences.

use crate::error::FeedError;
use crate::limits::{
    CENTRAL_HEADER_MIN_BYTES, EOCD_COUNT_OFFSET, EOCD_OFFSET_OFFSET, EOCD_SIGNATURE, EOCD_SIZE_OFFSET, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES,
    MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_EOCD_SEARCH, MAX_LOGGED_NAME_CHARS, MAX_RETAINED_ITEMS, MAX_TOTAL_BYTES, PAIR, RATIO_FLOOR_BYTES,
    ZIP64_COUNT_OFFSET, ZIP64_EOCD_SIGNATURE, ZIP64_LOCATOR_BYTES, ZIP64_LOCATOR_OFFSET, ZIP64_LOCATOR_SIGNATURE, ZIP64_SIZE_OFFSET,
};
use crate::model::{Directory, FeedLimits, FeedReport, FeedSettings, LoadedRecord, OsvRecord};
use crate::osv::parse_record;
use crate::types::Archive;
use flate2::bufread::DeflateDecoder;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::read::ZipFile;
use zip::{CompressionMethod, ZipArchive};


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


/// The bytes are read once, checksummed, then parsed from that same buffer.
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
    check_directory(&bytes, limits)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice()))?;
    (archive.len() <= limits.max_entries).then_some(()).ok_or(FeedError::TooManyEntries {
        count: archive.len() as u64,
        max: limits.max_entries,
    })?;
    check_disjoint(&mut archive)?;
    let (report, _total) = (0..archive.len()).try_fold((FeedReport::default(), u64::MIN), |state, index| {
        scan_entry(&mut archive, &bytes, index, settings, limits, state)
    })?;
    Ok(report)
}


fn field<const WIDTH: usize>(bytes: &[u8], at: usize) -> Result<[u8; WIDTH], FeedError> {
    at.checked_add(WIDTH)
        .and_then(|end| bytes.get(at..end))
        .and_then(|slice| slice.first_chunk::<WIDTH>().copied())
        .ok_or(FeedError::UnreadableDirectory)
}


/// Entry count and size of the central directory, read the way the zip crate finds it, before the crate indexes it.
pub fn directory_of(bytes: &[u8]) -> Result<Directory, FeedError> {
    let mut candidates = bytes
        .windows(EOCD_SIGNATURE.len())
        .enumerate()
        .skip(bytes.len().saturating_sub(MAX_EOCD_SEARCH))
        .filter(|(_, window)| *window == EOCD_SIGNATURE)
        .map(|(position, _)| position);
    let eocd = candidates.next().ok_or(FeedError::UnreadableDirectory)?;
    candidates.next().is_none().then_some(()).ok_or(FeedError::AmbiguousDirectory)?;
    let count = u16::from_le_bytes(field(bytes, eocd + EOCD_COUNT_OFFSET)?);
    let size = u32::from_le_bytes(field(bytes, eocd + EOCD_SIZE_OFFSET)?);
    let offset = u32::from_le_bytes(field(bytes, eocd + EOCD_OFFSET_OFFSET)?);
    if count == u16::MAX || size == u32::MAX || offset == u32::MAX {
        zip64_directory(bytes, eocd)
    } else {
        Ok(Directory {
            entries: u64::from(count),
            bytes: u64::from(size),
        })
    }
}


fn zip64_directory(bytes: &[u8], eocd: usize) -> Result<Directory, FeedError> {
    let locator = eocd.checked_sub(ZIP64_LOCATOR_BYTES).ok_or(FeedError::UnreadableDirectory)?;
    (field(bytes, locator)? == ZIP64_LOCATOR_SIGNATURE)
        .then_some(())
        .ok_or(FeedError::UnreadableDirectory)?;
    let record = u64::from_le_bytes(field(bytes, locator + ZIP64_LOCATOR_OFFSET)?) as usize;
    (field(bytes, record)? == ZIP64_EOCD_SIGNATURE)
        .then_some(())
        .ok_or(FeedError::UnreadableDirectory)?;
    let entries = u64::from_le_bytes(field(bytes, record + ZIP64_COUNT_OFFSET)?);
    let size = u64::from_le_bytes(field(bytes, record + ZIP64_SIZE_OFFSET)?);
    Ok(Directory { entries, bytes: size })
}


/// Refuses a directory whose count exceeds the cap or what its own size can hold, before the zip crate allocates for it.
pub fn check_directory(bytes: &[u8], limits: &FeedLimits) -> Result<(), FeedError> {
    let directory = directory_of(bytes)?;
    (directory.entries <= limits.max_entries as u64)
        .then_some(())
        .ok_or(FeedError::TooManyEntries {
            count: directory.entries,
            max: limits.max_entries,
        })?;
    let fits = directory.bytes <= bytes.len() as u64 && directory.entries <= directory.bytes / CENTRAL_HEADER_MIN_BYTES;
    fits.then_some(()).ok_or(FeedError::InconsistentDirectory {
        entries: directory.entries,
        bytes: directory.bytes,
    })
}


/// Two entries sharing or overlapping a byte range would let one small record be counted many times.
fn check_disjoint(archive: &mut Archive) -> Result<(), FeedError> {
    let mut ranges = (0..archive.len())
        .map(|index| {
            let entry = archive.by_index_raw(index)?;
            Ok((
                entry.header_start(),
                entry.data_start().map_or(u64::MAX, |start| start.saturating_add(entry.compressed_size())),
            ))
        })
        .collect::<Result<Vec<(u64, u64)>, FeedError>>()?;
    ranges.sort_unstable();
    ranges
        .windows(PAIR)
        .all(|pair| pair.first().zip(pair.get(1)).is_none_or(|(earlier, later)| earlier.1 <= later.0))
        .then_some(())
        .ok_or(FeedError::OverlappingEntries)
}


/// Versions and events a record keeps in memory.
pub fn retained_items(record: &OsvRecord) -> u64 {
    record
        .affected
        .iter()
        .map(|affected| affected.versions.len() + affected.ranges.iter().map(|range| range.events.len()).sum::<usize>())
        .sum::<usize>() as u64
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


/// Decompresses one entry from its own byte range; returns the content and the compressed bytes the decoder really consumed.
fn read_entry(data: &[u8], entry: &ZipFile<'_, Cursor<&[u8]>>, name: &str, limits: &FeedLimits) -> Result<(Vec<u8>, u64), FeedError> {
    let start = entry.data_start().map(|offset| offset as usize);
    let range = start.and_then(|from| data.get(from..from.saturating_add(entry.compressed_size() as usize)));
    let mut compressed = range.ok_or_else(|| FeedError::EntryOutOfBounds { name: name.to_string() })?;
    let available = compressed.len();
    let mut bytes = Vec::new();
    let cap = limits.max_entry_bytes.saturating_add(1);
    match entry.compression() {
        CompressionMethod::Stored => (&mut compressed).take(cap).read_to_end(&mut bytes)?,
        CompressionMethod::Deflated => DeflateDecoder::new(&mut compressed).take(cap).read_to_end(&mut bytes)?,
        _ => Err(FeedError::UnsupportedMethod { name: name.to_string() })?,
    };
    Ok((bytes, (available - compressed.len()) as u64))
}


fn scan_entry(
    archive: &mut Archive,
    data: &[u8],
    index: usize,
    settings: &FeedSettings,
    limits: &FeedLimits,
    (mut report, total): (FeedReport, u64),
) -> Result<(FeedReport, u64), FeedError> {
    let entry = archive.by_index_raw(index)?;
    let name: String = String::from_utf8_lossy(entry.name_raw()).chars().take(MAX_LOGGED_NAME_CHARS).collect();
    is_safe_name(entry.name_raw())
        .then_some(())
        .ok_or(FeedError::UnsafeName { name: name.clone() })?;
    if entry.is_dir() {
        Ok((report, total))
    } else {
        let (bytes, consumed) = read_entry(data, &entry, &name, limits)?;
        let size = bytes.len() as u64;
        (size <= limits.max_entry_bytes).then_some(()).ok_or(FeedError::EntryTooLarge {
            name: name.clone(),
            max: limits.max_entry_bytes,
        })?;
        let over_ratio = size > limits.ratio_floor_bytes && size > limits.max_ratio.saturating_mul(consumed.max(1));
        (!over_ratio).then_some(()).ok_or(FeedError::RatioExceeded {
            name: name.clone(),
            max: limits.max_ratio,
        })?;
        let new_total = total.saturating_add(size);
        (new_total <= limits.max_total_bytes)
            .then_some(())
            .ok_or(FeedError::TotalTooLarge { max: limits.max_total_bytes })?;
        match String::from_utf8(bytes).ok().and_then(|text| parse_record(&text).ok()) {
            Some(record) => match licence_of(settings, &record.id).filter(|licence| settings.allowed_licences.contains(licence)) {
                Some(licence) => {
                    report.retained_items = report.retained_items.saturating_add(retained_items(&record));
                    (report.retained_items <= limits.max_retained_items)
                        .then_some(())
                        .ok_or(FeedError::TooManyRetained {
                            max: limits.max_retained_items,
                        })?;
                    report.records.push(LoadedRecord { record, licence });
                }
                None => report.dropped_by_licence += 1,
            },
            None => {
                report.bad_entries += 1;
                tracing::warn!(entry = ?name, "skipped an unparsable feed entry");
            }
        }
        Ok((report, new_total))
    }
}

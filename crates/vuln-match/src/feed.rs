//! OSV archive loader: checksum, bounded zip reading, per-source licences.

use crate::error::FeedError;
use crate::limits::{
    EOCD_COUNT_OFFSET, EOCD_SIGNATURE, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_EOCD_SEARCH,
    MAX_LOGGED_NAME_CHARS, MAX_TOTAL_BYTES, RATIO_FLOOR_BYTES, ZIP64_COUNT_OFFSET, ZIP64_EOCD_SIGNATURE, ZIP64_LOCATOR_BYTES, ZIP64_LOCATOR_OFFSET,
    ZIP64_LOCATOR_SIGNATURE,
};
use crate::model::{FeedLimits, FeedReport, FeedSettings, LoadedRecord};
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
    let declared = declared_entries(&bytes).unwrap_or(u64::MIN);
    (declared <= limits.max_entries as u64).then_some(()).ok_or(FeedError::TooManyEntries {
        count: declared,
        max: limits.max_entries,
    })?;
    let mut archive = ZipArchive::new(Cursor::new(bytes.as_slice()))?;
    (archive.len() <= limits.max_entries).then_some(()).ok_or(FeedError::TooManyEntries {
        count: archive.len() as u64,
        max: limits.max_entries,
    })?;
    let (report, _total) = (0..archive.len()).try_fold((FeedReport::default(), u64::MIN), |state, index| {
        scan_entry(&mut archive, &bytes, index, settings, limits, state)
    })?;
    Ok(report)
}


fn field<const WIDTH: usize>(bytes: &[u8], at: usize) -> Option<[u8; WIDTH]> {
    bytes.get(at..at.checked_add(WIDTH)?)?.first_chunk::<WIDTH>().copied()
}


/// Entry count announced by the end-of-central-directory record (zip64 included), read before the zip crate indexes the directory.
pub fn declared_entries(bytes: &[u8]) -> Option<u64> {
    let eocd = bytes
        .windows(EOCD_SIGNATURE.len())
        .enumerate()
        .rev()
        .take(MAX_EOCD_SEARCH)
        .find(|(_, window)| *window == EOCD_SIGNATURE)
        .map(|(position, _)| position)?;
    let count = u16::from_le_bytes(field(bytes, eocd + EOCD_COUNT_OFFSET)?);
    if count == u16::MAX {
        zip64_entries(bytes, eocd)
    } else {
        Some(u64::from(count))
    }
}


fn zip64_entries(bytes: &[u8], eocd: usize) -> Option<u64> {
    let locator = eocd.checked_sub(ZIP64_LOCATOR_BYTES)?;
    (field(bytes, locator)? == ZIP64_LOCATOR_SIGNATURE).then_some(())?;
    let record = u64::from_le_bytes(field(bytes, locator + ZIP64_LOCATOR_OFFSET)?) as usize;
    (field(bytes, record)? == ZIP64_EOCD_SIGNATURE).then_some(())?;
    Some(u64::from_le_bytes(field(bytes, record.checked_add(ZIP64_COUNT_OFFSET)?)?))
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
                Some(licence) => report.records.push(LoadedRecord { record, licence }),
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

use crate::error::BackupError;
use crate::model::{Limits, Listing, SkipReason, Snapshot};
use crate::text::{is_hidden, valid_id, valid_text};
use crate::types::SkipCounts;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::io::Read;
use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};


pub const BORG_TIME_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second][optional [.[subsecond]]]");


/// Reads at most `limit` bytes: `take(limit + 1)` then `limit() == 0` means the source held more.
pub fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, BackupError> {
    let mut bytes = Vec::new();
    let mut limited = reader.take(limit.saturating_add(1));
    limited.read_to_end(&mut bytes).map_err(BackupError::Read)?;
    if limited.limit() == 0 {
        Err(BackupError::TooLarge { limit })
    } else {
        Ok(bytes)
    }
}


/// The elements of a JSON array as borrowed raw slices (16 bytes each); a non-array is `Malformed`.
pub fn raw_items<'a>(text: &'a str, what: &'static str) -> Result<Vec<&'a RawValue>, BackupError> {
    serde_json::from_str(text).map_err(|_| BackupError::Malformed { what })
}


#[derive(Deserialize)]
pub struct BorgRepository {
    pub id: Option<String>,
}


#[derive(Deserialize)]
pub struct BorgRoot<'a> {
    pub repository: Option<BorgRepository>,
    #[serde(borrow)]
    pub archives: Option<&'a RawValue>,
}


pub fn text_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}


/// An absent key is an empty list; a wrong-typed value, an oversized list or a refused item is `None`.
pub fn string_list(value: Option<&Value>, max_count: usize, accept: impl Fn(&str) -> bool) -> Option<Vec<String>> {
    match value {
        None => Some(Vec::new()),
        Some(found) => found.as_array().filter(|items| items.len() <= max_count).and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().filter(|text| accept(text)).map(str::to_owned))
                .collect()
        }),
    }
}


pub fn parse_rfc3339(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok().map(|time| time.to_offset(UtcOffset::UTC))
}


/// Borg writes ISO 8601 without a zone: it is read as UTC.
pub fn parse_borg_time(text: &str) -> Option<OffsetDateTime> {
    PrimitiveDateTime::parse(text, BORG_TIME_FORMAT).ok().map(PrimitiveDateTime::assume_utc)
}


pub fn restic_snapshot(object: &Map<String, Value>, limits: &Limits) -> Result<Snapshot, SkipReason> {
    let id = text_field(object, "id").filter(|text| valid_id(text)).ok_or(SkipReason::BadId)?;
    let time = text_field(object, "time").and_then(parse_rfc3339).ok_or(SkipReason::BadTime)?;
    let host = text_field(object, "hostname")
        .filter(|text| valid_text(text, limits.max_text_chars))
        .ok_or(SkipReason::BadHost)?;
    let paths = string_list(object.get("paths"), limits.max_paths, |text| text.len() <= limits.max_path_bytes).ok_or(SkipReason::BadPaths)?;
    let tags = string_list(object.get("tags"), limits.max_tags, |text| valid_text(text, limits.max_text_chars)).ok_or(SkipReason::BadTags)?;
    Ok(Snapshot {
        id: id.to_owned(),
        time,
        host: Some(host.to_owned()),
        paths,
        tags,
    })
}


/// The host is the archive name up to the first `-`, only when `from_name` is set.
pub fn borg_host(name: &str, from_name: bool, max_chars: usize) -> Result<Option<String>, SkipReason> {
    if from_name {
        name.split_once('-')
            .map(|(prefix, _)| prefix)
            .filter(|prefix| valid_text(prefix, max_chars))
            .map(|prefix| Some(prefix.to_owned()))
            .ok_or(SkipReason::BadHost)
    } else {
        Ok(None)
    }
}


pub fn borg_snapshot(object: &Map<String, Value>, from_name: bool, limits: &Limits) -> Result<Snapshot, SkipReason> {
    let id = text_field(object, "id").filter(|text| valid_id(text)).ok_or(SkipReason::BadId)?;
    let time = object
        .get("start")
        .or_else(|| object.get("time"))
        .and_then(Value::as_str)
        .and_then(parse_borg_time)
        .ok_or(SkipReason::BadTime)?;
    let name = text_field(object, "name")
        .filter(|text| text.chars().count() <= limits.max_name_chars && !text.chars().any(is_hidden))
        .ok_or(SkipReason::BadName)?;
    let host = borg_host(name, from_name, limits.max_text_chars)?;
    Ok(Snapshot {
        id: id.to_owned(),
        time,
        host,
        paths: Vec::new(),
        tags: Vec::new(),
    })
}


pub fn skip(counts: &mut SkipCounts, reason: SkipReason) {
    *counts.entry(reason).or_insert(0) += 1;
}


/// Collects the accepted snapshots; a repeated id is skipped as `Duplicate`.
pub fn collect(repository: String, results: Vec<Result<Snapshot, SkipReason>>) -> Listing {
    let mut seen = BTreeSet::new();
    let mut snapshots = Vec::new();
    let mut skipped = SkipCounts::new();
    results.into_iter().for_each(|result| match result {
        Ok(snapshot) if seen.insert(snapshot.id.clone()) => snapshots.push(snapshot),
        Ok(_) => skip(&mut skipped, SkipReason::Duplicate),
        Err(reason) => skip(&mut skipped, reason),
    });
    Listing {
        repository,
        snapshots,
        skipped,
    }
}


/// The count is checked on the raw slices before any element is parsed; every element must then be an object (else the listing is malformed).
pub fn snapshot_objects(items: &[&RawValue], limits: &Limits) -> Result<Vec<Map<String, Value>>, BackupError> {
    if items.len() > limits.max_snapshots {
        Err(BackupError::TooManySnapshots { limit: limits.max_snapshots })
    } else {
        items
            .iter()
            .map(|item| {
                serde_json::from_str(item.get()).map_err(|_| BackupError::Malformed {
                    what: "snapshot is not an object",
                })
            })
            .collect()
    }
}


/// `restic snapshots --json`; restic prints no repository id, so the caller names the repository.
pub fn parse_restic(reader: impl Read, repository: &str, limits: &Limits) -> Result<Listing, BackupError> {
    let bytes = read_bounded(reader, limits.max_bytes)?;
    let root: &RawValue = serde_json::from_slice(&bytes).map_err(BackupError::Json)?;
    let items = raw_items(root.get(), "snapshots is not an array")?;
    let objects = snapshot_objects(&items, limits)?;
    if valid_text(repository, limits.max_text_chars) {
        let results = objects.iter().map(|object| restic_snapshot(object, limits)).collect();
        Ok(collect(repository.to_owned(), results))
    } else {
        Err(BackupError::Malformed { what: "repository name" })
    }
}


/// `borg list --json`; the repository is `repository.id`.
pub fn parse_borg(reader: impl Read, hostname_from_name: bool, limits: &Limits) -> Result<Listing, BackupError> {
    let bytes = read_bounded(reader, limits.max_bytes)?;
    let document: &RawValue = serde_json::from_slice(&bytes).map_err(BackupError::Json)?;
    let root: BorgRoot = serde_json::from_str(document.get()).map_err(|_| BackupError::Malformed {
        what: "listing is not an object",
    })?;
    let repository = root
        .repository
        .and_then(|found| found.id)
        .filter(|id| valid_id(id))
        .ok_or(BackupError::Malformed { what: "repository id" })?;
    let archives = root.archives.ok_or(BackupError::Malformed {
        what: "archives is not an array",
    })?;
    let items = raw_items(archives.get(), "archives is not an array")?;
    let objects = snapshot_objects(&items, limits)?;
    let results = objects.iter().map(|object| borg_snapshot(object, hostname_from_name, limits)).collect();
    Ok(collect(repository, results))
}

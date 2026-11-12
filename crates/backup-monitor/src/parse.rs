use crate::error::{json_failure, BackupError};
use crate::model::{Limits, Listing, SkipReason, Snapshot};
use crate::text::{is_hidden, valid_id, valid_text};
use crate::types::SkipCounts;
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::io::Read;
use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};


pub const BORG_TIME_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second][optional [.[subsecond]]]");


/// One buffer of `limit + 1` bytes, reserved once; a size the allocator refuses is `Reservation`.
pub fn reserve_exact(limit: u64) -> Result<Vec<u8>, BackupError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(limit).unwrap_or(usize::MAX).saturating_add(1))
        .map_err(|source| BackupError::Reservation { limit, source })?;
    Ok(bytes)
}


/// Reads at most `limit` bytes: `take(limit + 1)` then `limit() == 0` means the source held more.
pub fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, BackupError> {
    let mut bytes = reserve_exact(limit)?;
    let mut limited = reader.take(limit.saturating_add(1));
    limited.read_to_end(&mut bytes).map_err(BackupError::Read)?;
    if limited.limit() == 0 {
        Err(BackupError::TooLarge { limit })
    } else {
        Ok(bytes)
    }
}


/// The elements of a JSON array as borrowed raw slices (16 bytes each), counted first with zero-size items so an oversized list allocates nothing.
pub fn raw_items<'a>(text: &'a str, what: &'static str, max_items: usize) -> Result<Vec<&'a RawValue>, BackupError> {
    let counted = serde_json::from_str::<Vec<IgnoredAny>>(text).map_err(|_| BackupError::Malformed { what })?;
    if counted.len() > max_items {
        Err(BackupError::TooManySnapshots { limit: max_items })
    } else {
        serde_json::from_str(text).map_err(json_failure)
    }
}


#[derive(Deserialize)]
pub struct BorgRepository {
    pub id: Option<String>,
}


#[derive(Deserialize)]
pub struct BorgRoot<'a> {
    #[serde(borrow)]
    pub repository: Option<&'a RawValue>,
    #[serde(borrow)]
    pub archives: Option<&'a RawValue>,
}


/// A key that is present is `Some` even when its value is `null`: a wrong-typed value, never an absent one.
pub fn present<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Option<&'de RawValue>, Source::Error> {
    <&RawValue>::deserialize(deserializer).map(Some)
}


/// One element with every field left as a raw slice: nothing is expanded and unknown fields are skipped without allocation.
#[derive(Deserialize)]
pub struct RawElement<'a> {
    #[serde(default, borrow, deserialize_with = "present")]
    pub id: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub time: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub start: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub hostname: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub name: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub paths: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub tags: Option<&'a RawValue>,
}


/// An element that is not an object (or repeats a key) is `Malformed` for the whole listing.
pub fn element(item: &RawValue) -> Result<RawElement<'_>, BackupError> {
    Some(item.get())
        .filter(|text| text.starts_with('{'))
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or(BackupError::Malformed {
            what: "snapshot is not an object",
        })
}


pub fn text_field(raw: Option<&RawValue>) -> Option<String> {
    raw.and_then(|found| serde_json::from_str(found.get()).ok())
}


/// An absent key is an empty list; a wrong-typed value, an oversized list or a refused item is `None`. The count is taken before any item is read.
pub fn string_list(raw: Option<&RawValue>, max_count: usize, accept: impl Fn(&str) -> bool) -> Option<Vec<String>> {
    match raw {
        None => Some(Vec::new()),
        Some(found) => serde_json::from_str::<Vec<IgnoredAny>>(found.get())
            .ok()
            .filter(|counted| counted.len() <= max_count)
            .and_then(|_| serde_json::from_str::<Vec<String>>(found.get()).ok())
            .filter(|items| items.iter().all(|item| accept(item))),
    }
}


pub fn parse_rfc3339(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok().map(|time| time.to_offset(UtcOffset::UTC))
}


/// Borg writes ISO 8601 without a zone: it is read as UTC.
pub fn parse_borg_time(text: &str) -> Option<OffsetDateTime> {
    PrimitiveDateTime::parse(text, BORG_TIME_FORMAT).ok().map(PrimitiveDateTime::assume_utc)
}


pub fn restic_snapshot(fields: &RawElement, limits: &Limits) -> Result<Snapshot, SkipReason> {
    let id = text_field(fields.id).filter(|text| valid_id(text)).ok_or(SkipReason::BadId)?;
    let time = text_field(fields.time).and_then(|text| parse_rfc3339(&text)).ok_or(SkipReason::BadTime)?;
    let host = text_field(fields.hostname)
        .filter(|text| valid_text(text, limits.max_text_chars))
        .ok_or(SkipReason::BadHost)?;
    let paths = string_list(fields.paths, limits.max_paths, |text| text.len() <= limits.max_path_bytes).ok_or(SkipReason::BadPaths)?;
    let tags = string_list(fields.tags, limits.max_tags, |text| valid_text(text, limits.max_text_chars)).ok_or(SkipReason::BadTags)?;
    Ok(Snapshot {
        id,
        time,
        host: Some(host),
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


pub fn borg_snapshot(fields: &RawElement, from_name: bool, limits: &Limits) -> Result<Snapshot, SkipReason> {
    let id = text_field(fields.id).filter(|text| valid_id(text)).ok_or(SkipReason::BadId)?;
    let time = text_field(fields.start.or(fields.time))
        .and_then(|text| parse_borg_time(&text))
        .ok_or(SkipReason::BadTime)?;
    let name = text_field(fields.name)
        .filter(|text| text.chars().count() <= limits.max_name_chars && !text.chars().any(is_hidden))
        .ok_or(SkipReason::BadName)?;
    let host = borg_host(&name, from_name, limits.max_text_chars)?;
    Ok(Snapshot {
        id,
        time,
        host,
        paths: Vec::new(),
        tags: Vec::new(),
    })
}


pub fn skip(counts: &mut SkipCounts, reason: SkipReason) {
    *counts.entry(reason).or_insert(0) += 1;
}


/// Parses the elements one at a time, so only one is ever expanded; a repeated id is skipped as `Duplicate`.
pub fn collect(
    repository: String,
    items: &[&RawValue],
    parse_one: impl Fn(&RawElement) -> Result<Snapshot, SkipReason>,
) -> Result<Listing, BackupError> {
    let start = Listing {
        repository,
        snapshots: Vec::new(),
        skipped: SkipCounts::new(),
    };
    let mut seen = BTreeSet::new();
    items.iter().try_fold(start, |mut listing, item| {
        match parse_one(&element(item)?) {
            Ok(snapshot) if seen.insert(snapshot.id.clone()) => listing.snapshots.push(snapshot),
            Ok(_) => skip(&mut listing.skipped, SkipReason::Duplicate),
            Err(reason) => skip(&mut listing.skipped, reason),
        }
        Ok(listing)
    })
}


/// `restic snapshots --json`; restic prints no repository id, so the caller names the repository (checked before any element is read).
pub fn parse_restic(reader: impl Read, repository: &str, limits: &Limits) -> Result<Listing, BackupError> {
    let bytes = read_bounded(reader, limits.max_bytes)?;
    let root: &RawValue = serde_json::from_slice(&bytes).map_err(json_failure)?;
    if valid_text(repository, limits.max_text_chars) {
        let items = raw_items(root.get(), "snapshots is not an array", limits.max_snapshots)?;
        collect(repository.to_owned(), &items, |fields| restic_snapshot(fields, limits))
    } else {
        Err(BackupError::Malformed { what: "repository name" })
    }
}


/// `borg list --json`; the repository is `repository.id`.
pub fn parse_borg(reader: impl Read, hostname_from_name: bool, limits: &Limits) -> Result<Listing, BackupError> {
    let bytes = read_bounded(reader, limits.max_bytes)?;
    let document: &RawValue = serde_json::from_slice(&bytes).map_err(json_failure)?;
    let root: BorgRoot = Some(document.get())
        .filter(|text| text.starts_with('{'))
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or(BackupError::Malformed {
            what: "listing is not an object",
        })?;
    let repository = root
        .repository
        .map(RawValue::get)
        .filter(|text| text.starts_with('{'))
        .and_then(|text| serde_json::from_str::<BorgRepository>(text).ok())
        .and_then(|found| found.id)
        .filter(|id| valid_id(id))
        .ok_or(BackupError::Malformed { what: "repository id" })?;
    let archives = root.archives.ok_or(BackupError::Malformed {
        what: "archives is not an array",
    })?;
    let items = raw_items(archives.get(), "archives is not an array", limits.max_snapshots)?;
    collect(repository, &items, |fields| borg_snapshot(fields, hostname_from_name, limits))
}

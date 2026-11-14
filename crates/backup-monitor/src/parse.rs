use crate::error::{json_failure, BackupError};
use crate::model::{Limits, Listing, PbsDetail, SkipReason, Snapshot, Verification, OWNER_DISPLAY_CHARS};
use crate::text::{display_text, is_hidden, valid_id, valid_text};
use crate::types::SkipCounts;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
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
    #[serde(default, borrow, deserialize_with = "present", rename = "backup-type")]
    pub backup_type: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present", rename = "backup-id")]
    pub backup_id: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present", rename = "backup-time")]
    pub backup_time: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub owner: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub protected: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub verification: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub files: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    pub size: Option<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct PbsVerification {
    pub state: String,
}


#[derive(Deserialize)]
pub struct PbsFile {
    pub filename: String,
    #[serde(default, deserialize_with = "strict")]
    pub size: Option<u64>,
    #[serde(default, rename = "crypt-mode", deserialize_with = "strict")]
    pub crypt_mode: Option<PbsCryptMode>,
}


/// The schema's `crypt-mode` enum.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PbsCryptMode {
    None,
    Encrypt,
    SignOnly,
}


/// An absent key is `None`, but a present one (`null` included) must have the type.
pub fn strict<'de, Value: Deserialize<'de>, Source: Deserializer<'de>>(deserializer: Source) -> Result<Option<Value>, Source::Error> {
    Value::deserialize(deserializer).map(Some)
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
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .and_then(|time| time.checked_to_offset(UtcOffset::UTC))
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
        pbs: None,
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
        pbs: None,
    })
}


pub const PBS_BACKUP_TYPES: [&str; 3] = ["vm", "ct", "host"];


pub const PBS_MAX_YEAR: i32 = 9999;


pub const PBS_MANIFEST: &str = "index.json.blob";


/// An absent key is `None`; a present value of the wrong type (`null` included) is `BadField`.
pub fn typed_field<Value: DeserializeOwned>(raw: Option<&RawValue>) -> Result<Option<Value>, SkipReason> {
    raw.map(|found| serde_json::from_str(found.get()).map_err(|_| SkipReason::BadField))
        .transpose()
}


/// The element count of an optional array, taken with zero-size items; above `max_items` or wrong-typed is `None`.
pub fn counted_items(raw: Option<&RawValue>, max_items: usize) -> Option<usize> {
    raw.map_or(Some(0), |found| {
        serde_json::from_str::<Vec<IgnoredAny>>(found.get())
            .ok()
            .map(|counted| counted.len())
            .filter(|count| *count <= max_items)
    })
}


/// A verification object holds a required `state`: `ok` verified, `failed` failed, any other value or shape is `BadField`; an absent object is unverified.
pub fn pbs_verification(raw: Option<&RawValue>) -> Result<Verification, SkipReason> {
    let state = raw
        .map(|found| {
            Some(found.get())
                .filter(|text| text.starts_with('{'))
                .and_then(|text| serde_json::from_str::<PbsVerification>(text).ok())
                .map(|verification| verification.state)
                .ok_or(SkipReason::BadField)
        })
        .transpose()?;
    match state.as_deref() {
        None => Ok(Verification::Unverified),
        Some("ok") => Ok(Verification::Verified),
        Some("failed") => Ok(Verification::Failed),
        Some(_) => Err(SkipReason::BadField),
    }
}


/// Whether one `files` entry (an object, never an array) names the manifest.
pub fn names_manifest(item: &RawValue) -> Option<bool> {
    Some(item.get())
        .filter(|text| text.starts_with('{'))
        .and_then(|text| serde_json::from_str::<PbsFile>(text).ok())
        .map(|file| file.filename == PBS_MANIFEST)
}


/// The file count (taken first, against `max_items`) and whether the manifest is listed; a wrong-typed list or entry is `None`.
pub fn pbs_files(raw: Option<&RawValue>, max_items: usize) -> Option<(usize, bool)> {
    let count = counted_items(raw, max_items)?;
    match raw {
        None => Some((count, false)),
        Some(found) => serde_json::from_str::<Vec<&RawValue>>(found.get())
            .ok()?
            .into_iter()
            .map(names_manifest)
            .try_fold(false, |seen, named| named.map(|is_manifest| seen || is_manifest))
            .map(|manifest| (count, manifest)),
    }
}


/// The manifest is written when a backup finishes, so a listed manifest and a size mean a finished snapshot.
pub fn pbs_detail(fields: &RawElement, limits: &Limits) -> Result<PbsDetail, SkipReason> {
    let (files, manifest) = pbs_files(fields.files, limits.max_paths).ok_or(SkipReason::BadPaths)?;
    let size = typed_field::<u64>(fields.size)?;
    Ok(PbsDetail {
        owner: typed_field::<String>(fields.owner)?.map(|text| display_text(&text, OWNER_DISPLAY_CHARS)),
        protected: typed_field::<bool>(fields.protected)?.unwrap_or(false),
        verification: pbs_verification(fields.verification)?,
        size,
        files,
        complete: manifest && size.is_some(),
    })
}


/// The backup time (epoch seconds, schema minimum 1) must fit RFC 3339: year 9999 at most.
pub fn pbs_time(raw: Option<&RawValue>) -> Option<OffsetDateTime> {
    raw.and_then(|found| serde_json::from_str::<i64>(found.get()).ok())
        .filter(|seconds| *seconds >= 1)
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .filter(|time| time.year() <= PBS_MAX_YEAR)
}


/// The host is `<type>/<id>` (for example `vm/100`); the snapshot id is the host plus the epoch time, which is unique in one datastore.
pub fn pbs_snapshot(fields: &RawElement, limits: &Limits) -> Result<Snapshot, SkipReason> {
    let kind = text_field(fields.backup_type)
        .filter(|text| PBS_BACKUP_TYPES.contains(&text.as_str()))
        .ok_or(SkipReason::BadHost)?;
    let name = text_field(fields.backup_id)
        .filter(|text| valid_text(text, limits.max_text_chars))
        .ok_or(SkipReason::BadHost)?;
    let host = Some(format!("{kind}/{name}"))
        .filter(|key| key.len() <= limits.max_text_chars)
        .ok_or(SkipReason::BadHost)?;
    let time = pbs_time(fields.backup_time).ok_or(SkipReason::BadTime)?;
    let detail = pbs_detail(fields, limits)?;
    Ok(Snapshot {
        id: format!("{host}/{}", time.unix_timestamp()),
        time,
        host: Some(host),
        paths: Vec::new(),
        tags: Vec::new(),
        pbs: Some(detail),
    })
}


pub fn skip(counts: &mut SkipCounts, reason: SkipReason) {
    *counts.entry(reason).or_insert(0) += 1;
}


/// Parses the elements one at a time, so only one is ever expanded; every copy of a repeated id is unusable and counted as `Duplicate`.
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
    let mut listing = items.iter().try_fold(start, |mut listing, item| {
        match parse_one(&element(item)?) {
            Ok(snapshot) => listing.snapshots.push(snapshot),
            Err(reason) => skip(&mut listing.skipped, reason),
        }
        Ok::<Listing, BackupError>(listing)
    })?;
    let copies = listing.snapshots.iter().fold(BTreeMap::<&str, usize>::new(), |mut counts, snapshot| {
        *counts.entry(snapshot.id.as_str()).or_insert(0) += 1;
        counts
    });
    let repeated: BTreeSet<String> = copies.into_iter().filter(|(_, count)| *count > 1).map(|(id, _)| id.to_owned()).collect();
    let before = listing.snapshots.len();
    listing.snapshots.retain(|snapshot| !repeated.contains(&snapshot.id));
    (0..before - listing.snapshots.len()).for_each(|_| skip(&mut listing.skipped, SkipReason::Duplicate));
    Ok(listing)
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


/// `proxmox-backup-client snapshot list --output-format json`; the caller names the repository, as for restic.
pub fn parse_pbs(reader: impl Read, repository: &str, limits: &Limits) -> Result<Listing, BackupError> {
    let bytes = read_bounded(reader, limits.max_bytes)?;
    let root: &RawValue = serde_json::from_slice(&bytes).map_err(json_failure)?;
    if valid_text(repository, limits.max_text_chars) {
        let items = raw_items(root.get(), "snapshots is not an array", limits.max_snapshots)?;
        collect(repository.to_owned(), &items, |fields| pbs_snapshot(fields, limits))
    } else {
        Err(BackupError::Malformed { what: "repository name" })
    }
}

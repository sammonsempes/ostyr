use crate::checks::is_privileged_sid;
use crate::error::{EntryError, SnapshotError};
use crate::filetime::filetime_to_unix;
use crate::limits::Limits;
use crate::model::{BoundHit, Entry, Gap, Items, Snapshot, Unreadable};
use crate::types::Outcome;
use ecs_normalise::suricata::is_unsafe;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny};
use serde::Deserialize;
use serde_json::error::Category;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;


/// A JSON string takes at most six bytes per decoded byte (`é`), plus the two quotes.
pub const RAW_ESCAPE_FACTOR: usize = 6;


pub const RAW_QUOTES: usize = 2;


/// Bytes of the SHA-256 of a DN token that name an unreadable entry in a finding.
pub const DIGEST_PREFIX_BYTES: usize = 8;


pub const REASON_DUPLICATE: &str = "duplicate DN";


pub const FIELD_DN: &str = "distinguishedName";


/// Keeps a JSON `null` as a token (`Option` alone would read it as an absent attribute), so it is refused as a wrong shape.
pub fn keep_raw<'de, Source: Deserializer<'de>>(source: Source) -> Result<Option<&'de RawValue>, Source::Error> {
    <&RawValue>::deserialize(source).map(Some)
}


/// An entry before its attributes are checked: every attribute stays a raw JSON token, so only the object shape can fail here.
#[derive(Deserialize)]
struct RawEntry<'a> {
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "distinguishedName")]
    dn: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "objectClass")]
    classes: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "sAMAccountName")]
    account: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "userAccountControl")]
    uac: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "servicePrincipalName")]
    spns: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "memberOf")]
    member_of: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "pwdLastSet")]
    pwd_last_set: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "lastLogonTimestamp")]
    last_logon: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "keep_raw", rename = "objectSid")]
    sid: Option<&'a RawValue>,
}


pub fn bad_entry(field: &'static str, source: &serde_json::Error) -> EntryError {
    EntryError::BadEntry {
        field,
        category: source.classify(),
    }
}


pub fn malformed(source: &serde_json::Error) -> SnapshotError {
    SnapshotError::Malformed {
        category: source.classify(),
        line: source.line(),
        column: source.column(),
    }
}


/// The reason a text is refused, `None` when it is usable: non-empty, within the byte bound, no unsafe character.
pub fn text_problem(text: &str, max_text_bytes: usize) -> Option<&'static str> {
    if text.is_empty() {
        Some("empty")
    } else if text.len() > max_text_bytes {
        Some("too long")
    } else if text.chars().any(is_unsafe) {
        Some("unsafe character")
    } else {
        None
    }
}


/// Decodes one JSON string only after its raw length is checked, so a hostile text is never materialised above the bound.
pub fn text_of(raw: &RawValue, field: &'static str, limits: &Limits) -> Result<String, EntryError> {
    let raw_cap = limits.max_text_bytes.saturating_mul(RAW_ESCAPE_FACTOR).saturating_add(RAW_QUOTES);
    if raw.get().len() > raw_cap {
        Err(EntryError::BadText { field, reason: "too long" })
    } else {
        let text: String = serde_json::from_str(raw.get()).map_err(|source| bad_entry(field, &source))?;
        match text_problem(&text, limits.max_text_bytes) {
            Some(reason) => Err(EntryError::BadText { field, reason }),
            None => Ok(text),
        }
    }
}


/// The elements of a JSON array, or its length when above `max`: counted without building anything first.
pub fn bounded_items(text: &str, max: usize) -> Result<Items<'_>, serde_json::Error> {
    let count = serde_json::from_str::<Vec<IgnoredAny>>(text)?.len();
    if count > max {
        Ok(Items::Over(count))
    } else {
        serde_json::from_str(text).map(Items::Within)
    }
}


/// An array of texts: counted without building it; a list over the bound keeps nothing, a refused text is dropped, both are counted in a gap.
pub fn list_of(raw: Option<&RawValue>, field: &'static str, limits: &Limits) -> Result<(Vec<String>, Option<Gap>), EntryError> {
    match raw {
        None => Ok((Vec::new(), None)),
        Some(list) => match bounded_items(list.get(), limits.max_values).map_err(|source| bad_entry(field, &source))? {
            Items::Over(count) => Ok((
                Vec::new(),
                Some(Gap {
                    field,
                    dropped: count,
                    over_limit: true,
                }),
            )),
            Items::Within(items) => {
                let kept: Vec<String> = items.iter().filter_map(|item| text_of(item, field, limits).ok()).collect();
                let dropped = items.len() - kept.len();
                Ok((
                    kept,
                    (dropped > 0).then_some(Gap {
                        field,
                        dropped,
                        over_limit: false,
                    }),
                ))
            }
        },
    }
}


pub fn optional_text(raw: Option<&RawValue>, field: &'static str, limits: &Limits) -> Result<Option<String>, EntryError> {
    raw.map(|text| text_of(text, field, limits)).transpose()
}


/// A SID is ASCII `S`, digits and `-` only.
pub fn is_sid(text: &str) -> bool {
    text.starts_with("S-") && text.chars().all(|found| found.is_ascii_digit() || found == 'S' || found == '-')
}


pub fn sid_of(raw: Option<&RawValue>, limits: &Limits) -> Result<Option<String>, EntryError> {
    let sid = optional_text(raw, "objectSid", limits)?;
    match sid {
        Some(text) if !is_sid(&text) => Err(EntryError::BadText {
            field: "objectSid",
            reason: "not a SID",
        }),
        other => Ok(other),
    }
}


pub fn number_of<Number: DeserializeOwned>(raw: Option<&RawValue>, field: &'static str) -> Result<Option<Number>, EntryError> {
    raw.map(|token| serde_json::from_str(token.get()).map_err(|source| bad_entry(field, &source)))
        .transpose()
}


pub fn filetime_of(raw: Option<&RawValue>, field: &'static str) -> Result<Option<i64>, EntryError> {
    match number_of::<u64>(raw, field)? {
        None => Ok(None),
        Some(value) => filetime_to_unix(value).map_err(|source| EntryError::BadFiletime { field, source }),
    }
}


/// One entry of the array: a refused DN, SID, number or shape is an `EntryError`; a refused value inside a list is only dropped and counted.
pub fn entry_of(raw: &RawValue, limits: &Limits) -> Result<Entry, EntryError> {
    let parsed: RawEntry = serde_json::from_str(raw.get()).map_err(|source| bad_entry("entry", &source))?;
    let dn = parsed.dn.ok_or(EntryError::BadEntry {
        field: FIELD_DN,
        category: Category::Data,
    })?;
    let (classes, classes_gap) = list_of(parsed.classes, "objectClass", limits)?;
    let (spns, spns_gap) = list_of(parsed.spns, "servicePrincipalName", limits)?;
    let (member_of, member_of_gap) = list_of(parsed.member_of, "memberOf", limits)?;
    Ok(Entry {
        dn: text_of(dn, FIELD_DN, limits)?,
        classes,
        account: optional_text(parsed.account, "sAMAccountName", limits)?,
        uac: number_of::<u32>(parsed.uac, "userAccountControl")?.unwrap_or(0),
        spns,
        member_of,
        pwd_last_set: filetime_of(parsed.pwd_last_set, "pwdLastSet")?,
        last_logon: filetime_of(parsed.last_logon, "lastLogonTimestamp")?,
        sid: sid_of(parsed.sid, limits)?,
        gaps: [classes_gap, spns_gap, member_of_gap].into_iter().flatten().collect(),
    })
}


pub fn field_of(error: &EntryError) -> &'static str {
    match error {
        EntryError::BadEntry { field, .. } | EntryError::BadText { field, .. } | EntryError::BadFiletime { field, .. } => field,
    }
}


pub fn reason_of(error: &EntryError) -> &'static str {
    match error {
        EntryError::BadEntry { .. } => "wrong shape",
        EntryError::BadText { reason, .. } => reason,
        EntryError::BadFiletime { .. } => "FILETIME out of range",
    }
}


/// First bytes of the SHA-256 of a token, in hex: names an entry without printing any of its text.
pub fn digest_prefix(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .take(DIGEST_PREFIX_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}


/// True when the SID of a refused entry is a privileged group's, or cannot be read at all: the group's members are then unassessable.
pub fn group_risk(sid: Option<&RawValue>, limits: &Limits) -> bool {
    match sid_of(sid, limits) {
        Ok(Some(text)) => is_privileged_sid(&text),
        Ok(None) => false,
        Err(_) => true,
    }
}


/// A text that can be printed: `None` when it is absent or refused (the entry stays named by its digest alone).
pub fn name_of(raw: Option<&RawValue>, limits: &Limits) -> Option<String> {
    optional_text(raw, "sAMAccountName", limits).into_iter().flatten().next()
}


pub fn sid_name_of(raw: Option<&RawValue>, limits: &Limits) -> Option<String> {
    sid_of(raw, limits).into_iter().flatten().next()
}


/// Sets an entry aside: the DN token (or the whole token when the entry is not an object) is hashed, never printed.
pub fn unreadable_of(index: usize, raw: &RawValue, field: &'static str, reason: &'static str, limits: &Limits) -> Unreadable {
    match serde_json::from_str::<RawEntry>(raw.get()) {
        Ok(parsed) => Unreadable {
            index,
            field,
            reason,
            dn_digest: digest_prefix(parsed.dn.map_or(raw.get(), RawValue::get)),
            group_risk: group_risk(parsed.sid, limits),
            account: name_of(parsed.account, limits),
            sid: sid_name_of(parsed.sid, limits),
        },
        Err(_) => Unreadable {
            index,
            field,
            reason,
            dn_digest: digest_prefix(raw.get()),
            group_risk: false,
            account: None,
            sid: None,
        },
    }
}


/// Length of a list token, 0 when it is not an array (that entry is refused later, with its own reason).
pub fn list_len(raw: Option<&RawValue>) -> usize {
    raw.map_or(0, |list| {
        serde_json::from_str::<Vec<IgnoredAny>>(list.get()).map_or(0, |items| items.len())
    })
}


/// Values that will be built for one entry: a list above its own bound is set aside whole and builds nothing.
pub fn values_of(raw: &RawValue, limits: &Limits) -> usize {
    serde_json::from_str::<RawEntry>(raw.get()).map_or(0, |parsed| {
        [parsed.classes, parsed.spns, parsed.member_of]
            .into_iter()
            .map(list_len)
            .filter(|count| *count <= limits.max_values)
            .fold(0, usize::saturating_add)
    })
}


/// Values of every list of every entry, counted before any is built.
pub fn total_values(raws: &[&RawValue], limits: &Limits) -> usize {
    raws.iter().map(|raw| values_of(raw, limits)).fold(0, usize::saturating_add)
}


/// DNs shared by two readable entries, compared as exact bytes: AD refuses a second object with the same DN, so the snapshot is broken there.
pub fn repeated_dns(outcomes: &[Outcome]) -> BTreeSet<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    outcomes
        .iter()
        .filter_map(|(_, _, outcome)| outcome.as_ref().ok())
        .for_each(|entry| *counts.entry(entry.dn.as_str()).or_insert(0) += 1);
    counts.into_iter().filter(|(_, count)| *count > 1).map(|(dn, _)| dn.to_owned()).collect()
}


/// Readable entries on one side, set-aside ones on the other.
pub fn split(outcomes: Vec<Outcome>, limits: &Limits) -> Snapshot {
    let repeated = repeated_dns(&outcomes);
    let mut entries = Vec::new();
    let mut unreadable = Vec::new();
    for (index, raw, outcome) in outcomes {
        match outcome {
            Ok(entry) if repeated.contains(&entry.dn) => unreadable.push(unreadable_of(index, raw, FIELD_DN, REASON_DUPLICATE, limits)),
            Ok(entry) => entries.push(entry),
            Err(error) => unreadable.push(unreadable_of(index, raw, field_of(&error), reason_of(&error), limits)),
        }
    }
    Snapshot {
        entries,
        unreadable,
        bounds: Vec::new(),
    }
}


/// A snapshot that holds only the global bound that was reached: nothing was built, the assessment reports it as Critical.
pub fn bound_hit(bound: &'static str, observed: u64, limit: u64) -> Snapshot {
    Snapshot {
        bounds: vec![BoundHit { bound, observed, limit }],
        ..Snapshot::default()
    }
}


pub fn parse_entries(buffer: &[u8], limits: &Limits) -> Result<Snapshot, SnapshotError> {
    let text = std::str::from_utf8(buffer).map_err(SnapshotError::NotUtf8)?;
    match bounded_items(text, limits.max_entries).map_err(|source| malformed(&source))? {
        Items::Over(count) => Ok(bound_hit("entries", count as u64, limits.max_entries as u64)),
        Items::Within(raws) => {
            let total = total_values(&raws, limits);
            if total > limits.max_total_values {
                Ok(bound_hit("values", total as u64, limits.max_total_values as u64))
            } else {
                let outcomes: Vec<Outcome> = raws
                    .into_iter()
                    .enumerate()
                    .map(|(index, raw)| (index, raw, entry_of(raw, limits)))
                    .collect();
                Ok(split(outcomes, limits))
            }
        }
    }
}


/// Reads a JSON array of entries: size, entry count and every value count are checked before anything is built; a bound hit is a result.
pub fn read_snapshot<Source: Read>(source: Source, limits: &Limits) -> Result<Snapshot, SnapshotError> {
    let mut buffer = Vec::new();
    source
        .take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(SnapshotError::Read)?;
    if buffer.len() as u64 > limits.max_bytes {
        Ok(bound_hit("bytes", buffer.len() as u64, limits.max_bytes))
    } else {
        parse_entries(&buffer, limits)
    }
}

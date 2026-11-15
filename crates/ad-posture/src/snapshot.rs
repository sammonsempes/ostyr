use crate::error::SnapshotError;
use crate::filetime::filetime_to_unix;
use crate::limits::Limits;
use crate::model::{Entry, Items, Snapshot};
use ecs_normalise::suricata::is_unsafe;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::io::Read;


/// A JSON string takes at most six bytes per decoded byte (`é`), plus the two quotes.
pub const RAW_ESCAPE_FACTOR: usize = 6;


pub const RAW_QUOTES: usize = 2;


#[derive(Deserialize)]
struct RawEntry<'a> {
    #[serde(borrow, rename = "distinguishedName")]
    dn: &'a RawValue,
    #[serde(borrow, rename = "objectClass")]
    classes: Option<&'a RawValue>,
    #[serde(borrow, rename = "sAMAccountName")]
    account: Option<&'a RawValue>,
    #[serde(rename = "userAccountControl")]
    uac: Option<u32>,
    #[serde(borrow, rename = "servicePrincipalName")]
    spns: Option<&'a RawValue>,
    #[serde(borrow, rename = "memberOf")]
    member_of: Option<&'a RawValue>,
    #[serde(rename = "pwdLastSet")]
    pwd_last_set: Option<u64>,
    #[serde(rename = "lastLogonTimestamp")]
    last_logon: Option<u64>,
    #[serde(borrow, rename = "objectSid")]
    sid: Option<&'a RawValue>,
}


pub fn bad_entry(index: usize, field: &'static str, source: &serde_json::Error) -> SnapshotError {
    SnapshotError::BadEntry {
        index,
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
pub fn text_of(raw: &RawValue, index: usize, field: &'static str, limits: &Limits) -> Result<String, SnapshotError> {
    let raw_cap = limits.max_text_bytes.saturating_mul(RAW_ESCAPE_FACTOR).saturating_add(RAW_QUOTES);
    if raw.get().len() > raw_cap {
        Err(SnapshotError::BadText {
            index,
            field,
            reason: "too long",
        })
    } else {
        let text: String = serde_json::from_str(raw.get()).map_err(|source| bad_entry(index, field, &source))?;
        match text_problem(&text, limits.max_text_bytes) {
            Some(reason) => Err(SnapshotError::BadText { index, field, reason }),
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


/// An array of texts: counted without building it, refused above the bound, then built one text at a time.
pub fn list_of(raw: Option<&RawValue>, index: usize, field: &'static str, limits: &Limits) -> Result<Vec<String>, SnapshotError> {
    match raw {
        None => Ok(Vec::new()),
        Some(list) => match bounded_items(list.get(), limits.max_values).map_err(|source| bad_entry(index, field, &source))? {
            Items::Over(count) => Err(SnapshotError::TooManyValues {
                index,
                field,
                count,
                max: limits.max_values,
            }),
            Items::Within(items) => items.into_iter().map(|item| text_of(item, index, field, limits)).collect(),
        },
    }
}


pub fn optional_text(raw: Option<&RawValue>, index: usize, field: &'static str, limits: &Limits) -> Result<Option<String>, SnapshotError> {
    raw.map(|text| text_of(text, index, field, limits)).transpose()
}


/// A SID is ASCII `S`, digits and `-` only.
pub fn is_sid(text: &str) -> bool {
    text.starts_with("S-") && text.chars().all(|found| found.is_ascii_digit() || found == 'S' || found == '-')
}


pub fn sid_of(raw: Option<&RawValue>, index: usize, limits: &Limits) -> Result<Option<String>, SnapshotError> {
    let sid = optional_text(raw, index, "objectSid", limits)?;
    match sid {
        Some(text) if !is_sid(&text) => Err(SnapshotError::BadText {
            index,
            field: "objectSid",
            reason: "not a SID",
        }),
        other => Ok(other),
    }
}


pub fn filetime_of(ticks: Option<u64>, index: usize, field: &'static str) -> Result<Option<i64>, SnapshotError> {
    match ticks {
        None => Ok(None),
        Some(value) => filetime_to_unix(value).map_err(|source| SnapshotError::BadFiletime { index, field, source }),
    }
}


pub fn entry_of(index: usize, raw: &RawValue, limits: &Limits) -> Result<Entry, SnapshotError> {
    let parsed: RawEntry = serde_json::from_str(raw.get()).map_err(|source| bad_entry(index, "entry", &source))?;
    Ok(Entry {
        dn: text_of(parsed.dn, index, "distinguishedName", limits)?,
        classes: list_of(parsed.classes, index, "objectClass", limits)?,
        account: optional_text(parsed.account, index, "sAMAccountName", limits)?,
        uac: parsed.uac.unwrap_or(0),
        spns: list_of(parsed.spns, index, "servicePrincipalName", limits)?,
        member_of: list_of(parsed.member_of, index, "memberOf", limits)?,
        pwd_last_set: filetime_of(parsed.pwd_last_set, index, "pwdLastSet")?,
        last_logon: filetime_of(parsed.last_logon, index, "lastLogonTimestamp")?,
        sid: sid_of(parsed.sid, index, limits)?,
    })
}


/// Two entries with the same DN (compared case-insensitively) make every group lookup ambiguous: refused.
pub fn check_unique(entries: &[Entry]) -> Result<(), SnapshotError> {
    let mut seen = BTreeSet::new();
    entries.iter().enumerate().try_for_each(|(index, entry)| {
        if seen.insert(entry.dn.to_lowercase()) {
            Ok(())
        } else {
            Err(SnapshotError::DuplicateDn { index })
        }
    })
}


pub fn parse_entries(buffer: &[u8], limits: &Limits) -> Result<Snapshot, SnapshotError> {
    let text = std::str::from_utf8(buffer).map_err(SnapshotError::NotUtf8)?;
    match bounded_items(text, limits.max_entries).map_err(|source| malformed(&source))? {
        Items::Over(count) => Err(SnapshotError::TooManyEntries {
            count,
            max: limits.max_entries,
        }),
        Items::Within(raws) => {
            let entries = raws
                .into_iter()
                .enumerate()
                .map(|(index, raw)| entry_of(index, raw, limits))
                .collect::<Result<Vec<_>, _>>()?;
            check_unique(&entries)?;
            Ok(Snapshot { entries })
        }
    }
}


/// Reads a JSON array of entries: size, entry count and every value count are checked before anything is built.
pub fn read_snapshot<Source: Read>(source: Source, limits: &Limits) -> Result<Snapshot, SnapshotError> {
    let mut buffer = Vec::new();
    source
        .take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(SnapshotError::Read)?;
    if buffer.len() as u64 > limits.max_bytes {
        Err(SnapshotError::TooLarge { max: limits.max_bytes })
    } else {
        parse_entries(&buffer, limits)
    }
}

//! CISA Known Exploited Vulnerabilities catalogue parser.

use crate::error::KevError;
use crate::limits::{MAX_CATALOGUE_TEXT_CHARS, MAX_KEV_BYTES, MAX_KEV_ENTRIES};
use crate::text::{bounded_text, is_cve_id};
use serde::Deserialize;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KevLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_text_chars: usize,
}


impl Default for KevLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_KEV_BYTES,
            max_entries: MAX_KEV_ENTRIES,
            max_text_chars: MAX_CATALOGUE_TEXT_CHARS,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KevEntry {
    pub date_added: Option<String>,
    pub due_date: Option<String>,
    pub ransomware_use: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KevCatalogue {
    pub ids: BTreeSet<String>,
    pub entries: BTreeMap<String, KevEntry>,
    pub catalog_version: Option<String>,
    pub date_released: Option<String>,
    pub declared_count: Option<u64>,
    pub count_matches: bool,
    pub bad_entries: usize,
    pub duplicates: usize,
}


#[derive(Deserialize)]
struct RawCatalogue {
    #[serde(rename = "catalogVersion")]
    catalog_version: Option<String>,
    #[serde(rename = "dateReleased")]
    date_released: Option<String>,
    count: Option<u64>,
    vulnerabilities: Vec<RawEntry>,
}


#[derive(Deserialize)]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: Option<String>,
    #[serde(rename = "dateAdded")]
    date_added: Option<String>,
    #[serde(rename = "dueDate")]
    due_date: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse")]
    ransomware_use: Option<String>,
}


fn read_capped<Source: Read>(source: Source, max_bytes: u64) -> Result<Vec<u8>, KevError> {
    let mut bytes = Vec::new();
    source.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Err(KevError::TooLarge { max: max_bytes })
    } else {
        Ok(bytes)
    }
}


/// Reads the CISA JSON under a byte cap and an entry cap; the first of duplicate ids wins, a bad `cveID` is counted and dropped.
pub fn parse_kev<Source: Read>(source: Source, limits: &KevLimits) -> Result<KevCatalogue, KevError> {
    let bytes = read_capped(source, limits.max_bytes)?;
    let raw: RawCatalogue = serde_json::from_slice(&bytes)?;
    if raw.vulnerabilities.len() > limits.max_entries {
        Err(KevError::TooMany {
            count: raw.vulnerabilities.len(),
            max: limits.max_entries,
        })?;
    }
    let text = |value: Option<String>| value.map(|inner| bounded_text(&inner, limits.max_text_chars));
    let mut entries = BTreeMap::new();
    let mut bad_entries = 0;
    let mut duplicates = 0;
    raw.vulnerabilities
        .into_iter()
        .for_each(|entry| match entry.cve_id.filter(|id| is_cve_id(id)) {
            None => bad_entries += 1,
            Some(id) => match entries.entry(id) {
                Entry::Occupied(_) => duplicates += 1,
                Entry::Vacant(slot) => {
                    slot.insert(KevEntry {
                        date_added: text(entry.date_added),
                        due_date: text(entry.due_date),
                        ransomware_use: text(entry.ransomware_use),
                    });
                }
            },
        });
    let parsed = entries.len() + bad_entries + duplicates;
    Ok(KevCatalogue {
        ids: entries.keys().cloned().collect(),
        entries,
        catalog_version: text(raw.catalog_version),
        date_released: text(raw.date_released),
        declared_count: raw.count,
        count_matches: raw.count == Some(parsed as u64),
        bad_entries,
        duplicates,
    })
}

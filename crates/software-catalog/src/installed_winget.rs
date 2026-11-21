//! Reads `winget export --include-versions --accept-source-agreements -o <file>` JSON, bounded (counts before any element is decoded).

use crate::error::InstalledError;
use crate::installed::read_input;
use crate::limits::Limits;
use crate::model::{Installed, InstalledRow, Manager};
use crate::text::is_winget_id;
use patch_inventory::validate::is_plain_text;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::io::Read;


const BOM: &[u8] = b"\xEF\xBB\xBF";


const WINGET_SOURCE_NAME: &str = "winget";


const WINGET_SOURCE_IDENTIFIER: &str = "Microsoft.Winget.Source_8wekyb3d8bbwe";


const MAX_VERSION_BYTES: usize = 128;


#[derive(Deserialize)]
pub struct Counted {
    #[serde(rename = "Sources")]
    pub sources: Vec<IgnoredAny>,
}


#[derive(Deserialize)]
pub struct Document {
    #[serde(rename = "Sources")]
    pub sources: Vec<Box<RawValue>>,
}


#[derive(Deserialize)]
pub struct Details {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Identifier")]
    pub identifier: Option<String>,
}


#[derive(Deserialize)]
pub struct Head {
    #[serde(rename = "SourceDetails")]
    pub details: Details,
    #[serde(rename = "Packages")]
    pub packages: Vec<IgnoredAny>,
}


#[derive(Deserialize)]
pub struct Body {
    #[serde(rename = "Packages")]
    pub packages: Vec<Box<RawValue>>,
}


#[derive(Deserialize)]
#[serde(untagged)]
pub enum VersionField {
    Text(String),
    Other(IgnoredAny),
}


#[derive(Deserialize)]
pub struct Package {
    #[serde(rename = "PackageIdentifier")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: Option<VersionField>,
}


pub struct Candidate {
    pub package: String,
    pub version: Option<String>,
}


pub fn is_object(raw: &RawValue) -> bool {
    raw.get().starts_with('{')
}


pub fn head_of(index: usize, raw: &RawValue) -> Result<Head, InstalledError> {
    Some(raw)
        .filter(|candidate| is_object(candidate))
        .and_then(|object| serde_json::from_str::<Head>(object.get()).ok())
        .ok_or(InstalledError::WingetSource { index })
}


pub fn is_winget_source(head: &Head) -> bool {
    head.details.name == WINGET_SOURCE_NAME && head.details.identifier.as_deref() == Some(WINGET_SOURCE_IDENTIFIER)
}


pub fn readable_version(field: Option<VersionField>) -> Option<String> {
    match field {
        Some(VersionField::Text(text)) if is_plain_text(&text) && text.len() <= MAX_VERSION_BYTES => Some(text),
        _ => None,
    }
}


pub fn candidate_of(raw: &RawValue) -> Option<Candidate> {
    let package = Some(raw)
        .filter(|object| is_object(object))
        .and_then(|object| serde_json::from_str::<Package>(object.get()).ok())
        .filter(|decoded| is_winget_id(&decoded.id))?;
    Some(Candidate {
        package: package.id,
        version: readable_version(package.version),
    })
}


pub fn folded(candidate: &Candidate) -> String {
    candidate.package.to_ascii_lowercase()
}


pub fn assemble(candidates: Vec<Option<Candidate>>) -> Installed {
    let malformed = candidates.iter().filter(|candidate| candidate.is_none()).count();
    let valid: Vec<Candidate> = candidates.into_iter().flatten().collect();
    let counts = valid.iter().fold(BTreeMap::<String, usize>::new(), |mut counts, candidate| {
        *counts.entry(folded(candidate)).or_default() += 1;
        counts
    });
    let duplicate_ids = counts.values().filter(|count| **count > 1).count();
    let unreadable_versions = valid.iter().filter(|candidate| candidate.version.is_none()).count();
    let rows: BTreeMap<String, InstalledRow> = valid
        .into_iter()
        .map(|candidate| {
            let unique = counts.get(&folded(&candidate)) == Some(&1);
            let version = candidate.version.filter(|_| unique).unwrap_or_else(String::new);
            (
                candidate.package.clone(),
                InstalledRow {
                    manager: Manager::Winget,
                    package: candidate.package,
                    version,
                    held: false,
                },
            )
        })
        .collect();
    Installed {
        rows: rows.into_values().collect(),
        malformed,
        duplicate_ids,
        unreadable_versions,
        ..Installed::default()
    }
}


pub fn winget_installed(raw: &RawValue, count: usize, limits: &Limits) -> Result<Installed, InstalledError> {
    if count > limits.max_installed {
        Ok(Installed {
            over_limit: count,
            ..Installed::default()
        })
    } else {
        let body: Body = serde_json::from_str(raw.get())?;
        Ok(assemble(body.packages.iter().map(|package| candidate_of(package)).collect()))
    }
}


pub fn merge(left: Installed, right: Installed) -> Installed {
    Installed {
        rows: left.rows.into_iter().chain(right.rows).collect(),
        malformed: left.malformed + right.malformed,
        over_limit: left.over_limit + right.over_limit,
        not_installed: left.not_installed + right.not_installed,
        other_source: left.other_source + right.other_source,
        unreadable_versions: left.unreadable_versions + right.unreadable_versions,
        duplicate_ids: left.duplicate_ids + right.duplicate_ids,
    }
}


pub fn parse_winget_export<Source: Read>(reader: Source, limits: &Limits) -> Result<Installed, InstalledError> {
    let buffer = read_input(reader, limits)?;
    let bytes = buffer.strip_prefix(BOM).unwrap_or(buffer.as_slice());
    let counted: Counted = serde_json::from_slice(bytes)?;
    if counted.sources.len() > limits.max_sources {
        Err(InstalledError::TooManySources { limit: limits.max_sources })
    } else {
        let document: Document = serde_json::from_slice(bytes)?;
        let heads = document
            .sources
            .iter()
            .enumerate()
            .map(|(index, raw)| head_of(index, raw))
            .collect::<Result<Vec<Head>, InstalledError>>()?;
        let named = heads.iter().filter(|head| head.details.name == WINGET_SOURCE_NAME).count();
        if named > 1 {
            Err(InstalledError::DuplicateSource)
        } else {
            document
                .sources
                .iter()
                .zip(heads.iter())
                .try_fold(Installed::default(), |installed, (raw, head)| {
                    let source = if is_winget_source(head) {
                        winget_installed(raw, head.packages.len(), limits)?
                    } else {
                        Installed {
                            other_source: head.packages.len(),
                            ..Installed::default()
                        }
                    };
                    Ok(merge(installed, source))
                })
        }
    }
}

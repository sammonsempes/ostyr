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


const MAX_ID_BYTES: usize = 1024;


const QUOTES: usize = 2;


#[derive(Deserialize)]
pub struct Counted {
    #[serde(rename = "Sources")]
    pub sources: Vec<IgnoredAny>,
}


#[derive(Deserialize)]
pub struct Document<'a> {
    #[serde(rename = "Sources", borrow)]
    pub sources: Vec<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct Details {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Identifier")]
    pub identifier: Option<String>,
}


#[derive(Deserialize)]
pub struct Head<'a> {
    #[serde(rename = "SourceDetails", borrow)]
    pub details: &'a RawValue,
    #[serde(rename = "Packages")]
    pub packages: Vec<IgnoredAny>,
}


pub struct Source {
    pub details: Details,
    pub packages: usize,
}


#[derive(Deserialize)]
pub struct Body<'a> {
    #[serde(rename = "Packages", borrow)]
    pub packages: Vec<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct Identity<'a> {
    #[serde(rename = "PackageIdentifier", borrow)]
    pub id: &'a RawValue,
}


#[derive(Deserialize)]
pub struct Versioned<'a> {
    #[serde(rename = "Version", borrow)]
    pub version: Option<&'a RawValue>,
}


pub struct Candidate {
    pub package: String,
    pub version: Option<String>,
}


pub fn is_object(raw: &RawValue) -> bool {
    raw.get().starts_with('{')
}


pub fn source_of(index: usize, raw: &RawValue) -> Result<Source, InstalledError> {
    let head = Some(raw)
        .filter(|candidate| is_object(candidate))
        .and_then(|object| serde_json::from_str::<Head>(object.get()).ok());
    head.as_ref()
        .map(|decoded| decoded.details)
        .filter(|details| is_object(details))
        .and_then(|details| serde_json::from_str::<Details>(details.get()).ok())
        .zip(head.map(|decoded| decoded.packages.len()))
        .map(|(details, packages)| Source { details, packages })
        .ok_or(InstalledError::WingetSource { index })
}


pub fn is_winget_source(details: &Details) -> bool {
    details.name == WINGET_SOURCE_NAME && details.identifier.as_deref() == Some(WINGET_SOURCE_IDENTIFIER)
}


pub fn short_text(raw: &RawValue, cap: usize) -> Option<String> {
    let text = raw.get();
    (text.starts_with('"') && text.len() <= cap + QUOTES)
        .then(|| serde_json::from_str::<String>(text).ok())
        .flatten()
}


pub fn candidate_of(raw: &RawValue) -> Option<Candidate> {
    let identity: Identity = Some(raw)
        .filter(|object| is_object(object))
        .and_then(|object| serde_json::from_str(object.get()).ok())?;
    let package = short_text(identity.id, MAX_ID_BYTES).filter(|text| is_winget_id(text))?;
    let version = serde_json::from_str::<Versioned>(raw.get())
        .ok()
        .and_then(|versioned| versioned.version)
        .and_then(|text| short_text(text, MAX_VERSION_BYTES))
        .filter(|text| is_plain_text(text));
    Some(Candidate { package, version })
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
        manager: Some(Manager::Winget),
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
            manager: Some(Manager::Winget),
            over_limit: count,
            ..Installed::default()
        })
    } else {
        let body: Body = serde_json::from_str(raw.get())?;
        Ok(assemble(body.packages.into_iter().map(candidate_of).collect()))
    }
}


pub fn winget_start() -> Installed {
    Installed {
        manager: Some(Manager::Winget),
        ..Installed::default()
    }
}


pub fn merge(left: Installed, right: Installed) -> Installed {
    Installed {
        manager: if left.manager == right.manager { left.manager } else { None },
        rows: left.rows.into_iter().chain(right.rows).collect(),
        malformed: left.malformed + right.malformed,
        over_limit: left.over_limit + right.over_limit,
        not_installed: left.not_installed + right.not_installed,
        other_source: left.other_source + right.other_source,
        unreadable_versions: left.unreadable_versions + right.unreadable_versions,
        duplicate_ids: left.duplicate_ids + right.duplicate_ids,
    }
}


pub fn checked(index: usize, source: Source) -> Result<Source, InstalledError> {
    if source.details.name == WINGET_SOURCE_NAME && !is_winget_source(&source.details) {
        Err(InstalledError::ForeignWingetSource { index })
    } else {
        Ok(source)
    }
}


pub fn parse_winget_export<Reader: Read>(reader: Reader, limits: &Limits) -> Result<Installed, InstalledError> {
    let buffer = read_input(reader, limits)?;
    let bytes = buffer.strip_prefix(BOM).unwrap_or(buffer.as_slice());
    let counted: Counted = serde_json::from_slice(bytes)?;
    if counted.sources.len() > limits.max_sources {
        Err(InstalledError::TooManySources { limit: limits.max_sources })
    } else {
        let document: Document = serde_json::from_slice(bytes)?;
        let sources = document
            .sources
            .iter()
            .enumerate()
            .map(|(index, raw)| source_of(index, raw).and_then(|source| checked(index, source)))
            .collect::<Result<Vec<Source>, InstalledError>>()?;
        let named = sources.iter().filter(|source| source.details.name == WINGET_SOURCE_NAME).count();
        if named > 1 {
            Err(InstalledError::DuplicateSource)
        } else {
            document
                .sources
                .iter()
                .zip(sources.iter())
                .try_fold(winget_start(), |installed, (raw, source)| {
                    let part = if is_winget_source(&source.details) {
                        winget_installed(raw, source.packages, limits)?
                    } else {
                        Installed {
                            manager: Some(Manager::Winget),
                            other_source: source.packages,
                            ..Installed::default()
                        }
                    };
                    Ok(merge(installed, part))
                })
        }
    }
}

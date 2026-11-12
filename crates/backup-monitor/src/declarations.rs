use crate::error::BackupError;
use crate::model::{Declarations, DeclarationsFile, DEFAULT_MAX_TEXT_CHARS};
use crate::text::valid_text;
use core_config::parse::parse_document;
use core_pg::scope::tenant_scope;
use std::collections::BTreeSet;


pub const MAX_ENTRIES: usize = 10_000;


pub const MIN_AGE_HOURS: u32 = 1;


pub const MAX_AGE_HOURS: u32 = 8760;


pub const MAX_FLOOR: usize = 1_000_000;


pub fn all_unique<'a>(names: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    names.into_iter().all(|name| seen.insert(name))
}


/// The first invalid part of the declarations, or `None`.
pub fn problem(file: &DeclarationsFile) -> Option<&'static str> {
    if file.critical.len() > MAX_ENTRIES || file.repositories.len() > MAX_ENTRIES {
        Some("entry count")
    } else if !file.critical.iter().all(|entry| valid_text(&entry.host, DEFAULT_MAX_TEXT_CHARS)) {
        Some("critical host")
    } else if !file
        .critical
        .iter()
        .all(|entry| (MIN_AGE_HOURS..=MAX_AGE_HOURS).contains(&entry.max_age_hours))
    {
        Some("max_age_hours")
    } else if !all_unique(file.critical.iter().map(|entry| entry.host.as_str())) {
        Some("duplicate critical host")
    } else if !file
        .repositories
        .iter()
        .all(|entry| valid_text(&entry.repository, DEFAULT_MAX_TEXT_CHARS))
    {
        Some("repository")
    } else if !file
        .repositories
        .iter()
        .all(|entry| (1..=MAX_FLOOR).contains(&entry.expected_min_snapshots))
    {
        Some("expected_min_snapshots")
    } else if !all_unique(file.repositories.iter().map(|entry| entry.repository.as_str())) {
        Some("duplicate repository")
    } else {
        None
    }
}


/// Parses and validates a declarations file; `file` only labels parse errors.
pub fn load_declarations(text: &str, file: &str) -> Result<Declarations, BackupError> {
    let parsed: DeclarationsFile = parse_document(text, file)?;
    let tenant = tenant_scope(&parsed.tenant)?;
    match problem(&parsed) {
        Some(what) => Err(BackupError::InvalidDeclarations { what }),
        None => Ok(Declarations {
            tenant,
            hostname_from_name: parsed.hostname_from_name,
            critical: parsed.critical,
            repositories: parsed.repositories,
        }),
    }
}

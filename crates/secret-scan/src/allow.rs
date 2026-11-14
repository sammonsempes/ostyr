//! The path allowlists of the scanner rules file, checked against the work directory (Unix only).

use crate::scan::{ensure, ScanError};
use regex::Regex;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use toml::{Table, Value};


pub const MAX_RULES_BYTES: u64 = 1 << 20;


pub const PROBE_DIR: &str = "secret-scan-XXXXXX";


fn paths_of(table: &Table) -> impl Iterator<Item = &str> {
    table
        .get("paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}


fn allowlist_tables(owner: &Table) -> Vec<&Table> {
    let single = owner.get("allowlist").and_then(Value::as_table);
    let many = owner
        .get("allowlists")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_table);
    single.into_iter().chain(many).collect()
}


/// Every `paths` regex of the `[allowlist]` and `[[allowlists]]` tables of the rules file, global and per rule.
pub fn allowlist_patterns(text: &str) -> Result<Vec<String>, ScanError> {
    let table: Table = text.parse().map_err(|_| ScanError::BadRules("not valid TOML"))?;
    let rules = table
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_table);
    Ok(std::iter::once(&table)
        .chain(rules)
        .flat_map(allowlist_tables)
        .flat_map(paths_of)
        .map(str::to_string)
        .collect())
}


/// Reads the rules file without following a link, at most `MAX_RULES_BYTES`.
pub fn read_rules(rules: &Path) -> Result<String, ScanError> {
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(rules)?
        .take(MAX_RULES_BYTES + 1)
        .read_to_string(&mut text)?;
    ensure(text.len() as u64 <= MAX_RULES_BYTES, ScanError::BadRules("too large"))?;
    Ok(text)
}


/// Refuses a work directory whose scan paths an allowlist regex of the rules file would match: every finding would then be hidden.
pub fn check_work_dir_rules(rules: &Path, work_dir: &Path) -> Result<(), ScanError> {
    let work_text = work_dir.to_str().ok_or(ScanError::BadSettings("work directory is not UTF-8"))?;
    let normalised = work_text.starts_with('/') && work_text.split('/').skip(1).all(|part| !part.is_empty() && part != "." && part != "..");
    ensure(normalised, ScanError::BadSettings("work directory is not a normalised absolute path"))?;
    let probe = format!("{work_text}/{PROBE_DIR}/data/tree/x");
    allowlist_patterns(&read_rules(rules)?)?.iter().try_for_each(|pattern| {
        let compiled = Regex::new(pattern).map_err(|_| ScanError::BadRules("allowlist pattern does not compile"))?;
        ensure(
            !compiled.is_match(&probe),
            ScanError::BadSettings("work directory matches an allowlist path of the rules"),
        )
    })
}

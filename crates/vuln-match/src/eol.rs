//! End-of-life table and findings.

use crate::error::EolError;
use crate::limits::MAX_EOL_ENTRIES;
use crate::model::{EolEntry, EolFinding, EolTable, Package};
use core_config::parse::{parse_document, read_file};
use std::path::Path;
use time::Date;


pub fn parse_eol_table(text: &str, file: &str) -> Result<EolTable, EolError> {
    let table: EolTable = parse_document(text, file)?;
    if table.entries.len() > MAX_EOL_ENTRIES {
        Err(EolError::TooMany {
            count: table.entries.len(),
            max: MAX_EOL_ENTRIES,
        })
    } else {
        Ok(table)
    }
}


pub fn load_eol_table(path: &Path) -> Result<EolTable, EolError> {
    let text = read_file(path)?;
    parse_eol_table(&text, &path.display().to_string())
}


/// A package is on a cycle when its version equals the cycle or starts with `<cycle>.`; end of life starts on the end date itself.
pub fn eol_findings(packages: &[Package], table: &EolTable, today: Date) -> Vec<EolFinding> {
    let mut findings: Vec<EolFinding> = packages
        .iter()
        .flat_map(|package| {
            table
                .entries
                .iter()
                .filter(|entry| entry.product == package.name && on_cycle(&package.version, entry) && entry.end_date <= today)
                .map(|entry| EolFinding {
                    package: package.name.clone(),
                    installed_version: package.version.clone(),
                    ecosystem: package.ecosystem.clone(),
                    cycle: entry.cycle.clone(),
                    end_date: entry.end_date,
                })
        })
        .collect();
    findings.sort();
    findings.dedup();
    findings
}


fn on_cycle(version: &str, entry: &EolEntry) -> bool {
    version == entry.cycle || version.strip_prefix(entry.cycle.as_str()).is_some_and(|rest| rest.starts_with('.'))
}

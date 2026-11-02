use std::fmt;
use std::path::{Path, PathBuf};

use crate::export::{Counts, Export, FileEntry};

#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    Missing { file: PathBuf },
    Branches { file: PathBuf, covered: u64, total: u64 },
    Lines { file: PathBuf, covered: u64, total: u64 },
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::Missing { file } => write!(formatter, "{}: absent from the coverage export", file.display()),
            Violation::Branches { file, covered, total } => write!(formatter, "{}: branches {covered}/{total}", file.display()),
            Violation::Lines { file, covered, total } => write!(formatter, "{}: lines {covered}/{total}", file.display()),
        }
    }
}

pub fn shortfall(counts: &Counts) -> Option<(u64, u64)> {
    (counts.covered < counts.count).then_some((counts.covered, counts.count))
}

pub fn check_entry(source: &Path, entry: &FileEntry) -> Vec<Violation> {
    let branches = shortfall(&entry.summary.branches).map(|(covered, total)| Violation::Branches {
        file: source.to_path_buf(),
        covered,
        total,
    });
    let lines = shortfall(&entry.summary.lines).map(|(covered, total)| Violation::Lines {
        file: source.to_path_buf(),
        covered,
        total,
    });
    branches.into_iter().chain(lines).collect()
}

pub fn check(export: &Export, sources: &[PathBuf]) -> Vec<Violation> {
    sources
        .iter()
        .flat_map(
            |source| match export.data.iter().flat_map(|data| &data.files).find(|entry| &entry.filename == source) {
                Some(entry) => check_entry(source, entry),
                None => vec![Violation::Missing { file: source.clone() }],
            },
        )
        .collect()
}

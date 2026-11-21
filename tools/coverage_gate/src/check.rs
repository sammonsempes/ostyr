use crate::error::GateError;
use crate::executable::file_has_executable_code;
use crate::export::{Counts, Export, FileEntry};
use std::fmt;
use std::path::{Path, PathBuf};


const BOUNDARY_DIR: &str = "crates/ebpf-probes";


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


pub fn in_boundary(root: &Path, source: &Path) -> bool {
    source.starts_with(root.join(BOUNDARY_DIR))
}


pub fn check_source(export: &Export, root: &Path, source: &Path) -> Result<Vec<Violation>, GateError> {
    let listed = export.data.iter().flat_map(|data| &data.files).find(|entry| entry.filename == source);
    Ok(match listed {
        Some(entry) => check_entry(source, entry),
        None => file_has_executable_code(source, in_boundary(root, source))?
            .then(|| Violation::Missing { file: source.to_path_buf() })
            .into_iter()
            .collect(),
    })
}


pub fn check(export: &Export, root: &Path, sources: &[PathBuf]) -> Result<Vec<Violation>, GateError> {
    let per_file = sources
        .iter()
        .map(|source| check_source(export, root, source))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(per_file.into_iter().flatten().collect())
}

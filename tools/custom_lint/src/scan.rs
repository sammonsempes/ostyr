use crate::{
    comments::extract_comments,
    error::LintError,
    model::{Context, Violation},
    rules::RULES,
    types::FileReader,
};
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};


const SCAN_DIRS: [&str; 2] = ["crates", "tools"];


const SKIPPED_DIR: &str = "target";


const RUST_EXTENSION: &str = "rs";


pub fn lint_source(path: &Path, source: &str) -> Result<Vec<Violation>, LintError> {
    let file = syn::parse_file(source).map_err(|error| LintError::Parse {
        path: path.to_path_buf(),
        source: error,
    })?;
    let context = Context {
        path: path.to_path_buf(),
        source: source.to_string(),
        comments: extract_comments(source),
        file,
    };
    Ok(RULES.iter().flat_map(|rule| (rule.check)(&context)).collect())
}


pub fn lint_file(root: &Path, path: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    let relative: PathBuf = path.components().skip(root.components().count()).collect();
    let bytes = read(path).map_err(|error| LintError::Read {
        path: relative.clone(),
        source: error,
    })?;
    let text = String::from_utf8(bytes).map_err(|error| LintError::Utf8 {
        path: relative.clone(),
        source: error,
    })?;
    lint_source(&relative, &text)
}


pub fn is_rust_file(entry: &DirEntry) -> bool {
    entry.file_type().is_file() && entry.path().extension().is_some_and(|extension| extension == RUST_EXTENSION)
}


pub fn lint_entry(
    root: &Path,
    mut found: Vec<Violation>,
    entry_result: Result<DirEntry, walkdir::Error>,
    read: FileReader,
) -> Result<Vec<Violation>, LintError> {
    let entry = entry_result?;
    if is_rust_file(&entry) {
        found.extend(lint_file(root, entry.path(), read)?);
    }
    Ok(found)
}


pub fn lint_dir(root: &Path, directory: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    WalkDir::new(directory)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.file_name() != SKIPPED_DIR)
        .try_fold(Vec::new(), |found, entry_result| lint_entry(root, found, entry_result, read))
}


pub fn lint_root(root: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    SCAN_DIRS.iter().try_fold(Vec::new(), |mut found, directory| {
        found.extend(lint_dir(root, &root.join(directory), read)?);
        Ok(found)
    })
}

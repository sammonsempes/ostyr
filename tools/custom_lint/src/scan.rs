use crate::{
    comments::extract_comments,
    error::LintError,
    model::{Context, Violation},
    rules::RULES,
    rules_recursion::recursion_in_crate,
    rules_yaml::yaml_comments,
    types::FileReader,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};


const SCAN_DIRS: [&str; 2] = ["crates", "tools"];


const SKIPPED_DIR: &str = "target";


const RUST_EXTENSION: &str = "rs";


const YAML_EXTENSIONS: [&str; 2] = ["yaml", "yml"];


const YAML_SKIPPED_DIRS: [&str; 3] = ["target", ".git", ".cache"];


const CRATE_KEY_DEPTH: usize = 2;


pub fn parse_source(path: &Path, source: &str) -> Result<Context, LintError> {
    let file = syn::parse_file(source).map_err(|error| LintError::Parse {
        path: path.to_path_buf(),
        source: error,
    })?;
    Ok(Context {
        path: path.to_path_buf(),
        source: source.to_string(),
        comments: extract_comments(source),
        file,
    })
}


pub fn file_violations(context: &Context) -> Vec<Violation> {
    RULES.iter().flat_map(|rule| (rule.check)(context)).collect()
}


pub fn crate_key(path: &Path) -> PathBuf {
    path.components().take(CRATE_KEY_DEPTH).collect()
}


pub fn crate_violations(contexts: &[Context]) -> Vec<Violation> {
    contexts
        .iter()
        .fold(BTreeMap::<PathBuf, Vec<&Context>>::new(), |mut groups, context| {
            groups.entry(crate_key(&context.path)).or_default().push(context);
            groups
        })
        .values()
        .flat_map(|group| recursion_in_crate(group))
        .collect()
}


pub fn context_violations(contexts: &[Context]) -> Vec<Violation> {
    contexts.iter().flat_map(file_violations).chain(crate_violations(contexts)).collect()
}


pub fn lint_source(path: &Path, source: &str) -> Result<Vec<Violation>, LintError> {
    let context = parse_source(path, source)?;
    Ok(context_violations(std::slice::from_ref(&context)))
}


pub fn read_text(root: &Path, path: &Path, read: FileReader) -> Result<(PathBuf, String), LintError> {
    let relative: PathBuf = path.components().skip(root.components().count()).collect();
    let bytes = read(path).map_err(|error| LintError::Read {
        path: relative.clone(),
        source: error,
    })?;
    let text = String::from_utf8(bytes).map_err(|error| LintError::Utf8 {
        path: relative.clone(),
        source: error,
    })?;
    Ok((relative, text))
}


pub fn load_file(root: &Path, path: &Path, read: FileReader) -> Result<Context, LintError> {
    let (relative, text) = read_text(root, path, read)?;
    parse_source(&relative, &text)
}


pub fn lint_file(root: &Path, path: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    let context = load_file(root, path, read)?;
    Ok(context_violations(std::slice::from_ref(&context)))
}


pub fn has_extension(entry: &DirEntry, extensions: &[&str]) -> bool {
    entry.file_type().is_file()
        && entry
            .path()
            .extension()
            .is_some_and(|found| extensions.iter().any(|extension| found == *extension))
}


pub fn load_entry(
    root: &Path,
    mut found: Vec<Context>,
    entry_result: Result<DirEntry, walkdir::Error>,
    read: FileReader,
) -> Result<Vec<Context>, LintError> {
    let entry = entry_result?;
    if has_extension(&entry, &[RUST_EXTENSION]) {
        found.push(load_file(root, entry.path(), read)?);
    }
    Ok(found)
}


pub fn load_dir(root: &Path, directory: &Path, read: FileReader) -> Result<Vec<Context>, LintError> {
    WalkDir::new(directory)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.file_name() != SKIPPED_DIR)
        .try_fold(Vec::new(), |found, entry_result| load_entry(root, found, entry_result, read))
}


pub fn lint_yaml_entry(
    root: &Path,
    mut found: Vec<Violation>,
    entry_result: Result<DirEntry, walkdir::Error>,
    read: FileReader,
) -> Result<Vec<Violation>, LintError> {
    let entry = entry_result?;
    if has_extension(&entry, &YAML_EXTENSIONS) {
        let (relative, text) = read_text(root, entry.path(), read)?;
        found.extend(yaml_comments(&relative, &text));
    }
    Ok(found)
}


pub fn lint_yaml_tree(root: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !YAML_SKIPPED_DIRS.iter().any(|skipped| entry.file_name() == *skipped))
        .try_fold(Vec::new(), |found, entry_result| lint_yaml_entry(root, found, entry_result, read))
}


pub fn lint_root(root: &Path, read: FileReader) -> Result<Vec<Violation>, LintError> {
    let contexts = SCAN_DIRS.iter().try_fold(Vec::new(), |mut found, directory| {
        found.extend(load_dir(root, &root.join(directory), read)?);
        Ok::<_, LintError>(found)
    })?;
    let mut violations = context_violations(&contexts);
    violations.extend(lint_yaml_tree(root, read)?);
    Ok(violations)
}

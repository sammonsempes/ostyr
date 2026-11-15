//! Rule loading: every `.yar` and `.yara` file of a directory is compiled once; any failure fails the whole load.


use crate::error::NdrError;
use crate::model::Limits;
use crate::reader::read_capped;
use std::error::Error;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Rules};


const MAX_LOG_CHARS: usize = 1_000;


/// A rule file is a regular name ending in `.yar` or `.yara`.
pub fn is_rule_file(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "yar" || extension == "yara")
}


/// Keeps the rule files of a directory listing in name order, at most `max_rule_files`; one more is an error, never a silent cut.
pub fn rule_files_from(entries: Box<dyn Iterator<Item = io::Result<PathBuf>>>, dir: &Path, limits: &Limits) -> Result<Vec<PathBuf>, NdrError> {
    let mut files = entries
        .filter(|entry| entry.as_ref().map_or(true, |path| is_rule_file(path)))
        .take(limits.max_rule_files.saturating_add(1))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|source| NdrError::RulesDir {
            path: dir.to_path_buf(),
            source,
        })?;
    files.sort();
    match (files.len() > limits.max_rule_files, files.is_empty()) {
        (true, _) => Err(NdrError::TooManyRuleFiles {
            max_files: limits.max_rule_files,
        }),
        (false, true) => Err(NdrError::NoRules),
        (false, false) => Ok(files),
    }
}


/// Lists the rule files of `dir`.
pub fn list_rule_files(dir: &Path, limits: &Limits) -> Result<Vec<PathBuf>, NdrError> {
    let entries = fs::read_dir(dir).map_err(|source| NdrError::RulesDir {
        path: dir.to_path_buf(),
        source,
    })?;
    rule_files_from(Box::new(entries.map(|entry| entry.map(|found| found.path()))), dir, limits)
}


/// Reads one rule file under the size cap; a larger file is refused.
pub fn read_rule(path: &Path, max_bytes: u64) -> Result<String, NdrError> {
    let read_error = |source| NdrError::RuleRead {
        path: path.to_path_buf(),
        source,
    };
    let content = read_capped(File::open(path).map_err(read_error)?, max_bytes).map_err(read_error)?;
    let bytes = content.ok_or_else(|| NdrError::RuleTooLarge {
        path: path.to_path_buf(),
        max_bytes,
    })?;
    String::from_utf8(bytes).map_err(|source| read_error(io::Error::new(io::ErrorKind::InvalidData, source)))
}


/// Compiles the whole directory; the first file that fails to read or compile fails the load.
pub fn load_rules(dir: &Path, limits: &Limits) -> Result<Rules, NdrError> {
    let mut compiler = Compiler::new();
    list_rule_files(dir, limits)?.iter().try_for_each(|path| {
        let text = read_rule(path, limits.max_rule_bytes)?;
        compiler
            .add_source(text.as_str())
            .map(|_| ())
            .map_err(|source| NdrError::Compile { path: path.clone(), source })
    })?;
    Ok(compiler.build())
}


/// The error and its cause on one text, cut to `MAX_LOG_CHARS`.
pub fn describe(error: &NdrError) -> String {
    let cause = error.source().map_or_else(String::new, |source| format!(": {source}"));
    format!("{error}{cause}").chars().take(MAX_LOG_CHARS).collect()
}


/// Reloads from `dir`; when the new set is refused the current one stays and the cause is logged.
pub fn swap_rules(current: Rules, dir: &Path, limits: &Limits) -> Rules {
    match load_rules(dir, limits) {
        Ok(fresh) => fresh,
        Err(error) => {
            let cause = describe(&error);
            tracing::warn!(cause = %cause, "rule reload refused, keeping the current rules");
            current
        }
    }
}

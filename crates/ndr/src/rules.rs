//! Rule loading: every `.yar` and `.yara` file of a directory is compiled once by `yr compile`; any failure fails the whole load.


use crate::error::NdrError;
use crate::exec::run_bounded;
use crate::model::{Limits, Yr};
use crate::reader::read_capped;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;


const MAX_LOG_CHARS: usize = 1_000;


const COMPILED_NAME: &str = "rules.yarc";


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


/// Compiled rules: the `.yarc` file lives in a private directory that is removed when the value is dropped.
#[derive(Debug)]
pub struct Rules {
    pub compiled: PathBuf,
    pub workspace: TempDir,
}


/// Copies one checked rule file into the private directory, so `yr` compiles exactly the bytes that passed the size and UTF-8 checks.
pub fn copy_rule(path: &Path, workspace: &Path, index: usize, max_bytes: u64) -> Result<PathBuf, NdrError> {
    let text = read_rule(path, max_bytes)?;
    let copy = workspace.join(format!("rule-{index:05}.yar"));
    fs::write(&copy, text).map_err(NdrError::Workspace)?;
    Ok(copy)
}


/// The `yr compile` arguments: the output first, then `--` so no file name can read as an option.
pub fn compile_args(compiled: &Path, sources: &[PathBuf]) -> Vec<OsString> {
    let head = [
        OsString::from("compile"),
        OsString::from("--output"),
        compiled.as_os_str().to_os_string(),
        OsString::from("--"),
    ];
    head.into_iter()
        .chain(sources.iter().map(|source| source.as_os_str().to_os_string()))
        .collect()
}


/// Compiles the whole directory with `yr compile`; the first file that fails to read, or any compile error, fails the load.
pub fn load_rules(yr: &Yr, dir: &Path, limits: &Limits) -> Result<Rules, NdrError> {
    let files = list_rule_files(dir, limits)?;
    let workspace = tempfile::Builder::new()
        .prefix("ndr-rules-")
        .tempdir_in(&yr.work_dir)
        .map_err(NdrError::Workspace)?;
    let sources = files
        .iter()
        .enumerate()
        .map(|(index, path)| copy_rule(path, workspace.path(), index, limits.max_rule_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let compiled = workspace.path().join(COMPILED_NAME);
    let run = run_bounded(yr, &compile_args(&compiled, &sources), limits.max_output_bytes, limits.compile_timeout)?;
    match run.exited_ok && compiled.is_file() {
        true => Ok(Rules { compiled, workspace }),
        false => Err(NdrError::Compile {
            exited_ok: run.exited_ok,
            timed_out: run.timed_out,
            cut: run.cut,
            stderr: String::from_utf8_lossy(&run.bytes).escape_debug().to_string(),
        }),
    }
}


/// The error and its cause on one text, cut to `MAX_LOG_CHARS`.
pub fn describe(error: &NdrError) -> String {
    let cause = error.source().map_or_else(String::new, |source| format!(": {source}"));
    format!("{error}{cause}").chars().take(MAX_LOG_CHARS).collect()
}


/// Reloads from `dir`; when the new set is refused the current one stays and the cause is logged.
pub fn swap_rules(yr: &Yr, current: Rules, dir: &Path, limits: &Limits) -> Rules {
    match load_rules(yr, dir, limits) {
        Ok(fresh) => fresh,
        Err(error) => {
            let cause = describe(&error);
            tracing::warn!(cause = %cause, "rule reload refused, keeping the current rules");
            current
        }
    }
}

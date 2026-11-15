//! The path allowlists of the scanner rules file, checked against the work directory (Unix only).

use crate::scan::{ensure, ScanError};
use regex::bytes::{Regex, RegexBuilder};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use toml::{Table, Value};


pub const MAX_RULES_BYTES: u64 = 1 << 20;


pub const PROBE_DIR: &str = "secret-scan-XXXXXX";


pub const MAX_KEY_PATH: usize = 64;


pub const CUT_MARK: &str = "...";


pub const TOP_KEYS: [&str; 5] = ["title", "description", "allowlist", "allowlists", "rules"];


pub const RULE_KEYS: [&str; 10] = [
    "id",
    "description",
    "path",
    "regex",
    "secretGroup",
    "entropy",
    "keywords",
    "tags",
    "allowlist",
    "allowlists",
];


pub const RULE_ALLOWLIST_KEYS: [&str; 7] = ["description", "condition", "commits", "paths", "regexTarget", "regexes", "stopwords"];


pub const GLOBAL_ALLOWLIST_KEYS: [&str; 8] = [
    "description",
    "condition",
    "commits",
    "paths",
    "regexTarget",
    "regexes",
    "stopwords",
    "targetRules",
];


pub const STRING_LISTS: [&str; 7] = ["paths", "regexes", "stopwords", "commits", "keywords", "tags", "targetRules"];


pub const PROBE_TAILS: [&str; 5] = ["/data", "/data/tree", "/data/tree/x", "/data/tree/xx", "/data/tree/xxxxxxxx"];


pub const WIDE_ESCAPES: [char; 6] = ['x', 'u', 'U', 'p', 'P', 'N'];


pub struct NamedTable<'a> {
    pub name: String,
    pub table: &'a Table,
}


/// The refused key path as printable ASCII, cut to `MAX_KEY_PATH` characters with a visible mark.
pub fn key_path_text(path: &str) -> String {
    let clean: String = path.chars().map(|ch| if ch.is_ascii_graphic() { ch } else { '?' }).collect();
    if clean.len() > MAX_KEY_PATH {
        format!("{}{CUT_MARK}", clean.chars().take(MAX_KEY_PATH).collect::<String>())
    } else {
        clean
    }
}


fn refuse(path: &str) -> ScanError {
    ScanError::BadRulesKey(key_path_text(path))
}


fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}


fn check_keys(prefix: &str, table: &Table, allowed: &[&str]) -> Result<(), ScanError> {
    table
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
        .map_or(Ok(()), |key| Err(refuse(&join(prefix, key))))
}


fn check_string_lists(prefix: &str, table: &Table) -> Result<(), ScanError> {
    STRING_LISTS.iter().try_for_each(|key| {
        let valid = table
            .get(*key)
            .is_none_or(|value| value.as_array().is_some_and(|items| items.iter().all(Value::is_str)));
        ensure(valid, refuse(&join(prefix, key)))
    })
}


fn table_named<'a>(name: String, value: &'a Value) -> Result<NamedTable<'a>, ScanError> {
    value
        .as_table()
        .map(|table| NamedTable { name: name.clone(), table })
        .ok_or_else(|| refuse(&name))
}


fn tables_of<'a>(path: &str, value: &'a Value) -> Result<Vec<NamedTable<'a>>, ScanError> {
    let items = value.as_array().ok_or_else(|| refuse(path))?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| table_named(format!("{path}[{i}]"), item))
        .collect()
}


fn allowlists_of<'a>(prefix: &str, owner: &'a Table) -> Result<Vec<NamedTable<'a>>, ScanError> {
    let single = owner
        .get("allowlist")
        .map(|value| table_named(join(prefix, "allowlist"), value))
        .transpose()?;
    let many = owner
        .get("allowlists")
        .map(|value| tables_of(&join(prefix, "allowlists"), value))
        .transpose()?;
    Ok(single.into_iter().chain(many.into_iter().flatten()).collect())
}


fn check_table(named: &NamedTable<'_>, allowed: &[&str]) -> Result<(), ScanError> {
    check_keys(&named.name, named.table, allowed)?;
    check_string_lists(&named.name, named.table)
}


/// Every `paths` regex of the allowlist tables, the file accepted only with exactly the documented keys and string lists.
pub fn allowlist_patterns(text: &str) -> Result<Vec<String>, ScanError> {
    let table: Table = text.parse().map_err(|_| ScanError::BadRules("not valid TOML"))?;
    check_keys("", &table, &TOP_KEYS)?;
    let rules: Vec<NamedTable<'_>> = table
        .get("rules")
        .map(|value| tables_of("rules", value))
        .transpose()?
        .into_iter()
        .flatten()
        .collect();
    rules.iter().try_for_each(|rule| check_table(rule, &RULE_KEYS))?;
    let global = allowlists_of("", &table)?;
    global.iter().try_for_each(|list| check_table(list, &GLOBAL_ALLOWLIST_KEYS))?;
    let found = rules
        .iter()
        .map(|rule| allowlists_of(&rule.name, rule.table))
        .collect::<Result<Vec<_>, ScanError>>()?;
    let per_rule: Vec<NamedTable<'_>> = found.into_iter().flatten().collect();
    per_rule.iter().try_for_each(|list| check_table(list, &RULE_ALLOWLIST_KEYS))?;
    Ok(global
        .iter()
        .chain(per_rule.iter())
        .filter_map(|list| list.table.get("paths").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
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


/// Refuses a work directory that is not ASCII or whose text differs from its cleaned form; returns the text.
pub fn check_normalised(work_dir: &Path) -> Result<&str, ScanError> {
    let work_text = work_dir.to_str().ok_or(ScanError::BadSettings("work directory is not UTF-8"))?;
    ensure(work_text.is_ascii(), ScanError::BadSettings("work directory is not ASCII"))?;
    let normalised = work_text.starts_with('/') && work_text.split('/').skip(1).all(|part| !part.is_empty() && part != "." && part != "..");
    ensure(normalised, ScanError::BadSettings("work directory is not a normalised absolute path"))?;
    Ok(work_text)
}


/// True when the pattern holds a non-ASCII character or a `\x`, `\u`, `\U`, `\p`, `\P` or `\N` escape (an escaped backslash is skipped).
pub fn is_wide_pattern(pattern: &str) -> bool {
    pattern
        .chars()
        .fold((false, false), |(escaped, wide), ch| {
            (!escaped && ch == '\\', wide || !ch.is_ascii() || (escaped && WIDE_ESCAPES.contains(&ch)))
        })
        .1
}


/// Compiles a pattern as Go does for the allowlist: bytes, ASCII classes (`\b`, `\w`, `\d`, `\s`), no Unicode, no escape above 0x7F.
pub fn compile_pattern(pattern: &str) -> Result<Regex, ScanError> {
    ensure(
        !is_wide_pattern(pattern),
        ScanError::BadRules("allowlist pattern is not ASCII or holds a Unicode escape"),
    )?;
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .map_err(|_| ScanError::BadRules("allowlist pattern does not compile"))
}


/// Refuses a private directory whose scan root, tree or a leaf an allowlist pattern would match: every finding would then be hidden.
pub fn check_probes(patterns: &[Regex], private: &Path) -> Result<(), ScanError> {
    let base = private.as_os_str().as_bytes();
    PROBE_TAILS.iter().try_for_each(|tail| {
        let probe = [base, tail.as_bytes()].concat();
        ensure(
            !patterns.iter().any(|pattern| pattern.is_match(&probe)),
            ScanError::BadSettings("work directory matches an allowlist path of the rules"),
        )
    })
}


/// Reads and checks the rules file once and returns its compiled allowlist, already probed with the placeholder private directory.
pub fn load_allowlist(rules: &Path, work_dir: &Path) -> Result<Vec<Regex>, ScanError> {
    let work_text = check_normalised(work_dir)?;
    let patterns = allowlist_patterns(&read_rules(rules)?)?
        .iter()
        .map(|pattern| compile_pattern(pattern))
        .collect::<Result<Vec<_>, ScanError>>()?;
    check_probes(&patterns, Path::new(&format!("{work_text}/{PROBE_DIR}")))?;
    Ok(patterns)
}

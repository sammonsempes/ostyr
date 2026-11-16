//! The strict grammar of the scanner rules file and its single checked read (Unix only).

use crate::copy::GROUP_OTHER_WRITE;
use crate::scan::{ensure, ScanError};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use toml::{Table, Value};


pub const MAX_RULES_BYTES: u64 = 1 << 20;


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


/// The parsed rules file, accepted only with exactly the documented keys and string lists.
pub fn checked_rules(text: &str) -> Result<Table, ScanError> {
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
    Ok(table)
}


/// Opens the rules without following a link, checks that handle (regular, owned by `expected_uid`, not group or other writable) and reads at most `MAX_RULES_BYTES` from it.
pub fn read_rules(rules: &Path, expected_uid: u32) -> Result<String, ScanError> {
    ensure(rules.is_absolute(), ScanError::BadRules("not absolute"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(rules)?;
    let metadata = file.metadata()?;
    ensure(metadata.is_file(), ScanError::BadRules("not a regular file"))?;
    ensure(metadata.uid() == expected_uid, ScanError::BadRules("not owned by the caller"))?;
    ensure(
        metadata.mode() & GROUP_OTHER_WRITE == 0,
        ScanError::BadRules("writable by group or others"),
    )?;
    let mut text = String::new();
    file.take(MAX_RULES_BYTES + 1).read_to_string(&mut text)?;
    ensure(text.len() as u64 <= MAX_RULES_BYTES, ScanError::BadRules("too large"))?;
    Ok(text)
}

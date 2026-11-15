//! Canary rule and canary files: gitleaks itself reports which directories the rules allowlist (Unix only).

use crate::copy::{display_path, write_file, CopySummary, Ctx};
use crate::model::{Limits, CANARY_RULE_ID};
use crate::scan::{ensure, ScanError};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;
use toml::{Table, Value};


pub const NAME_PREFIX: &str = "ostyr-canary-";


pub const CANARY_REGEX: &str = "ostyr-canary-[0-9a-f]{32}";


pub const NAME_RANDOM_BYTES: usize = 8;


pub const VALUE_RANDOM_BYTES: usize = 16;


pub const URANDOM: &str = "/dev/urandom";


pub const CONFIG_NAME: &str = "config.toml";


pub const MAX_HIDDEN_PATHS: usize = 100;


pub const REPORT_BYTES_PER_CANARY: usize = 1024;


/// The per-run canary: the file name written into every copied directory and the secret it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    pub name: String,
    pub value: String,
}


/// What the rules allowlist: the number of copied directories whose canary was not reported and the original paths of the first ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlisted {
    pub dirs: usize,
    pub paths: Vec<String>,
}


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


/// A canary built from `source`, a random byte source (production: `/dev/urandom`).
pub fn canary_from<Source: Read>(mut source: Source) -> Result<Canary, ScanError> {
    let mut name_bytes = [u8::default(); NAME_RANDOM_BYTES];
    let mut value_bytes = [u8::default(); VALUE_RANDOM_BYTES];
    source.read_exact(&mut name_bytes)?;
    source.read_exact(&mut value_bytes)?;
    Ok(Canary {
        name: format!("{NAME_PREFIX}{}", hex(&name_bytes)),
        value: format!("{NAME_PREFIX}{}", hex(&value_bytes)),
    })
}


/// A fresh canary from the kernel's random source.
pub fn new_canary() -> Result<Canary, ScanError> {
    canary_from(File::open(URANDOM)?)
}


/// The gitleaks configuration of one run: the operator's checked rules plus the canary rule.
pub fn config_text(rules: &Table) -> Result<String, ScanError> {
    let operator = rules.get("rules").and_then(Value::as_array).map_or_else(Vec::new, |found| found.clone());
    let reserved = operator.iter().any(|rule| rule.get("id").and_then(Value::as_str) == Some(CANARY_RULE_ID));
    ensure(!reserved, ScanError::BadRules("the rules file uses the reserved canary rule id"))?;
    let mut canary_rule = Table::new();
    canary_rule.insert("id".to_string(), Value::String(CANARY_RULE_ID.to_string()));
    canary_rule.insert("description".to_string(), Value::String("scan canary".to_string()));
    canary_rule.insert("regex".to_string(), Value::String(CANARY_REGEX.to_string()));
    let mut config = rules.clone();
    config.insert(
        "rules".to_string(),
        Value::Array(operator.into_iter().chain(std::iter::once(Value::Table(canary_rule))).collect()),
    );
    Ok(toml::to_string(&config)?)
}


/// Writes the canary file into a copied directory and counts it against the copy bounds; `rel` is the directory's original path below the scan root.
pub fn plant_canary(ctx: &Ctx, dst: &OwnedFd, rel: &Path, state: &mut CopySummary) -> Result<(), ScanError> {
    state.canary_total += 1;
    state.entries += 1;
    state.bytes = state.bytes.saturating_add(ctx.canary.value.len() as u64);
    ensure(state.entries <= ctx.limits.max_entries, ScanError::CopyLimit("entries"))?;
    ensure(state.bytes <= ctx.limits.max_bytes, ScanError::CopyLimit("bytes"))?;
    let kept = !rel.as_os_str().is_empty() && state.canary_dirs.len() < MAX_HIDDEN_PATHS;
    state.canary_dirs.extend(kept.then(|| rel.to_path_buf()));
    write_file(dst, &ctx.canary.name, ctx.canary.value.as_bytes())
}


/// The report limits widened by one finding and its bytes per canary file.
pub fn widened_limits(limits: &Limits, canary_files: usize) -> Limits {
    Limits {
        max_findings: limits.max_findings.saturating_add(canary_files),
        max_bytes: limits.max_bytes.saturating_add(canary_files.saturating_mul(REPORT_BYTES_PER_CANARY)),
        ..*limits
    }
}


fn canary_shown(root: &Path, dir: &Path, canary: &Canary) -> String {
    display_path(&root.join(dir).join(&canary.name))
}


/// `BlindScan` when the root canary was not reported; otherwise the directories whose canary was not reported (`seen` holds the shown paths).
pub fn check_canaries(canary: &Canary, summary: &CopySummary, root: &Path, seen: &HashSet<String>) -> Result<Allowlisted, ScanError> {
    ensure(seen.contains(&canary_shown(root, Path::new(""), canary)), ScanError::BlindScan)?;
    let paths: Vec<String> = summary
        .canary_dirs
        .iter()
        .filter(|dir| !seen.contains(&canary_shown(root, dir, canary)))
        .map(|dir| display_path(&root.join(dir)))
        .collect();
    Ok(Allowlisted {
        dirs: summary.canary_total.saturating_sub(seen.len()),
        paths,
    })
}

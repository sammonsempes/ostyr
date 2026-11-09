use crate::policy::{compile, LoadedPolicy, Policy, PolicyError};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_file, ROOT_FIELD_PATH};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use serde::de::Error as _;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};


/// The reload engine reports only `ConfigError`: a typed policy error travels as its message.
pub fn refusal(file: &str, error: &PolicyError) -> ConfigError {
    ConfigError::Parse {
        file: file.to_owned(),
        line: 0,
        column: 0,
        field_path: ROOT_FIELD_PATH.to_owned(),
        message: error.to_string(),
        source: Box::new(serde_saphyr::Error::custom(error.to_string())),
    }
}


/// One read: the text that is parsed is the text that is hashed.
pub fn load_policy(path: &Path) -> Result<LoadedPolicy, ConfigError> {
    let name = path.display().to_string();
    let text = read_file(path)?;
    let policy: Policy = parse_document(&text, &name)?;
    let hash = salted_digest(&text);
    compile(policy, hash).map_err(|error| refusal(&name, &error))
}


pub fn policy_loader(path: PathBuf) -> Box<LoaderFn<LoadedPolicy>> {
    Box::new(move || load_policy(&path))
}


pub fn joined(values: &[String]) -> String {
    values.join(", ")
}


pub const LIST_SALT: &str = "ostyr-policy-validator-list-v1";


/// Salted SHA-256 of a whole text: equal texts give equal digests, and a guessed policy cannot be confirmed without the salt.
pub fn salted_digest(text: &str) -> String {
    format!("{:x}", Sha256::new().chain_update(LIST_SALT).chain_update(text).finalize())
}


/// Count and salted digest of a list: the diff shows that it changed, never the entries.
pub fn list_summary(values: &[String]) -> String {
    let digest = values
        .iter()
        .fold(Sha256::new().chain_update(LIST_SALT), |state, value| {
            state.chain_update(value.len().to_string()).chain_update(":").chain_update(value)
        })
        .finalize();
    format!("count={} sha256-salted={digest:x}", values.len())
}


/// Count and whether the list differs from the built-in default: no entry and no digest, a digest of a short list can be confirmed by guessing.
pub fn sensitive_summary(values: &[String], default: &[String]) -> String {
    format!("count={} changed={}", values.len(), values != default)
}


/// One key per setting, so a reload diff names what changed.
pub fn policy_state(loaded: &LoadedPolicy) -> ConfigState {
    let policy = &loaded.policy;
    let default = Policy::default();
    let rules: Vec<String> = policy.critical_asr_rules.iter().map(ToString::to_string).collect();
    [
        ("config_hash", loaded.hash.clone()),
        ("min_benign_verdicts", policy.min_benign_verdicts.to_string()),
        ("min_distinct_days", policy.min_distinct_days.to_string()),
        ("max_lifetime_days", policy.max_lifetime_days.to_string()),
        ("interpreters", joined(&policy.interpreters)),
        ("user_writable_prefixes", joined(&policy.user_writable_prefixes)),
        ("user_writable_segments", joined(&policy.user_writable_segments)),
        ("honeytoken_paths", sensitive_summary(&policy.honeytoken_paths, &default.honeytoken_paths)),
        ("agent_paths", sensitive_summary(&policy.agent_paths, &default.agent_paths)),
        ("critical_asr_rules", joined(&rules)),
        ("os_directories", list_summary(&policy.os_directories)),
        ("security_sensors", sensitive_summary(&policy.security_sensors, &default.security_sensors)),
        ("service_tools", list_summary(&policy.service_tools)),
        ("os_vendor_signers", list_summary(&policy.os_vendor_signers)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn open_validator(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<LoadedPolicy>, ConfigError> {
    open_engine(policy_loader(path), policy_state, Vec::new(), audit, context)
}

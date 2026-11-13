use crate::error::PolicyError;
use cmdb::model::Criticality;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_POLICY_BYTES: u64 = 65_536;


pub const DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 900;


pub const CEILING_IDLE_TIMEOUT_SECONDS: u64 = 3600;


pub const DEFAULT_MAX_DURATION_SECONDS: u64 = 14_400;


pub const CEILING_MAX_DURATION_SECONDS: u64 = 43_200;


pub const DEFAULT_MFA_MAX_AGE_SECONDS: u64 = 120;


pub const CEILING_MFA_MAX_AGE_SECONDS: u64 = 300;


pub const DEFAULT_APPROVAL_MAX_AGE_SECONDS: u64 = 900;


pub const CEILING_APPROVAL_MAX_AGE_SECONDS: u64 = 3600;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellPolicy {
    pub idle_timeout_seconds: u64,
    pub max_duration_seconds: u64,
    pub mfa_max_age_seconds: u64,
    pub approval_max_age_seconds: u64,
    pub dual_approval_from: Criticality,
}


impl Default for ShellPolicy {
    fn default() -> Self {
        ShellPolicy {
            idle_timeout_seconds: DEFAULT_IDLE_TIMEOUT_SECONDS,
            max_duration_seconds: DEFAULT_MAX_DURATION_SECONDS,
            mfa_max_age_seconds: DEFAULT_MFA_MAX_AGE_SECONDS,
            approval_max_age_seconds: DEFAULT_APPROVAL_MAX_AGE_SECONDS,
            dual_approval_from: Criticality::Critical,
        }
    }
}


/// Reads at most `MAX_POLICY_BYTES` from `reader`, parses strictly and checks every duration against its ceiling; `file` only labels errors.
pub fn parse_policy(reader: &mut dyn Read, file: &str) -> Result<ShellPolicy, PolicyError> {
    let text = read_text_capped(reader, file, MAX_POLICY_BYTES)?;
    let policy = parse_document::<ShellPolicy>(&text, file)?;
    validate_policy(&policy, file)?;
    Ok(policy)
}


pub fn load_policy(path: &Path) -> Result<ShellPolicy, PolicyError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_policy(&mut handle, &file)
}


pub fn validate_policy(policy: &ShellPolicy, file: &str) -> Result<(), PolicyError> {
    let checks = [
        ("idle_timeout_seconds", policy.idle_timeout_seconds, CEILING_IDLE_TIMEOUT_SECONDS),
        ("max_duration_seconds", policy.max_duration_seconds, CEILING_MAX_DURATION_SECONDS),
        ("mfa_max_age_seconds", policy.mfa_max_age_seconds, CEILING_MFA_MAX_AGE_SECONDS),
        (
            "approval_max_age_seconds",
            policy.approval_max_age_seconds,
            CEILING_APPROVAL_MAX_AGE_SECONDS,
        ),
    ];
    checks
        .iter()
        .find(|(_, value, ceiling)| !(1..=*ceiling).contains(value))
        .map_or(Ok(()), |(field, _, _)| {
            Err(PolicyError::Invalid {
                file: file.to_string(),
                field,
            })
        })
}

use crate::error::PolicyError;
use crate::limits::{MAX_POLICY_BYTES, MAX_RULES};
use crate::model::Policy;
use core_config::parse::{parse_document, read_text_capped};
use std::fs::File;
use std::io::Read;
use std::path::Path;


/// Reads at most `MAX_POLICY_BYTES`, parses strictly and refuses more than `MAX_RULES` rules and exceptions together.
pub fn parse_policy(reader: &mut dyn Read, file: &str) -> Result<Policy, PolicyError> {
    let text = read_text_capped(reader, file, MAX_POLICY_BYTES)?;
    let policy: Policy = parse_document(&text, file)?;
    let count = policy.rules.len() + policy.exceptions.len();
    if count > MAX_RULES {
        Err(PolicyError::TooManyRules {
            file: file.to_string(),
            count,
        })
    } else {
        Ok(policy)
    }
}


pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| PolicyError::Open { path: file.clone(), source })?;
    parse_policy(&mut handle, &file)
}

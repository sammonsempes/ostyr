use crate::error::{redacted, CorrelationError};
use crate::ruleset::{fingerprint, parse_ruleset, RuleSet};
use crate::types::RuleTexts;
use core_config::error::ConfigError;
use core_config::parse::{read_file, ROOT_FIELD_PATH};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use serde::de::Error as _;
use sigma_sql::mapping::parse_mapping;
use std::path::{Path, PathBuf};


/// The reload engine reports only `ConfigError`: a typed rule error travels as its message, in the `Parse` variant, with the file name.
pub fn refusal(file: &str, error: &CorrelationError) -> ConfigError {
    ConfigError::Parse {
        file: file.to_string(),
        line: 0,
        column: 0,
        field_path: ROOT_FIELD_PATH.to_string(),
        message: error.to_string(),
        source: Box::new(serde_saphyr::Error::custom(error.to_string())),
    }
}


pub fn read_texts(files: &[PathBuf]) -> Result<RuleTexts, ConfigError> {
    files
        .iter()
        .map(|file| read_file(file).map(|text| (file.display().to_string(), text)))
        .collect()
}


pub fn load_rules(mapping_file: &Path, rule_files: &[PathBuf]) -> Result<RuleSet, ConfigError> {
    let mapping_name = mapping_file.display().to_string();
    let mapping = parse_mapping(&read_file(mapping_file)?).map_err(|error| refusal(&mapping_name, &redacted(error)))?;
    let texts = read_texts(rule_files)?;
    parse_ruleset(&texts, &mapping).map_err(|error| refusal(&mapping_name, &error))
}


/// Reads the mapping file and every rule file again on each reload, so a change to either one is picked up.
pub fn rules_loader(mapping_file: PathBuf, rule_files: Vec<PathBuf>) -> Box<LoaderFn<RuleSet>> {
    Box::new(move || load_rules(&mapping_file, &rule_files))
}


/// Keys base rules by title and content hash (a changed base is a delete plus a create) and correlation rules by id, so a reload diff names what changed.
pub fn rules_state(rules: &RuleSet) -> ConfigState {
    let bases = rules
        .bases
        .iter()
        .map(|base| (format!("base.{}.{}", base.title, fingerprint(&base.source, &[])), base.source.clone()));
    let correlations = rules
        .correlations
        .iter()
        .map(|rule| (format!("correlation.{}", rule.id), rule.source.clone()));
    bases.chain(correlations).collect()
}


pub fn open_rules(
    mapping_file: PathBuf,
    rule_files: Vec<PathBuf>,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<RuleSet>, ConfigError> {
    open_engine(rules_loader(mapping_file, rule_files), rules_state, Vec::new(), audit, context)
}

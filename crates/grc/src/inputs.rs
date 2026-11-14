use crate::error::GrcError;
use crate::load::{is_identifier, is_owner, is_printable_text, MAX_ID_CHARS, MAX_INDICATOR_CHARS, MAX_TITLE_CHARS};
use crate::model::{IndicatorValue, ManualEvidence};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_INPUT_BYTES: u64 = 4_194_304;


pub const MAX_INDICATORS: usize = 10_000;


pub const MAX_MANUAL: usize = 2_000;


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualFile {
    pub evidence: Vec<ManualEvidence>,
}


fn invalid(file: &str, reason: &str) -> GrcError {
    GrcError::Invalid {
        file: file.to_owned(),
        reason: reason.to_owned(),
    }
}


/// A JSON array of indicator values; a number out of the `f64` range (`1e309`) is a parse error.
pub fn parse_indicators(reader: &mut dyn Read, file: &str) -> Result<Vec<IndicatorValue>, GrcError> {
    let text = read_text_capped(reader, file, MAX_INPUT_BYTES)?;
    let values: Vec<IndicatorValue> = serde_json::from_str(&text).map_err(|error| GrcError::Json {
        file: file.to_owned(),
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    })?;
    if values.len() > MAX_INDICATORS {
        Err(invalid(file, "too many indicator values"))
    } else if !values
        .iter()
        .all(|value| is_identifier(&value.name, MAX_INDICATOR_CHARS) && is_printable_text(&value.source, MAX_TITLE_CHARS))
    {
        Err(invalid(file, "an indicator has an invalid name or source"))
    } else {
        Ok(values)
    }
}


/// A YAML document `evidence: [...]` of manual evidence records.
pub fn parse_manual(reader: &mut dyn Read, file: &str) -> Result<Vec<ManualEvidence>, GrcError> {
    let text = read_text_capped(reader, file, MAX_INPUT_BYTES)?;
    let parsed: ManualFile = parse_document(&text, file)?;
    if parsed.evidence.len() > MAX_MANUAL {
        Err(invalid(file, "too many manual evidence records"))
    } else if !parsed
        .evidence
        .iter()
        .all(|record| is_identifier(&record.control, MAX_ID_CHARS) && is_owner(&record.owner))
    {
        Err(invalid(file, "a manual evidence record has an invalid control or owner"))
    } else {
        Ok(parsed.evidence)
    }
}


fn open_file(path: &Path) -> Result<(File, String), GrcError> {
    let file = path.display().to_string();
    File::open(path)
        .map(|handle| (handle, file.clone()))
        .map_err(|source| GrcError::Config(ConfigError::Io { file, source }))
}


pub fn load_indicators(path: &Path) -> Result<Vec<IndicatorValue>, GrcError> {
    open_file(path).and_then(|(mut handle, file)| parse_indicators(&mut handle, &file))
}


pub fn load_manual(path: &Path) -> Result<Vec<ManualEvidence>, GrcError> {
    open_file(path).and_then(|(mut handle, file)| parse_manual(&mut handle, &file))
}

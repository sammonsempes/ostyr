use crate::error::ConfigError;
use serde::de::{DeserializeOwned, Error as _};
use serde_path_to_error::Path as FieldPath;
use serde_saphyr::{Error as YamlError, Location};
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const ROOT_FIELD_PATH: &str = ".";


pub fn read_text(reader: &mut dyn Read, file: &str) -> Result<String, ConfigError> {
    let mut text = String::new();
    reader.read_to_string(&mut text).map_err(|source| ConfigError::Io {
        file: file.to_string(),
        source,
    })?;
    Ok(text)
}


pub fn read_file(path: &Path) -> Result<String, ConfigError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    read_text(&mut handle, &file)
}


/// Line and column of a parser location, `(0, 0)` when the parser gave none.
pub fn position_of(location: Option<Location>) -> (u64, u64) {
    location.map_or((0, 0), |known| (known.line(), known.column()))
}


/// Names a schema list such as the expected fields; the schema is code, not document content.
fn expected_list(expected: &[&str]) -> String {
    expected.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ")
}


/// The error text with every key, value, tag and name taken from the document removed.
pub fn describe_error(error: &YamlError) -> String {
    match error {
        YamlError::SerdeUnknownField { expected, .. } => format!("unknown field, expected one of {}", expected_list(expected)),
        YamlError::SerdeUnknownVariant { expected, .. } => format!("unknown variant, expected one of {}", expected_list(expected)),
        YamlError::SerdeInvalidType { expected, .. } => format!("invalid type, expected {expected}"),
        YamlError::SerdeInvalidValue { expected, .. } => format!("invalid value, expected {expected}"),
        YamlError::DuplicateMappingKey { .. } => "duplicate mapping key".to_string(),
        YamlError::TaggedEnumMismatch { target, .. } => format!("tag does not match {target}"),
        YamlError::SerdeVariantId { .. } => "invalid variant identifier".to_string(),
        YamlError::NonFiniteFloat { .. } => "non-finite float".to_string(),
        YamlError::QuotingRequired { .. } => "value requires quotes".to_string(),
        other => other.to_string(),
    }
}


/// The field path with the offending key removed for an unknown field, since that key comes from the document.
pub fn describe_path(path: &FieldPath, unknown_field: bool) -> String {
    let full = path.to_string();
    let last = path.iter().next_back().map_or(String::new(), ToString::to_string);
    let parent = full.strip_suffix(last.as_str()).unwrap_or(full.as_str()).trim_end_matches('.');
    match (unknown_field, parent.is_empty()) {
        (false, _) => full,
        (true, true) => ROOT_FIELD_PATH.to_string(),
        (true, false) => parent.to_string(),
    }
}


/// Parses `text` strictly; `file` only labels errors, which carry line, column and field path but never text taken from the document.
pub fn parse_document<Document: DeserializeOwned>(text: &str, file: &str) -> Result<Document, ConfigError> {
    let options = serde_saphyr::options! { with_snippet: false };
    let mut field_path = ROOT_FIELD_PATH.to_string();
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options, |deserializer| {
        serde_path_to_error::deserialize::<_, Document>(deserializer).map_err(|error| {
            field_path = describe_path(error.path(), matches!(error.inner(), YamlError::SerdeUnknownField { .. }));
            error.into_inner()
        })
    });
    result.map_err(|source| {
        let (line, column) = position_of(source.location());
        let message = describe_error(&source);
        ConfigError::Parse {
            file: file.to_string(),
            line,
            column,
            field_path: field_path.clone(),
            message: message.clone(),
            source: Box::new(YamlError::custom(message)),
        }
    })
}

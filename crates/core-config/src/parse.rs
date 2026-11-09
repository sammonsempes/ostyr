use crate::error::ConfigError;
use serde::de::{DeserializeOwned, Error as _};
use serde_path_to_error::{Path as FieldPath, Segment};
use serde_saphyr::{Error as YamlError, ExternalMessageSource, Location};
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const ROOT_FIELD_PATH: &str = ".";


pub const MAX_FILE_BYTES: u64 = 8_388_608;


/// Reads at most `max` bytes; one byte more is refused with `ConfigError::TooLarge` naming the file.
pub fn read_text_capped(reader: &mut dyn Read, file: &str, max: u64) -> Result<String, ConfigError> {
    let mut bytes = Vec::new();
    Read::take(reader, max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Io {
            file: file.to_string(),
            source,
        })?;
    if bytes.len() as u64 > max {
        Err(ConfigError::TooLarge { file: file.to_string(), max })
    } else {
        String::from_utf8(bytes).map_err(|source| ConfigError::Io {
            file: file.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })
    }
}


pub fn read_text(reader: &mut dyn Read, file: &str) -> Result<String, ConfigError> {
    read_text_capped(reader, file, MAX_FILE_BYTES)
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


/// The error behind any alias replay or snippet wrapper, which carry document text of their own.
pub fn root_cause(error: &YamlError) -> &YamlError {
    std::iter::successors(Some(error), |current| match current {
        YamlError::AliasError { error: inner, .. } | YamlError::WithSnippet { error: inner, .. } => Some(inner.as_ref()),
        _ => None,
    })
    .last()
    .unwrap_or(error)
}


/// The error class with every key, value, tag and name taken from the document removed; unlisted variants get a fixed class.
pub fn describe_error(error: &YamlError) -> String {
    match root_cause(error) {
        YamlError::SerdeUnknownField { expected, .. } => format!("unknown field, expected one of {}", expected_list(expected)),
        YamlError::SerdeUnknownVariant { expected, .. } => format!("unknown variant, expected one of {}", expected_list(expected)),
        YamlError::SerdeInvalidType { expected, .. } => format!("invalid type, expected {expected}"),
        YamlError::SerdeInvalidValue { expected, .. } => format!("invalid value, expected {expected}"),
        YamlError::DuplicateMappingKey { .. } => "duplicate mapping key".to_string(),
        YamlError::TaggedEnumMismatch { target, .. } => format!("tag does not match {target}"),
        YamlError::SerdeVariantId { .. } => "invalid variant identifier".to_string(),
        YamlError::NonFiniteFloat { .. } => "non-finite float".to_string(),
        YamlError::QuotingRequired { .. } => "value requires quotes".to_string(),
        YamlError::Message { msg, .. } => bounded_message(&strip_serde_names(msg)),
        YamlError::InvalidScalar { ty, .. } => format!("invalid {ty}"),
        YamlError::ExternalMessage { source, .. } if matches!(source.as_ref(), ExternalMessageSource::Parser(_)) => "YAML syntax error".to_string(),
        YamlError::ExternalMessage { .. } | YamlError::HookError { .. } => "validation hook error".to_string(),
        YamlError::CyclicInclude { .. } | YamlError::ResolverError { .. } | YamlError::UnsupportedIncludeForm { .. } => "include error".to_string(),
        YamlError::UnresolvedProperty { .. }
        | YamlError::InvalidPropertyName { .. }
        | YamlError::PropertyRequiredButUnset { .. }
        | YamlError::PropertyRequiredButEmpty { .. } => "property error".to_string(),
        YamlError::UnsupportedTag { .. } => "unsupported tag".to_string(),
        known @ (YamlError::Eof { .. }
        | YamlError::MultipleDocuments { .. }
        | YamlError::Unexpected { .. }
        | YamlError::UnexpectedSequenceEnd { .. }
        | YamlError::UnexpectedMappingEnd { .. }
        | YamlError::SerdeMissingField { .. }
        | YamlError::SerdeInvalidLength { .. }
        | YamlError::UnknownAnchor { .. }) => known.to_string(),
        _ => "invalid document".to_string(),
    }
}


/// Maximum bytes of a mapping key shown in a field path.
pub const MAX_KEY_BYTES: usize = 64;


/// Maximum characters of a validation message kept in an error.
pub const MAX_MESSAGE_CHARS: usize = 256;


/// A key shaped like a schema identifier (`[a-z][a-z0-9_]*`) is shown, any other text from the document is `<key>`.
pub fn shown_key(key: &str) -> String {
    let mut chars = key.chars();
    let identifier = key.len() <= MAX_KEY_BYTES
        && chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '_');
    if identifier {
        key.to_string()
    } else {
        "<key>".to_string()
    }
}


/// Serde prefixes whose message embeds a name taken from the document, as in a flattened struct.
const NAMING_PREFIXES: [&str; 3] = ["unknown field `", "unknown variant `", "duplicate field `"];


/// Cuts the document name out of a message serde built itself; other messages pass unchanged.
pub fn strip_serde_names(message: &str) -> String {
    NAMING_PREFIXES
        .iter()
        .find(|prefix| message.starts_with(**prefix))
        .map_or_else(|| message.to_string(), |prefix| prefix.trim_end_matches(" `").to_string())
}


/// A validation message bounded to `MAX_MESSAGE_CHARS` characters with control characters escaped.
pub fn bounded_message(message: &str) -> String {
    message
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .flat_map(|character| character.escape_default().collect::<Vec<_>>())
        .collect()
}


/// The field path with identifier-shaped keys kept, other keys shown as `<key>` and the offending key of an unknown field removed.
pub fn describe_path(path: &FieldPath, unknown_field: bool) -> String {
    let keep = path.iter().count().saturating_sub(usize::from(unknown_field));
    let described = path.iter().take(keep).fold(String::new(), |mut text, segment| {
        match segment {
            Segment::Seq { index } => text.push_str(&format!("[{index}]")),
            other => {
                let name = match other {
                    Segment::Map { key } => shown_key(key),
                    Segment::Enum { variant } => shown_key(variant),
                    _ => "<key>".to_string(),
                };
                text.push_str(&if text.is_empty() { name } else { format!(".{name}") });
            }
        }
        text
    });
    if described.is_empty() {
        ROOT_FIELD_PATH.to_string()
    } else {
        described
    }
}


/// Parses `text` strictly; `file` only labels errors, which carry line, column and field path but never text taken from the document.
pub fn parse_document<Document: DeserializeOwned>(text: &str, file: &str) -> Result<Document, ConfigError> {
    let options = serde_saphyr::options! { with_snippet: false };
    let mut field_path = ROOT_FIELD_PATH.to_string();
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options, |deserializer| {
        serde_path_to_error::deserialize::<_, Document>(deserializer).map_err(|error| {
            field_path = describe_path(error.path(), matches!(root_cause(error.inner()), YamlError::SerdeUnknownField { .. }));
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

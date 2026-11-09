use crate::error::ScriptError;
use crate::model::{
    Manifest, ParamKind, MAX_ENUM_VALUES, MAX_NAME_LENGTH, MAX_OUTPUT_BYTES, MAX_PARAMETERS, MAX_PATH_LENGTH, MAX_PREFIXES, MAX_STRING_LENGTH,
    MAX_TIMEOUT_SECONDS, SHA256_HEX_LENGTH,
};
use crate::path::{absolute_components, is_separator};
use crate::pattern::compile_pattern;


pub fn ensure(condition: bool, error: ScriptError) -> Result<(), ScriptError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}


fn invalid(field: &str) -> ScriptError {
    ScriptError::InvalidManifest { field: field.to_string() }
}


pub fn is_identifier(text: &str) -> bool {
    text.chars().next().is_some_and(|first| first.is_ascii_lowercase())
        && text.len() <= MAX_NAME_LENGTH
        && text.chars().all(|character| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-'))
}


/// Relative to the library root: no root, no `..`, no backslash, no control character, never starts with `-`.
pub fn is_library_path(script: &str) -> bool {
    !script.is_empty()
        && script.len() <= MAX_PATH_LENGTH
        && !script.starts_with(is_separator)
        && !script.starts_with('-')
        && !script.contains('\\')
        && !script.chars().any(char::is_control)
        && !script.split('/').any(|part| part.is_empty() || part == "." || part == "..")
}


pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == SHA256_HEX_LENGTH && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}


fn is_plain(text: &str) -> bool {
    text.len() <= MAX_STRING_LENGTH && !text.contains('\0')
}


fn check_kind(name: &str, kind: &ParamKind) -> Result<(), ScriptError> {
    let field = format!("parameters.{name}");
    match kind {
        ParamKind::Text {
            min_length,
            max_length,
            pattern,
        } => {
            ensure(min_length <= max_length, invalid(&field))?;
            ensure(*max_length <= MAX_STRING_LENGTH, invalid(&field))?;
            pattern.as_ref().map_or(Ok(()), |text| compile_pattern(text).map(drop))
        }
        ParamKind::Integer { min, max } => ensure(min <= max, invalid(&field)),
        ParamKind::Enumeration { values } => {
            ensure(!values.is_empty(), invalid(&field))?;
            ensure(values.len() <= MAX_ENUM_VALUES, invalid(&field))?;
            ensure(values.iter().all(|value| is_plain(value)), invalid(&field))
        }
        ParamKind::Path { allowed_prefixes } => {
            ensure(!allowed_prefixes.is_empty(), invalid(&field))?;
            ensure(allowed_prefixes.len() <= MAX_PREFIXES, invalid(&field))?;
            ensure(
                allowed_prefixes.iter().all(|prefix| absolute_components(prefix).is_some()),
                invalid(&field),
            )
        }
    }
}


/// Bounds every field of a parsed manifest.
pub fn check_manifest(manifest: &Manifest) -> Result<(), ScriptError> {
    ensure(is_identifier(&manifest.name), invalid("name"))?;
    ensure(is_library_path(&manifest.script), invalid("script"))?;
    ensure(is_sha256_hex(&manifest.sha256), invalid("sha256"))?;
    ensure((1..=MAX_TIMEOUT_SECONDS).contains(&manifest.timeout_seconds), invalid("timeout_seconds"))?;
    ensure((1..=MAX_OUTPUT_BYTES).contains(&manifest.max_output_bytes), invalid("max_output_bytes"))?;
    ensure(manifest.parameters.len() <= MAX_PARAMETERS, invalid("parameters"))?;
    manifest.parameters.iter().try_for_each(|(name, kind)| {
        ensure(is_identifier(name), invalid("parameters"))?;
        check_kind(name, kind)
    })
}

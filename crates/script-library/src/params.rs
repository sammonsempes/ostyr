use crate::check::ensure;
use crate::error::ScriptError;
use crate::model::{Manifest, ParamKind, ParamValue};
use crate::path::{absolute_components, is_under_prefixes};
use crate::pattern::compile_pattern;
use crate::types::Params;


fn check_text(name: &str, text: &str, min_length: usize, max_length: usize, pattern: &Option<String>) -> Result<(), ScriptError> {
    ensure(text.len() >= min_length, ScriptError::TooShort(name.to_string()))?;
    ensure(text.len() <= max_length, ScriptError::TooLong(name.to_string()))?;
    ensure(!text.contains('\0'), ScriptError::NulByte(name.to_string()))?;
    pattern.as_ref().map_or(Ok(()), |source| {
        ensure(compile_pattern(source)?.is_match(text), ScriptError::PatternMismatch(name.to_string()))
    })
}


fn check_path(name: &str, text: &str, prefixes: &[String]) -> Result<(), ScriptError> {
    ensure(absolute_components(text).is_some(), ScriptError::MalformedPath(name.to_string()))?;
    ensure(is_under_prefixes(text, prefixes), ScriptError::PathOutsidePrefixes(name.to_string()))
}


fn check_value(name: &str, kind: &ParamKind, value: &ParamValue) -> Result<(), ScriptError> {
    match (kind, value) {
        (
            ParamKind::Text {
                min_length,
                max_length,
                pattern,
            },
            ParamValue::Text(text),
        ) => check_text(name, text, *min_length, *max_length, pattern),
        (ParamKind::Integer { min, max }, ParamValue::Integer(number)) => {
            ensure((*min..=*max).contains(number), ScriptError::OutOfRange(name.to_string()))
        }
        (ParamKind::Enumeration { values }, ParamValue::Text(text)) => ensure(values.contains(text), ScriptError::NotAllowed(name.to_string())),
        (ParamKind::Path { allowed_prefixes }, ParamValue::Text(text)) => check_path(name, text, allowed_prefixes),
        _ => Err(ScriptError::WrongType(name.to_string())),
    }
}


/// Every declared parameter must be present and valid, and nothing else may be given.
pub fn validate_params(manifest: &Manifest, params: &Params) -> Result<(), ScriptError> {
    manifest.parameters.iter().try_for_each(|(name, kind)| {
        let value = params.get(name).ok_or_else(|| ScriptError::MissingParameter(name.clone()))?;
        check_value(name, kind, value)
    })?;
    ensure(params.len() == manifest.parameters.len(), ScriptError::UnknownParameter)
}

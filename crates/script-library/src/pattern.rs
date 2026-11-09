use crate::check::ensure;
use crate::error::ScriptError;
use crate::model::{MAX_PATTERN_LENGTH, PATTERN_SIZE_LIMIT};
use regex::{bytes, Regex, RegexBuilder};


fn build(pattern: &str) -> Result<Regex, ScriptError> {
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map_err(ScriptError::Pattern)
}


/// The regex matches the whole value; the bare pattern is compiled first so an unbalanced `)` cannot escape the anchoring group.
pub fn compile_pattern(pattern: &str) -> Result<Regex, ScriptError> {
    ensure(
        pattern.len() <= MAX_PATTERN_LENGTH,
        ScriptError::InvalidManifest {
            field: "pattern".to_string(),
        },
    )?;
    build(pattern)?;
    build(&format!(r"\A(?:{pattern})\z"))
}


/// Every pattern of a manifest, compiled; the first refusal wins.
pub fn compile_secret_patterns(patterns: &[String]) -> Result<Vec<bytes::Regex>, ScriptError> {
    patterns.iter().map(|pattern| compile_secret_pattern(pattern)).collect()
}


/// A secret pattern follows the parameter rules (length, size limit, bare pattern compiled first) and must not match the empty text.
pub fn compile_secret_pattern(pattern: &str) -> Result<bytes::Regex, ScriptError> {
    compile_pattern(pattern)?;
    let regex = bytes::RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map_err(ScriptError::Pattern)?;
    ensure(
        !regex.is_match(b""),
        ScriptError::InvalidManifest {
            field: "secret_patterns".to_string(),
        },
    )?;
    Ok(regex)
}

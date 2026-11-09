use crate::check::ensure;
use crate::error::ScriptError;
use crate::model::{MAX_PATTERN_LENGTH, PATTERN_SIZE_LIMIT, REDACTION_SLACK_BYTES};
use regex::{bytes, Regex, RegexBuilder};
use regex_syntax::ParserBuilder;


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


/// The longest match of a secret pattern in bytes, `None` when unbounded.
pub fn maximum_match_bytes(pattern: &str) -> Result<Option<usize>, ScriptError> {
    let hir = ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|error| ScriptError::Pattern(regex::Error::Syntax(error.to_string())))?;
    Ok(hir.properties().maximum_len())
}


/// A secret match must be bounded and fit the redaction slack, so a secret straddling the output cap is never cut.
pub fn ensure_match_bounded(maximum: Option<usize>, limit: u64) -> Result<(), ScriptError> {
    ensure(
        maximum.is_some_and(|length| u64::try_from(length).is_ok_and(|bytes| bytes <= limit)),
        ScriptError::InvalidManifest {
            field: "secret_patterns".to_string(),
        },
    )
}


/// A secret pattern: the parameter rules, no empty match, a bounded maximum match length of at most `REDACTION_SLACK_BYTES`.
pub fn compile_secret_pattern(pattern: &str) -> Result<bytes::Regex, ScriptError> {
    compile_pattern(pattern)?;
    ensure_match_bounded(maximum_match_bytes(pattern)?, REDACTION_SLACK_BYTES)?;
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

use crate::check::ensure;
use crate::error::ScriptError;
use crate::model::{MAX_PATTERN_LENGTH, PATTERN_SIZE_LIMIT};
use regex::{Regex, RegexBuilder};


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

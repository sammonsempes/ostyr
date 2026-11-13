use crate::error::SchemaError;


/// Longest accepted identifier in bytes, the ClickHouse limit for table and database names (file name limit).
pub const MAX_IDENTIFIER_BYTES: usize = 255;


/// Characters of a refused name kept in the error.
pub const ERROR_PREFIX_CHARS: usize = 64;


fn is_allowed(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '_' | '.' | '@')
}


/// Keeps a bounded prefix of a refused name and states how many bytes were cut.
pub fn bound_refused_name(name: &str) -> String {
    let prefix: String = name.chars().take(ERROR_PREFIX_CHARS).collect();
    let omitted = name.len() - prefix.len();
    if omitted == 0 {
        prefix
    } else {
        format!("{prefix}… [{omitted} bytes omitted]")
    }
}


/// Checks a name against `^[a-z0-9_.@]{1,255}$` and returns it unchanged.
pub fn validate_identifier(name: &str) -> Result<&str, SchemaError> {
    let valid = !name.is_empty() && name.len() <= MAX_IDENTIFIER_BYTES && name.chars().all(is_allowed);
    if valid {
        Ok(name)
    } else {
        Err(SchemaError::InvalidIdentifier(bound_refused_name(name)))
    }
}


/// Validates a name and wraps it in backticks.
pub fn quote_identifier(name: &str) -> Result<String, SchemaError> {
    validate_identifier(name).map(|valid| format!("`{valid}`"))
}

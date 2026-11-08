use crate::error::SchemaError;


fn is_allowed(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '_' | '.' | '@')
}


/// Checks a name against `^[a-z0-9_.@]+$` and returns it unchanged.
pub fn validate_identifier(name: &str) -> Result<&str, SchemaError> {
    let valid = !name.is_empty() && name.chars().all(is_allowed);
    if valid {
        Ok(name)
    } else {
        Err(SchemaError::InvalidIdentifier(name.to_string()))
    }
}


/// Validates a name and wraps it in backticks.
pub fn quote_identifier(name: &str) -> Result<String, SchemaError> {
    validate_identifier(name).map(|valid| format!("`{valid}`"))
}

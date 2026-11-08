use crate::error::SigmaError;


fn escape_char(character: char) -> String {
    match character {
        '\\' => "\\\\".to_string(),
        '\'' => "\\'".to_string(),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        '\0' => "\\0".to_string(),
        other => other.to_string(),
    }
}


/// Renders text as a ClickHouse string literal that no content can close early.
pub fn sql_literal(text: &str) -> String {
    let body: String = text.chars().map(escape_char).collect();
    format!("'{body}'")
}


/// Escapes one character so that it matches itself inside a `LIKE` pattern (before literal escaping).
pub fn like_escape(character: char) -> String {
    match character {
        '\\' | '%' | '_' => format!("\\{character}"),
        other => other.to_string(),
    }
}


/// Quotes a column or table name with backticks after checking it holds only letters, digits, `_` and `.`.
pub fn quote_identifier(name: &str) -> Result<String, SigmaError> {
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '.');
    if valid {
        Ok(format!("`{name}`"))
    } else {
        Err(SigmaError::BadIdentifier(name.to_string()))
    }
}


/// ECS fields stored as `Array(...)` columns; mirrors the array column list of `siem-schema`.
pub const ARRAY_FIELDS: &[&str] = &[
    "event.category",
    "event.type",
    "host.ip",
    "process.args",
    "related.ip",
    "related.user",
    "related.hash",
    "tags",
];


/// Tells whether an ECS column is an array column.
pub fn is_array_field(column: &str) -> bool {
    ARRAY_FIELDS.contains(&column)
}

//! Grammar of every text field kept from a tool output: reference name, timezone, unit name, sub-state.

use crate::limits::{MAX_APPLICATION_NAME_CHARS, MAX_SUB_STATE_CHARS, MAX_UNIT_NAME_CHARS};


pub const MAX_IDENT_CHARS: usize = 64;


pub const UNIT_SUFFIXES: [&str; 3] = [".service", ".timer", ".socket"];


pub fn is_clean_ident(text: &str) -> bool {
    let printable = text.chars().all(|character| character.is_ascii_graphic() || character == ' ');
    let bounded = !text.is_empty() && text.chars().count() <= MAX_IDENT_CHARS;
    printable && bounded && !text.starts_with('-')
}


/// A unit name of `[A-Za-z0-9:_.@-]`, a non-empty stem starting with `[A-Za-z0-9]` and a known suffix.
pub fn is_unit_name(text: &str) -> bool {
    let charset = text
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '.' | '@' | '-'));
    let bounded = text.chars().count() <= MAX_UNIT_NAME_CHARS;
    let suffixed = UNIT_SUFFIXES
        .iter()
        .any(|suffix| text.strip_suffix(suffix).is_some_and(|stem| !stem.is_empty()));
    charset && bounded && suffixed && text.starts_with(|character: char| character.is_ascii_alphanumeric())
}


/// A systemd sub-state: ASCII letters, digits and `-`, 1 to `MAX_SUB_STATE_CHARS` characters.
pub fn is_sub_state(text: &str) -> bool {
    let charset = text.chars().all(|character| character.is_ascii_alphanumeric() || character == '-');
    charset && !text.is_empty() && text.chars().count() <= MAX_SUB_STATE_CHARS
}


/// A unit name (see `is_unit_name`) ending in `suffix`.
pub fn is_unit_name_with(text: &str, suffix: &str) -> bool {
    is_unit_name(text) && text.ends_with(suffix)
}


/// A database name: `[A-Za-z0-9:_.@-]`, 1 to `MAX_UNIT_NAME_CHARS` characters, starting with `[A-Za-z0-9]` (so never a leading `-`).
pub fn is_db_name(text: &str) -> bool {
    let charset = text
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '.' | '@' | '-'));
    charset && text.chars().count() <= MAX_UNIT_NAME_CHARS && text.starts_with(|character: char| character.is_ascii_alphanumeric())
}


/// A PostgreSQL `application_name` kept from a tool output: `[A-Za-z0-9._-]{1,64}`, no leading `-`.
pub fn is_application_name(text: &str) -> bool {
    let charset = text
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'));
    charset && !text.is_empty() && !text.starts_with('-') && text.chars().count() <= MAX_APPLICATION_NAME_CHARS
}

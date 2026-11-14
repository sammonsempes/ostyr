use crate::limits::MAX_CONTINUE_BYTES;
use unicode_general_category::{get_general_category, GeneralCategory};


pub const LABEL_NAME_MAX: usize = 63;


pub const LABEL_PREFIX_MAX: usize = 253;


pub const LABEL_SEPARATOR: char = '/';


pub const UUID_LENGTH: usize = 36;


pub const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];


/// A `continue` token goes back to the API server as a query value: ASCII letters, digits, `-`, `_`, `=` and `.`, 1 to `MAX_CONTINUE_BYTES` bytes.
pub fn valid_continue(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_CONTINUE_BYTES
        && token
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || matches!(next, '-' | '_' | '=' | '.'))
}


/// True for control, format (bidirectional and zero-width included) and line or paragraph separator characters.
pub fn is_hidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// Non-empty, within the byte cap, no leading `-`, no hidden character.
pub fn valid_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.starts_with('-') && !text.chars().any(is_hidden)
}


/// Alphanumeric first and last character (false for an empty text).
pub fn alphanumeric_edges(text: &str) -> bool {
    text.chars()
        .next()
        .zip(text.chars().next_back())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric())
}


/// Kubernetes name segment: alphanumeric at both ends, `-`, `_` and `.` inside, at most 63 characters.
pub fn valid_segment(segment: &str) -> bool {
    segment.len() <= LABEL_NAME_MAX
        && alphanumeric_edges(segment)
        && segment
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || matches!(next, '-' | '_' | '.'))
}


/// DNS subdomain prefix of a label key: lowercase labels of at most 63 characters, at most 253 in all.
pub fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= LABEL_PREFIX_MAX
        && prefix.split('.').all(|part| {
            part.len() <= LABEL_NAME_MAX
                && alphanumeric_edges(part)
                && part.chars().all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '-')
        })
}


pub fn valid_label_key(key: &str) -> bool {
    match key.split_once(LABEL_SEPARATOR) {
        Some((prefix, name)) => valid_prefix(prefix) && valid_segment(name),
        None => valid_segment(key),
    }
}


pub fn valid_label_value(value: &str) -> bool {
    value.is_empty() || valid_segment(value)
}


/// Kubernetes uid: a lowercase RFC 4122 UUID in its 36-character hyphenated form, ASCII only.
pub fn valid_uid(uid: &str) -> bool {
    uid.len() == UUID_LENGTH
        && uid.chars().enumerate().all(|(position, next)| {
            if UUID_HYPHENS.contains(&position) {
                next == '-'
            } else {
                next.is_ascii_digit() || matches!(next, 'a'..='f')
            }
        })
}


/// Kubernetes `IsDNS1123Subdomain`: at most 253 characters, dot-separated parts of lowercase ASCII alphanumerics and `-` starting and ending alphanumeric.
pub fn valid_subdomain(name: &str) -> bool {
    name.len() <= LABEL_PREFIX_MAX
        && name
            .split('.')
            .all(|part| alphanumeric_edges(part) && part.chars().all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '-'))
}


/// Kubernetes `IsDNS1123Label` (namespaces): a subdomain without dots, at most 63 characters.
pub fn valid_dns_label(name: &str) -> bool {
    name.len() <= LABEL_NAME_MAX && valid_subdomain(name) && !name.contains('.')
}

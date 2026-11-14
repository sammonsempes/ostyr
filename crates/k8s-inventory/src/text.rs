use unicode_general_category::{get_general_category, GeneralCategory};


pub const LABEL_NAME_MAX: usize = 63;


pub const LABEL_PREFIX_MAX: usize = 253;


pub const LABEL_SEPARATOR: char = '/';


pub const UUID_LENGTH: usize = 36;


pub const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];


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


/// RFC 1123 subdomain (pod and node names): lowercase ASCII alphanumerics, `-` and `.`, at most 253 characters.
pub fn valid_subdomain(name: &str) -> bool {
    valid_prefix(name)
}


/// RFC 1123 label (namespaces): a subdomain without dots, at most 63 characters.
pub fn valid_dns_label(name: &str) -> bool {
    !name.contains('.') && valid_prefix(name)
}

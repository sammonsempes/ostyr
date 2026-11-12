//! Grammar of every text field kept from a device: model, serial, device name, attribute name, protocol.

pub const MAX_IDENT_CHARS: usize = 64;


pub fn is_clean_ident(text: &str) -> bool {
    let first_ok = text.chars().next().is_some_and(|first| first.is_ascii_alphanumeric() || first == '/');
    let body_ok = text
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || " ._:/-".contains(character));
    first_ok && body_ok && !text.ends_with(' ') && text.chars().count() <= MAX_IDENT_CHARS
}

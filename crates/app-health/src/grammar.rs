//! Grammar of every text field kept from a tool output: reference name, timezone.

pub const MAX_IDENT_CHARS: usize = 64;


pub fn is_clean_ident(text: &str) -> bool {
    let printable = text.chars().all(|character| character.is_ascii_graphic() || character == ' ');
    let bounded = !text.is_empty() && text.chars().count() <= MAX_IDENT_CHARS;
    printable && bounded && !text.starts_with('-')
}

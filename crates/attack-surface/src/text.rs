use unicode_general_category::{get_general_category, GeneralCategory};


pub const SHOWN_BYTES: usize = 64;


pub const REFERENCE_PUNCTUATION: &str = "_.:/-";


/// True for control, format (bidirectional and zero-width included) and line or paragraph separator characters.
pub fn is_hidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// At most the first `SHOWN_BYTES` bytes with every character that is not ASCII graphic or a space escaped, and `...` when the value was cut.
pub fn shown(value: &str) -> String {
    let kept: String = value
        .char_indices()
        .take_while(|(index, character)| index + character.len_utf8() <= SHOWN_BYTES)
        .map(|(_, character)| character)
        .collect();
    let body: String = kept
        .chars()
        .flat_map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                vec![character]
            } else {
                character.escape_unicode().collect::<Vec<_>>()
            }
        })
        .collect();
    if kept.len() < value.len() {
        format!("{body}...")
    } else {
        body
    }
}


/// ASCII graphic characters only (0x21 to 0x7E), non-empty, within the byte cap, no leading `-`.
pub fn valid_argument(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.starts_with('-') && text.chars().all(|next| next.is_ascii_graphic())
}


/// ASCII allowlist `[A-Za-z0-9][A-Za-z0-9_.:/-]*` within the byte cap (no leading `-`, no space, no non-ASCII character).
pub fn valid_reference(text: &str, max_bytes: usize) -> bool {
    text.len() <= max_bytes
        && text.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && text
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || REFERENCE_PUNCTUATION.contains(next))
}

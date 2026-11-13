use unicode_general_category::{get_general_category, GeneralCategory};


pub const SHOWN_BYTES: usize = 64;


pub const MAX_NAME_BYTES: usize = 253;


pub const MAX_LABEL_BYTES: usize = 63;


pub const MIN_NAME_LABELS: usize = 2;


/// True for control, format (bidirectional and zero-width included) and line or paragraph separator characters.
pub fn is_hidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// At most the first `SHOWN_BYTES` bytes with hidden characters escaped, and `...` when the value was cut.
pub fn shown(value: &str) -> String {
    let kept: String = value
        .char_indices()
        .take_while(|(index, character)| index + character.len_utf8() <= SHOWN_BYTES)
        .map(|(_, character)| character)
        .collect();
    let body: String = kept
        .chars()
        .flat_map(|character| {
            if is_hidden(character) {
                character.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect();
    if kept.len() < value.len() {
        format!("{body}...")
    } else {
        body
    }
}


/// Non-empty, within the byte cap, no leading `-`, no hidden character, no whitespace.
pub fn valid_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.starts_with('-') && !text.chars().any(|next| is_hidden(next) || next.is_whitespace())
}


fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '-')
}


/// Lowercase DNS name of at least two labels whose last label holds a letter (so no address-like text, no `localhost`).
pub fn valid_hostname(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= MAX_NAME_BYTES
        && labels.len() >= MIN_NAME_LABELS
        && labels.iter().all(|label| valid_label(label))
        && labels.last().is_some_and(|last| last.chars().any(|next| next.is_ascii_lowercase()))
}

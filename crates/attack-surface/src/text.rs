use crate::model::{MAX_HOSTNAME_BYTES, MAX_HOSTNAME_LABELS, MAX_LABEL_BYTES, MIN_HOSTNAME_LABELS};
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


fn valid_label(label: &str) -> bool {
    let edge = |character: Option<char>| character.is_some_and(|next| next.is_ascii_alphanumeric());
    label.len() <= MAX_LABEL_BYTES
        && edge(label.chars().next())
        && edge(label.chars().last())
        && label.chars().all(|next| next.is_ascii_alphanumeric() || next == '-')
}


/// ASCII LDH name of 2 to 8 labels, at most 253 bytes, no trailing dot, last label not all digits (IDN U-labels, `_` and wildcards refused).
pub fn valid_hostname(text: &str) -> bool {
    let labels = text.split('.').collect::<Vec<_>>();
    text.len() <= MAX_HOSTNAME_BYTES
        && (MIN_HOSTNAME_LABELS..=MAX_HOSTNAME_LABELS).contains(&labels.len())
        && labels.iter().all(|label| valid_label(label))
        && labels.last().is_some_and(|last| !last.chars().all(|next| next.is_ascii_digit()))
}

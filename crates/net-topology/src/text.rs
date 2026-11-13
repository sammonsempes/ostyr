use unicode_general_category::{get_general_category, GeneralCategory};


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

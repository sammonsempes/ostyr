use unicode_general_category::{get_general_category, GeneralCategory};


pub const ID_HEX_LEN: usize = 64;


/// True for control, format (bidirectional and zero-width included) and line or paragraph separator characters.
pub fn is_hidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// Host and tag grammar: non-empty, at most `max_chars` characters, no hidden character, no leading `-`.
pub fn valid_text(text: &str, max_chars: usize) -> bool {
    (1..=max_chars).contains(&text.chars().count()) && !text.starts_with('-') && !text.chars().any(is_hidden)
}


/// A snapshot or archive id: 64 lowercase hexadecimal digits.
pub fn valid_id(text: &str) -> bool {
    text.len() == ID_HEX_LEN && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

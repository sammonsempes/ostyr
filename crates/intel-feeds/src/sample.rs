use crate::limits::MAX_SAMPLE_CHARS;
use unicode_general_category::{get_general_category, GeneralCategory};


pub const ESCAPED_CATEGORIES: [GeneralCategory; 6] = [
    GeneralCategory::Control,
    GeneralCategory::Format,
    GeneralCategory::LineSeparator,
    GeneralCategory::ParagraphSeparator,
    GeneralCategory::PrivateUse,
    GeneralCategory::Unassigned,
];


/// Controls, every format, separator, private-use and unassigned character (bidi, zero-width, tag block included) and the backslash.
pub fn is_unsafe_char(character: char) -> bool {
    character == '\\' || ESCAPED_CATEGORIES.contains(&get_general_category(character))
}


/// Feed text for an error, a sample or a log: at most `MAX_SAMPLE_CHARS` characters, unsafe characters escaped, a cut says how much is omitted.
pub fn bounded_text(text: &str) -> String {
    let kept: String = text
        .chars()
        .take(MAX_SAMPLE_CHARS)
        .flat_map(|character| {
            if is_unsafe_char(character) {
                character.escape_unicode().collect::<Vec<char>>()
            } else {
                vec![character]
            }
        })
        .collect();
    let omitted = text.chars().count().saturating_sub(MAX_SAMPLE_CHARS);
    if omitted > 0 {
        format!("{kept}… [{omitted} omitted]")
    } else {
        kept
    }
}

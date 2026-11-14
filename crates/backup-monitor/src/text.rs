use unicode_general_category::{get_general_category, GeneralCategory};


pub const ID_HEX_LEN: usize = 64;


/// True for control, format (bidirectional and zero-width included) and line or paragraph separator characters.
pub fn is_hidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// Host and tag grammar, an ASCII allowlist: 1 to `max_bytes` bytes of `[A-Za-z0-9._-]`, no leading `-` or `.`.
pub fn valid_text(text: &str, max_bytes: usize) -> bool {
    (1..=max_bytes).contains(&text.len())
        && !text.starts_with(['-', '.'])
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
}


/// A declared host: the host grammar, or a PBS `<type>/<id>` key whose two parts each follow it.
pub fn valid_host_key(text: &str, max_bytes: usize) -> bool {
    text.len() <= max_bytes
        && text.split_once('/').map_or_else(
            || valid_text(text, max_bytes),
            |(kind, name)| valid_text(kind, max_bytes) && valid_text(name, max_bytes),
        )
}


/// Display only: at most `max_chars` characters, every non-printable or non-ASCII one escaped, `...` appended when cut.
pub fn display_text(text: &str, max_chars: usize) -> String {
    let escaped: String = text.chars().take(max_chars).flat_map(char::escape_default).collect();
    if text.chars().nth(max_chars).is_some() {
        format!("{escaped}...")
    } else {
        escaped
    }
}


/// A snapshot or archive id: 64 lowercase hexadecimal digits.
pub fn valid_id(text: &str) -> bool {
    text.len() == ID_HEX_LEN && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

use crate::limits::{MAX_OWNER_CHARS, MAX_REASON_CHARS, MAX_SERIAL_CHARS};


pub fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}


pub fn is_token(text: &str, max: usize, first: fn(char) -> bool, rest: fn(char) -> bool) -> bool {
    let length_ok = (1..=max).contains(&text.chars().count());
    let head_ok = text.chars().next().is_some_and(first);
    let tail_ok = text.chars().skip(1).all(rest);
    length_ok && head_ok && tail_ok
}


pub fn is_alphanumeric(character: char) -> bool {
    character.is_ascii_alphanumeric()
}


pub fn is_serial_rest(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
}


pub fn is_owner_first(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit()
}


pub fn is_owner_rest(character: char) -> bool {
    is_owner_first(character) || matches!(character, '.' | '_' | '@' | '-')
}


pub fn is_serial(text: &str) -> bool {
    is_token(text, MAX_SERIAL_CHARS, is_alphanumeric, is_serial_rest)
}


pub fn is_owner(text: &str) -> bool {
    is_token(text, MAX_OWNER_CHARS, is_owner_first, is_owner_rest)
}


/// Control characters, separators, bidirectional marks and invisible format characters.
pub fn is_forbidden(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}' | '\u{200b}' | '\u{2028}'..='\u{2029}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
        )
}


pub fn is_too_long_reason(text: &str) -> bool {
    text.chars().count() > MAX_REASON_CHARS
}


pub fn is_reason_forbidden(character: char) -> bool {
    is_forbidden(character) || matches!(character, '"' | '\\')
}

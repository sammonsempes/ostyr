use crate::limits::MAX_SAMPLE_CHARS;


pub const BIDI_CONTROLS: [char; 15] = [
    '\\', '\u{2028}', '\u{2029}', '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}',
    '\u{2067}', '\u{2068}', '\u{2069}',
];


pub fn is_unsafe_char(character: char) -> bool {
    character.is_control() || BIDI_CONTROLS.contains(&character)
}


/// Feed text for an error, a sample or a log: at most `MAX_SAMPLE_CHARS` characters, control and bidi characters escaped, a cut says how much is omitted.
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

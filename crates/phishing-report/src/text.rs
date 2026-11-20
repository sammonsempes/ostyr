use crate::model::Counts;


pub const REPLACEMENT: char = '\u{FFFD}';


const HOSTILE_RANGES: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{202E}'),
    ('\u{2066}', '\u{2069}'),
    ('\u{3164}', '\u{3164}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFA0}', '\u{FFA0}'),
];


/// Control characters (NUL, ESC, CR, LF), bidi controls, zero-width marks, line separators and the blank Hangul fillers.
pub fn is_hostile(candidate: char) -> bool {
    candidate.is_control() || HOSTILE_RANGES.iter().any(|(low, high)| (*low..=*high).contains(&candidate))
}


/// Invisible characters a URL may carry without changing where it points: zero-width marks, word joiner, BOM and soft hyphen.
pub fn is_zero_width(candidate: char) -> bool {
    matches!(candidate, '\u{00AD}' | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}')
}


pub fn has_hostile(text: &str) -> bool {
    text.chars().any(is_hostile)
}


/// Keeps at most `max_chars` characters, replaces hostile ones and names a cut with a marker; both are counted.
pub fn clean(text: &str, max_chars: usize, counts: &mut Counts) -> String {
    let total = text.chars().count();
    let kept: String = text
        .chars()
        .take(max_chars)
        .map(|candidate| {
            counts.replaced_chars += usize::from(is_hostile(candidate));
            if is_hostile(candidate) {
                REPLACEMENT
            } else {
                candidate
            }
        })
        .collect();
    let omitted = total.saturating_sub(max_chars);
    counts.text_cut += usize::from(omitted > 0);
    if omitted > 0 {
        format!("{kept}[cut {omitted} chars]")
    } else {
        kept
    }
}


/// An address without angle brackets, refused (counted) when too long, hostile or without an at sign.
pub fn clean_address(text: &str, max_bytes: usize, counts: &mut Counts) -> Option<String> {
    let address = text.trim().trim_matches(['<', '>']);
    let refused = address.len() > max_bytes || has_hostile(address) || !address.contains('@');
    counts.addresses_refused += usize::from(refused && !address.is_empty());
    (!refused).then_some(address.to_owned())
}

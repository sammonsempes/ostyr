use crate::model::ObservableKind;
use std::net::IpAddr;


pub const MAX_LABEL_CHARS: usize = 63;


pub const MAX_DOMAIN_CHARS: usize = 253;


pub const MAX_LOCAL_CHARS: usize = 64;


pub const HASH_LENGTHS: [usize; 4] = [32, 40, 64, 128];


pub const URL_SCHEMES: [&str; 3] = ["http://", "https://", "ftp://"];


pub const URL_AUTHORITY_ENDS: [char; 3] = ['/', '?', '#'];


/// Bidirectional controls (U+202A to U+202E, U+2066 to U+2069) can reorder what an analyst reads.
pub fn is_bidi_control(character: char) -> bool {
    matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}


/// No C0, C1 or DEL control character and no bidirectional control.
pub fn is_plain_text(text: &str) -> bool {
    !text.chars().any(|character| character.is_control() || is_bidi_control(character))
}


pub fn is_printable_ascii(text: &str) -> bool {
    text.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}


/// A lowercase LDH label of 1 to 63 characters that neither starts nor ends with a hyphen.
pub fn is_label(label: &str) -> bool {
    (1..=MAX_LABEL_CHARS).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}


pub fn is_domain(text: &str) -> bool {
    text.len() <= MAX_DOMAIN_CHARS && text.split('.').all(is_label)
}


pub fn is_hash(text: &str) -> bool {
    HASH_LENGTHS.contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


pub fn is_email(text: &str) -> bool {
    text.split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && local.len() <= MAX_LOCAL_CHARS && is_printable_ascii(local) && is_domain(domain))
}


/// `http`, `https` or `ftp`, a non-empty authority, printable ASCII only (no space, no control character).
pub fn is_url(text: &str) -> bool {
    let rest = URL_SCHEMES.iter().find_map(|scheme| {
        text.get(..scheme.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
            .and_then(|_prefix| text.get(scheme.len()..))
    });
    is_printable_ascii(text)
        && rest
            .and_then(|tail| tail.chars().next())
            .is_some_and(|first| !URL_AUTHORITY_ENDS.contains(&first))
}


/// The grammar of one kind, applied to the normalised value.
pub fn is_valid_value(kind: ObservableKind, value: &str) -> bool {
    match kind {
        ObservableKind::Ip => value.parse::<IpAddr>().is_ok(),
        ObservableKind::Domain => is_domain(value),
        ObservableKind::Hash => is_hash(value),
        ObservableKind::Email => is_email(value),
        ObservableKind::Url => is_url(value),
        ObservableKind::Filename | ObservableKind::Other => is_plain_text(value),
    }
}

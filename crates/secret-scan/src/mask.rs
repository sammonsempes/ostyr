pub const MASK_MARKER: &str = "********";


pub const MAX_FIELD_CHARS: usize = 512;


const KEEP_RATIO: usize = 2;


/// Escapes control characters and quotes, then cuts the result to `max_chars` characters.
pub fn escape_bounded(text: &str, max_chars: usize) -> String {
    text.chars().flat_map(char::escape_debug).take(max_chars).collect()
}


/// Keeps `kept_chars` leading characters only when the text is at least twice as long, then the fixed marker.
pub fn mask_secret(secret: &str, kept_chars: usize) -> String {
    let kept = if secret.chars().count() >= kept_chars.saturating_mul(KEEP_RATIO) {
        kept_chars
    } else {
        0
    };
    secret.chars().take(kept).chain(MASK_MARKER.chars()).collect()
}


/// The match with every occurrence of the secret masked; the whole match is masked when the secret is not found in it.
pub fn masked_excerpt(match_text: &str, secret: &str, kept_chars: usize, excerpt_chars: usize) -> String {
    let found = !secret.is_empty() && match_text.contains(secret);
    let masked = if found {
        match_text.replace(secret, &mask_secret(secret, kept_chars))
    } else {
        mask_secret(match_text, kept_chars)
    };
    escape_bounded(&masked, excerpt_chars)
}

//! The one text grammar shared by rule ids and the texts that reach an alert title.

use sha2::{Digest, Sha256};


pub const MAX_TOKEN_CHARS: usize = 100;


pub const TOKEN_PUNCTUATION: &str = "._+-:@/~^";


pub const DIGEST_CHARS: usize = 12;


pub const DIGEST_MARK: char = '#';


/// Alphanumeric or `@` first (so never a leading `-`), then alphanumerics and `TOKEN_PUNCTUATION`, at most `MAX_TOKEN_CHARS` characters.
pub fn is_token(text: &str) -> bool {
    let mut characters = text.chars();
    text.chars().take(MAX_TOKEN_CHARS + 1).count() <= MAX_TOKEN_CHARS
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && characters.all(|next| next.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(next))
}


/// The text itself when it is a token, else `#` and the first `DIGEST_CHARS` hex characters of its SHA-256: visible, stable, and free of raw bytes.
pub fn shown(text: &str) -> String {
    if is_token(text) {
        text.to_owned()
    } else {
        let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
        format!("{DIGEST_MARK}{}", digest.chars().take(DIGEST_CHARS).collect::<String>())
    }
}

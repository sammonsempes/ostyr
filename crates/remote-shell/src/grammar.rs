pub const MAX_SUBJECT_BYTES: usize = 255;


pub const MAX_REFERENCE_BYTES: usize = 128;


pub const SUBJECT_PUNCTUATION: &str = "-_.@:+/=|";


pub const REFERENCE_PUNCTUATION: &str = "_.:/-";


/// An OIDC subject: 1 to 255 bytes of ASCII letters, digits and `-_.@:+/=|` only: an allowlist, so no look-alike or hidden character.
pub fn valid_subject(subject: &str) -> bool {
    (1..=MAX_SUBJECT_BYTES).contains(&subject.len())
        && subject
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || SUBJECT_PUNCTUATION.contains(character))
}


/// A ticket, incident or request reference: `[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}`.
pub fn valid_reference(reference: &str) -> bool {
    let mut characters = reference.chars();
    (1..=MAX_REFERENCE_BYTES).contains(&reference.len())
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|character| character.is_ascii_alphanumeric() || REFERENCE_PUNCTUATION.contains(character))
}

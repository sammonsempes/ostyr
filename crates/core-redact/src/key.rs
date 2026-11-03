pub const SENSITIVE_SEGMENTS: [&str; 13] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "auth",
    "authorization",
    "cookie",
    "credential",
    "session",
    "passphrase",
    "apikey",
];


pub const PLURAL_SUFFIX: &str = "s";


/// True when `current` starts a new segment: letter/digit change, `aB`, or the last capital of `ABc`.
pub fn is_boundary(previous: char, current: char, next: Option<char>) -> bool {
    previous.is_ascii_digit() != current.is_ascii_digit()
        || (previous.is_lowercase() && current.is_uppercase())
        || (previous.is_uppercase() && current.is_uppercase() && next.is_some_and(char::is_lowercase))
}


/// Splits a key on every non alphanumeric character and on camel case boundaries; empty segments may remain.
pub fn split_segments(key: &str) -> Vec<String> {
    let characters: Vec<char> = key.chars().collect();
    characters
        .iter()
        .enumerate()
        .fold(Vec::new(), |mut segments: Vec<String>, (index, character)| {
            let previous = index.checked_sub(1).and_then(|position| characters.get(position)).copied();
            let next = characters.get(index + 1).copied();
            let boundary = previous.is_some_and(|before| is_boundary(before, *character, next));
            match segments.last_mut() {
                _ if !character.is_alphanumeric() => segments.push(String::new()),
                Some(last) if !boundary => last.push(*character),
                _ => segments.push(character.to_string()),
            }
            segments
        })
}


pub fn is_sensitive_segment(segment: &str) -> bool {
    let lowered = segment.to_lowercase();
    let singular = lowered.strip_suffix(PLURAL_SUFFIX).unwrap_or(&lowered);
    SENSITIVE_SEGMENTS.iter().any(|sensitive| *sensitive == lowered || *sensitive == singular)
}


/// Case-insensitive match of any key segment against `SENSITIVE_SEGMENTS` (or its plural): `api_key` yes, `monkey` no.
pub fn is_sensitive_key(key: &str) -> bool {
    split_segments(key).iter().any(|segment| is_sensitive_segment(segment))
}

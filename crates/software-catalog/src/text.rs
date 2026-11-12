//! Grammars of the catalogue fields.

use patch_inventory::scan::is_forbidden;


const MAX_NAME_CHARS: usize = 64;


const MAX_WINGET_CHARS: usize = 128;


const MAX_MSI_KEY_CHARS: usize = 201;


const MAX_SUBJECT_CHARS: usize = 256;


const SHA256_CHARS: usize = 64;


const FINGERPRINT_CHARS: usize = 40;


const MIN_WINGET_SEGMENTS: usize = 2;


pub fn is_clean(text: &str) -> bool {
    !text.is_empty() && !text.starts_with('-') && !text.chars().any(is_forbidden)
}


pub fn is_entry_name(text: &str) -> bool {
    text.chars().count() <= MAX_NAME_CHARS
        && text.starts_with(|first: char| matches!(first, 'a'..='z' | '0'..='9'))
        && text.chars().all(|character| matches!(character, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
}


pub fn is_winget_segment(segment: &str) -> bool {
    segment.starts_with(|first: char| first.is_ascii_alphanumeric())
        && segment.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
}


pub fn is_winget_id(text: &str) -> bool {
    text.chars().count() <= MAX_WINGET_CHARS && text.split('.').count() >= MIN_WINGET_SEGMENTS && text.split('.').all(is_winget_segment)
}


pub fn is_msi_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".."
}


pub fn is_msi_key(text: &str) -> bool {
    text.chars().count() <= MAX_MSI_KEY_CHARS
        && text.starts_with(|first: char| matches!(first, 'a'..='z' | '0'..='9'))
        && text
            .chars()
            .all(|character| matches!(character, 'a'..='z' | '0'..='9' | '.' | '_' | '/' | '-'))
        && text.split('/').all(is_msi_segment)
}


pub fn is_sha256(text: &str) -> bool {
    text.len() == SHA256_CHARS && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}


pub fn is_fingerprint(text: &str) -> bool {
    text.len() == FINGERPRINT_CHARS && text.chars().all(|character| matches!(character, '0'..='9' | 'A'..='F'))
}


pub fn is_subject(text: &str) -> bool {
    is_clean(text) && text.chars().count() <= MAX_SUBJECT_CHARS
}

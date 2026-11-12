//! Shared text helpers for the public catalogues.

use crate::limits::{CUT_MARKER, CVE_ID_PARTS, CVE_ID_PREFIX, CVE_SEQUENCE_MAX_DIGITS, CVE_SEQUENCE_MIN_DIGITS, CVE_YEAR_DIGITS};


const CVE_YEAR_INDEX: usize = 1;


const CVE_ZERO_YEAR: &str = "0000";


/// Printable ASCII only (anything else becomes `?`), cut after `max_chars` with a visible marker.
pub fn bounded_text(text: &str, max_chars: usize) -> String {
    let kept: String = text
        .chars()
        .take(max_chars)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect();
    if text.chars().nth(max_chars).is_some() {
        format!("{kept}{CUT_MARKER}")
    } else {
        kept
    }
}


fn is_digits(part: Option<&&str>, min: usize, max: usize) -> bool {
    part.is_some_and(|value| (min..=max).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit()))
}


/// `CVE-YYYY-NNNN` with 4 to 7 sequence digits, ASCII digits only, year not `0000`; the one grammar of the KEV, EPSS and alert code.
pub fn is_cve_id(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    parts.len() == CVE_ID_PARTS
        && parts.first() == Some(&CVE_ID_PREFIX)
        && parts.get(CVE_YEAR_INDEX) != Some(&CVE_ZERO_YEAR)
        && is_digits(parts.get(CVE_YEAR_INDEX), CVE_YEAR_DIGITS, CVE_YEAR_DIGITS)
        && is_digits(parts.get(CVE_YEAR_INDEX + 1), CVE_SEQUENCE_MIN_DIGITS, CVE_SEQUENCE_MAX_DIGITS)
}

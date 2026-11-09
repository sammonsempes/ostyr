use crate::model::REDACTION_MARK;
use regex::bytes::Regex;


/// Replaces every non-empty match of every pattern, one pattern after the other, over the whole buffer (so a match split across read chunks is found).
pub fn redact(bytes: Vec<u8>, patterns: &[Regex]) -> Vec<u8> {
    let boundary = bytes.len();
    redact_within(bytes, patterns, boundary).0
}


/// Like `redact`, but only matches starting before `boundary` are replaced; the returned boundary is where it moved to and the text beyond is context only.
pub fn redact_within(bytes: Vec<u8>, patterns: &[Regex], boundary: usize) -> (Vec<u8>, usize) {
    patterns.iter().fold((bytes, boundary), |(text, limit), pattern| {
        let (mut redacted, copied) = pattern
            .find_iter(&text)
            .take_while(|found| found.start() < limit)
            .filter(|found| !found.is_empty())
            .fold((Vec::new(), 0), |(mut kept, copied), found| {
                kept.extend(text.get(copied..found.start()).into_iter().flatten());
                kept.extend(REDACTION_MARK);
                (kept, found.end())
            });
        let moved = redacted.len() + limit.saturating_sub(copied);
        redacted.extend(text.get(copied..).into_iter().flatten());
        (redacted, moved)
    })
}

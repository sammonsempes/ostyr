use crate::model::REDACTION_MARK;
use regex::bytes::Regex;


/// Replaces every non-empty match of every pattern, one pattern after the other, over the whole buffer (so a match split across read chunks is found).
pub fn redact(bytes: Vec<u8>, patterns: &[Regex]) -> Vec<u8> {
    patterns.iter().fold(bytes, |text, pattern| {
        let (mut redacted, copied) = pattern
            .find_iter(&text)
            .filter(|found| !found.is_empty())
            .fold((Vec::new(), 0), |(mut kept, copied), found| {
                kept.extend(text.get(copied..found.start()).into_iter().flatten());
                kept.extend(REDACTION_MARK);
                (kept, found.end())
            });
        redacted.extend(text.get(copied..).into_iter().flatten());
        redacted
    })
}

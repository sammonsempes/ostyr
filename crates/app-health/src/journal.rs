//! Bounded excerpt of `journalctl -o cat` output for an alert.

use crate::error::NtpError;
use crate::limits::MAX_JOURNAL_BYTES;
use crate::model::Excerpt;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use unicode_general_category::{get_general_category, GeneralCategory};


pub const ESCAPED_CATEGORIES: [GeneralCategory; 7] = [
    GeneralCategory::Control,
    GeneralCategory::Format,
    GeneralCategory::LineSeparator,
    GeneralCategory::ParagraphSeparator,
    GeneralCategory::SpaceSeparator,
    GeneralCategory::PrivateUse,
    GeneralCategory::Unassigned,
];


/// Controls, formats (bidi, zero-width), separators other than a plain space, private-use, unassigned and the backslash.
pub fn is_unsafe_char(character: char) -> bool {
    character != ' ' && (character == '\\' || ESCAPED_CATEGORIES.contains(&get_general_category(character)))
}


/// One log line: cut at `max_bytes` on a character boundary with a visible marker, unsafe characters written as `\u{..}`.
pub fn clean_line(raw: &[u8], max_bytes: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let kept: String = text
        .chars()
        .scan(0, |used, character| {
            *used += character.len_utf8();
            Some((*used, character))
        })
        .take_while(|(used, _)| *used <= max_bytes)
        .map(|(_, character)| character)
        .collect();
    let omitted = text.len() - kept.len();
    let escaped: String = kept
        .chars()
        .flat_map(|character| {
            if is_unsafe_char(character) {
                character.escape_unicode().collect::<Vec<char>>()
            } else {
                vec![character]
            }
        })
        .collect();
    if omitted > 0 {
        format!("{escaped}… [{omitted} bytes omitted]")
    } else {
        escaped
    }
}


/// The last `max_lines` lines, each through `clean_line`, and how many earlier lines were dropped; at most `MAX_JOURNAL_BYTES` are read.
pub fn log_excerpt<Input: Read>(mut reader: Input, max_lines: usize, max_bytes: usize) -> Result<Excerpt, NtpError> {
    excerpt_from(&mut reader, max_lines, max_bytes)
}


/// Same as `log_excerpt` over a trait object, so the body is one instantiation for coverage.
pub fn excerpt_from(reader: &mut dyn Read, max_lines: usize, max_bytes: usize) -> Result<Excerpt, NtpError> {
    let mut buffered = BufReader::new(reader.take(MAX_JOURNAL_BYTES + 1));
    let mut window: VecDeque<String> = VecDeque::new();
    let mut total = 0;
    buffered.by_ref().split(b'\n').try_for_each(|line| {
        window.push_back(clean_line(&line?, max_bytes));
        total += 1;
        if window.len() > max_lines {
            window.pop_front();
        }
        Ok::<(), std::io::Error>(())
    })?;
    Ok(Excerpt {
        omitted: total - window.len(),
        input_truncated: buffered.get_ref().limit() == 0,
        lines: window.into_iter().collect(),
    })
}

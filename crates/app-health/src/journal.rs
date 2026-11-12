//! Bounded excerpt of `journalctl -o cat` output for an alert.

use crate::error::NtpError;
use crate::limits::{MAX_EXCERPT_LINES, MAX_JOURNAL_BYTES, MAX_LINE_BYTES, MIN_LINE_BYTES};
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


fn escaped_len(character: char) -> usize {
    if is_unsafe_char(character) {
        character.escape_unicode().count()
    } else {
        character.len_utf8()
    }
}


fn escape_char(character: char) -> String {
    if is_unsafe_char(character) {
        character.escape_unicode().collect()
    } else {
        character.to_string()
    }
}


/// One log line: escaped first, then the escaped text plus the marker is at most `max_bytes`; the marker counts the omitted raw bytes.
fn clean_line(raw: &[u8], max_bytes: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let fits = text.chars().map(escaped_len).sum::<usize>() <= max_bytes;
    let marker_len = format!("… [{} bytes omitted]", text.len()).len();
    let budget = if fits { max_bytes } else { max_bytes.saturating_sub(marker_len) };
    let kept: Vec<(usize, String)> = text
        .chars()
        .scan(0, |used, character| {
            *used += escaped_len(character);
            Some((*used, character))
        })
        .take_while(|(used, _)| *used <= budget)
        .map(|(_, character)| (character.len_utf8(), escape_char(character)))
        .collect();
    let omitted = text.len() - kept.iter().map(|(source_len, _)| source_len).sum::<usize>();
    let escaped: String = kept.into_iter().map(|(_, piece)| piece).collect();
    if omitted > 0 {
        format!("{escaped}… [{omitted} bytes omitted]")
    } else {
        escaped
    }
}


/// The last `max_lines` (at most `MAX_EXCERPT_LINES`) lines, each through `clean_line`, and how many earlier lines were dropped; at most `MAX_JOURNAL_BYTES` are read.
pub fn log_excerpt<Input: Read>(mut reader: Input, max_lines: usize, max_bytes: usize) -> Result<Excerpt, NtpError> {
    excerpt_from(&mut reader, max_lines, max_bytes)
}


/// Same as `log_excerpt` over a trait object, so the body is one instantiation for coverage.
pub fn excerpt_from(reader: &mut dyn Read, max_lines: usize, max_bytes: usize) -> Result<Excerpt, NtpError> {
    if max_lines > MAX_EXCERPT_LINES {
        Err(NtpError::OutOfRange { field: "max_lines" })
    } else if !(MIN_LINE_BYTES..=MAX_LINE_BYTES).contains(&max_bytes) {
        Err(NtpError::OutOfRange { field: "max_bytes" })
    } else {
        read_excerpt(reader, max_lines, max_bytes)
    }
}


fn read_excerpt(reader: &mut dyn Read, max_lines: usize, max_bytes: usize) -> Result<Excerpt, NtpError> {
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

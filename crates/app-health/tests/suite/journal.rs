use crate::suite::common::TestResult;
use app_health::error::NtpError;
use app_health::journal::log_excerpt;
use std::io::Read;


const HUGE: usize = 10_000_000;


const MANY_LINES: usize = 1_000_000;


const LINE_CAP: usize = 16;


const WIDE_CAP: usize = 200;


const TINY_CAP: usize = 3;


const KEEP_TWO: usize = 2;


const KEEP_THREE: usize = 3;


const KEEP_FIVE: usize = 5;


const SHORT_LINE: usize = 100;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


#[test]
fn keeps_the_last_lines_and_counts_the_rest() -> TestResult {
    let excerpt = log_excerpt("a\nb\nc\nd\n".as_bytes(), KEEP_TWO, LINE_CAP)?;
    assert_eq!(excerpt.lines, ["c", "d"]);
    assert_eq!(excerpt.omitted, KEEP_TWO);
    assert!(!excerpt.input_truncated);
    let all = log_excerpt("a\nb".as_bytes(), KEEP_FIVE, LINE_CAP)?;
    assert_eq!(all.lines, ["a", "b"]);
    assert_eq!(all.omitted, 0);
    Ok(())
}


#[test]
fn empty_input_and_zero_lines() -> TestResult {
    let empty = log_excerpt("".as_bytes(), KEEP_THREE, LINE_CAP)?;
    assert!(empty.lines.is_empty());
    assert_eq!(empty.omitted, 0);
    let none = log_excerpt("a\nb\n".as_bytes(), 0, LINE_CAP)?;
    assert!(none.lines.is_empty());
    assert_eq!(none.omitted, KEEP_TWO);
    Ok(())
}


#[test]
fn unsafe_characters_are_escaped() -> TestResult {
    let raw = "esc\u{1b}[31m bidi\u{202e}x nul\u{0}y nb\u{a0}sp back\\slash tab\t\n";
    let excerpt = log_excerpt(raw.as_bytes(), 1, WIDE_CAP)?;
    let line = excerpt.lines.first().ok_or("no line")?;
    assert_eq!(line, "esc\\u{1b}[31m bidi\\u{202e}x nul\\u{0}y nb\\u{a0}sp back\\u{5c}slash tab\\u{9}");
    assert!(line.chars().all(|character| !character.is_control() && character != '\u{202e}'));
    Ok(())
}


#[test]
fn long_lines_are_cut_on_a_character_boundary_with_a_marker() -> TestResult {
    let excerpt = log_excerpt("0123456789abcdefXYZ\n".as_bytes(), 1, LINE_CAP)?;
    assert_eq!(excerpt.lines, ["0123456789abcdef… [3 bytes omitted]"]);
    let wide = log_excerpt("aé€é\n".as_bytes(), 1, TINY_CAP)?;
    assert_eq!(wide.lines, ["aé… [5 bytes omitted]"]);
    let exact = log_excerpt("0123456789abcdef\n".as_bytes(), 1, LINE_CAP)?;
    assert_eq!(exact.lines, ["0123456789abcdef"]);
    Ok(())
}


#[test]
fn invalid_utf8_is_replaced_not_refused() -> TestResult {
    let excerpt = log_excerpt(&b"ok\xff\xfe\n"[..], 1, LINE_CAP)?;
    assert_eq!(excerpt.lines, ["ok\u{fffd}\u{fffd}"]);
    Ok(())
}


#[test]
fn a_million_lines_are_read_only_up_to_the_cap() -> TestResult {
    let raw = "abcdefg\n".repeat(MANY_LINES);
    let excerpt = log_excerpt(raw.as_bytes(), KEEP_TWO, LINE_CAP)?;
    assert_eq!(excerpt.lines.len(), KEEP_TWO);
    assert!(excerpt.input_truncated);
    assert!(excerpt.omitted < MANY_LINES);
    Ok(())
}


#[test]
fn a_ten_megabyte_line_is_cut() -> TestResult {
    let raw = "x".repeat(HUGE);
    let excerpt = log_excerpt(raw.as_bytes(), KEEP_THREE, LINE_CAP)?;
    assert!(excerpt.input_truncated);
    let line = excerpt.lines.first().ok_or("no line")?;
    assert!(line.starts_with("xxxxxxxxxxxxxxxx… ["));
    assert!(line.len() < SHORT_LINE);
    Ok(())
}


#[test]
fn read_errors_are_reported() -> TestResult {
    assert!(matches!(log_excerpt(FailingReader, KEEP_THREE, LINE_CAP), Err(NtpError::Read(_))));
    Ok(())
}

use crate::suite::common::TestResult;
use app_health::error::NtpError;
use app_health::journal::log_excerpt;
use std::io::Read;


const HUGE: usize = 10_000_000;


const MANY_LINES: usize = 1_000_000;


const LINE_CAP: usize = 64;


const WIDE_CAP: usize = 200;


const TOO_MANY_LINES: usize = 201;


const MAX_LINES: usize = 200;


const BELOW_MIN_CAP: usize = 63;


const ESC_COUNT: usize = 512;


const ESC_CAP: usize = 100;


const KEEP_TWO: usize = 2;


const KEEP_THREE: usize = 3;


const KEEP_FIVE: usize = 5;


const KEEP_TEN: usize = 10;


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
    let raw = format!("{}XYZ", "0123456789".repeat(KEEP_TEN));
    let excerpt = log_excerpt(format!("{raw}\n").as_bytes(), 1, LINE_CAP)?;
    let line = excerpt.lines.first().ok_or("no line")?;
    assert!(line.len() <= LINE_CAP);
    assert!(line.starts_with("0123456789"));
    assert!(line.ends_with(" bytes omitted]"));
    let wide = log_excerpt("é".repeat(LINE_CAP).as_bytes(), 1, LINE_CAP)?;
    let wide_line = wide.lines.first().ok_or("no line")?;
    assert!(wide_line.len() <= LINE_CAP);
    assert!(wide_line.contains("é… ["));
    let exact = "0123456789abcdef".repeat(KEEP_FIVE - 1);
    let fits = log_excerpt(format!("{exact}\n").as_bytes(), 1, LINE_CAP)?;
    assert_eq!(fits.lines, [exact]);
    Ok(())
}


#[test]
fn escaping_comes_before_the_cut() -> TestResult {
    let raw = "\u{1b}".repeat(ESC_COUNT);
    let excerpt = log_excerpt(raw.as_bytes(), 1, ESC_CAP)?;
    let line = excerpt.lines.first().ok_or("no line")?;
    assert!(line.len() <= ESC_CAP);
    assert!(line.starts_with("\\u{1b}\\u{1b}"));
    let kept = line.matches("\\u{1b}").count();
    assert!(line.ends_with(&format!("… [{} bytes omitted]", ESC_COUNT - kept)));
    Ok(())
}


#[test]
fn line_and_cap_bounds_are_refused() -> TestResult {
    assert!(log_excerpt("a\n".as_bytes(), MAX_LINES, LINE_CAP).is_ok());
    assert!(matches!(
        log_excerpt("a\n".as_bytes(), TOO_MANY_LINES, LINE_CAP),
        Err(NtpError::OutOfRange { field: "max_lines" })
    ));
    assert!(matches!(
        log_excerpt("a\n".as_bytes(), 1, BELOW_MIN_CAP),
        Err(NtpError::OutOfRange { field: "max_bytes" })
    ));
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
    assert!(line.starts_with("xxxxxxxxxxxxxxxx"));
    assert!(line.contains("… ["));
    assert!(line.len() <= LINE_CAP);
    assert!(line.len() < SHORT_LINE);
    Ok(())
}


#[test]
fn read_errors_are_reported() -> TestResult {
    assert!(matches!(log_excerpt(FailingReader, KEEP_THREE, LINE_CAP), Err(NtpError::Read(_))));
    Ok(())
}

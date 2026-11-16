#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::model::{Entry, Located, HASH_HEX_LEN};
use breached_passwords::parse::{decode_hash, first_line_start, locate, parse_count, parse_line, terminated_length};
use types::TestResult;


const HASH: &str = "8846F7EAEE8FB117AD06BDD830B7586C";


const FIRST_HASH_BYTE: u8 = 0x88;


const OFFSET: u64 = 7;


const COUNT: u64 = 9;


const SEVEN: u64 = 7;


const THREE: usize = 3;


const TOO_LONG: usize = 200;


const LINE_LENGTH: u64 = 35;


const SECOND_LINE_START: u64 = 5;


fn entry_of(located: Located) -> Result<Entry, Box<dyn std::error::Error>> {
    match located {
        Located::Line(entry) => Ok(entry),
        Located::Missing => Err("no line".into()),
    }
}


#[test]
fn counts_are_decimal_and_bounded() -> TestResult {
    assert_eq!(parse_count(b"18446744073709551615"), Some(u64::MAX));
    assert_eq!(parse_count(b"007"), Some(SEVEN));
    assert_eq!(parse_count(b"18446744073709551616"), None);
    assert_eq!(parse_count(b""), None);
    assert_eq!(parse_count(b"4x"), None);
    assert_eq!(parse_count(b"+4"), None);
    Ok(())
}


#[test]
fn hashes_are_32_hex_digits_of_any_case() -> TestResult {
    assert!(decode_hash(HASH.as_bytes()).is_some());
    assert!(decode_hash(HASH.to_lowercase().as_bytes()).is_some());
    assert!(decode_hash(b"abcd").is_none());
    assert!(decode_hash("Z".repeat(HASH_HEX_LEN).as_bytes()).is_none());
    Ok(())
}


#[test]
fn lines_parse_or_name_their_offset() -> TestResult {
    let hash = parse_line(format!("{HASH}:{COUNT}\r").as_bytes(), OFFSET)?;
    assert_eq!(hash.0.first(), Some(&FIRST_HASH_BYTE));
    [
        HASH.to_owned(),
        format!("{HASH}:1:2"),
        format!("{HASH}:"),
        format!("{HASH}:x"),
        "zz:1".to_owned(),
        String::new(),
    ]
    .iter()
    .for_each(|bad| assert!(matches!(parse_line(bad.as_bytes(), OFFSET), Err(ListError::Malformed { offset: OFFSET }))));
    Ok(())
}


#[test]
fn the_first_line_start_depends_on_alignment_and_end_of_file() -> TestResult {
    assert_eq!(first_line_start(b"abc", 0, true, false)?, Some(0));
    assert_eq!(first_line_start(b"ab\ncd", 0, false, false)?, Some(THREE));
    assert_eq!(first_line_start(b"abc", 0, false, true)?, None);
    assert!(matches!(
        first_line_start(b"abc", OFFSET, false, false),
        Err(ListError::LineTooLong { offset: OFFSET })
    ));
    Ok(())
}


#[test]
fn terminated_lengths_are_capped() -> TestResult {
    let long: Vec<u8> = std::iter::repeat_n(b'a', TOO_LONG).chain(*b"\n").collect();
    assert_eq!(terminated_length(b"abc\nrest", 0, false)?, THREE);
    assert!(matches!(terminated_length(&long, OFFSET, false), Err(ListError::LineTooLong { .. })));
    assert!(matches!(
        terminated_length(b"abc", OFFSET, true),
        Err(ListError::Unterminated { offset: OFFSET })
    ));
    assert!(matches!(
        terminated_length(b"abc", OFFSET, false),
        Err(ListError::LineTooLong { offset: OFFSET })
    ));
    Ok(())
}


#[test]
fn locating_a_line_in_a_window() -> TestResult {
    let whole = format!("{HASH}:{COUNT}\nnext");
    let entry = entry_of(locate(whole.as_bytes(), OFFSET, true, false)?)?;
    assert_eq!((entry.start, entry.next), (OFFSET, OFFSET + LINE_LENGTH));
    let skipped = format!("tail\n{HASH}:{COUNT}\n");
    let second = entry_of(locate(skipped.as_bytes(), 0, false, false)?)?;
    assert_eq!(second.start, SECOND_LINE_START);
    assert!(matches!(locate(b"", 0, true, true)?, Located::Missing));
    assert!(matches!(locate(b"abc", 0, false, true)?, Located::Missing));
    assert!(matches!(locate(b"abc\n", 0, false, true)?, Located::Missing));
    assert!(matches!(locate(b"abc\n", 0, false, false), Err(ListError::LineTooLong { .. })));
    assert!(matches!(locate(b"abc\nxyz", 0, false, true), Err(ListError::Unterminated { .. })));
    assert!(matches!(locate(b"abc\nxyz\n", 0, false, true), Err(ListError::Malformed { .. })));
    Ok(())
}

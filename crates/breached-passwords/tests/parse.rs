#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::model::HASH_HEX_LEN;
use breached_passwords::parse::{decode_hash, parse_count, parse_line};
use types::TestResult;


const HASH: &str = "8846F7EAEE8FB117AD06BDD830B7586C";


const FIRST_HASH_BYTE: u8 = 0x88;


const COUNT: u64 = 9;


const SEVEN: u64 = 7;


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
fn lines_parse_or_are_malformed() -> TestResult {
    let hash = parse_line(format!("{HASH}:{COUNT}\r").as_bytes())?;
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
    .for_each(|bad| assert!(matches!(parse_line(bad.as_bytes()), Err(ListError::Malformed))));
    Ok(())
}

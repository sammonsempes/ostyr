#[path = "support/types.rs"]
mod types;


use breached_passwords::error::{HashFileError, ListError};
use breached_passwords::hashes::read_hashes;
use breached_passwords::model::{MAX_HASHES, MAX_HASH_FILE_BYTES};
use std::io::{self, Read};
use types::TestResult;


const HASH: &str = "8846F7EAEE8FB117AD06BDD830B7586C";


const TWO: usize = 2;


const OTHER: &str = "0123456789abcdef0123456789abcdef";


struct Failing;


impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


#[test]
fn lf_crlf_and_blank_lines_are_read() -> TestResult {
    let text = format!("{HASH}\r\n\n{OTHER}\n");
    let hashes = read_hashes(&mut text.as_bytes())?;
    assert_eq!(hashes.len(), TWO);
    Ok(())
}


#[test]
fn a_bad_line_is_named_by_number_only() -> TestResult {
    let text = format!("{HASH}\nnot-a-hash-{OTHER}\n");
    let result = read_hashes(&mut text.as_bytes());
    assert!(matches!(result, Err(HashFileError::Malformed { line: TWO })));
    Ok(())
}


#[test]
fn size_and_count_caps_and_read_failures_are_typed() -> TestResult {
    let mut huge = io::repeat(b'a');
    assert!(matches!(read_hashes(&mut huge), Err(HashFileError::TooLarge)));
    let newlines = "\n".repeat(MAX_HASHES + 1);
    assert!(matches!(read_hashes(&mut newlines.as_bytes()), Err(HashFileError::TooMany)));
    assert!(matches!(read_hashes(&mut Failing), Err(HashFileError::Read(_))));
    assert!(MAX_HASH_FILE_BYTES > MAX_HASHES as u64);
    Ok(())
}


#[test]
fn no_error_text_carries_a_hash() -> TestResult {
    let text = format!("{OTHER}\nnope{HASH}\n");
    let error = read_hashes(&mut text.as_bytes()).err().ok_or("expected an error")?;
    let file_error = format!("{error} {error:?}");
    let list_error = ListError::Malformed;
    let rendered = [file_error, format!("{list_error} {list_error:?}")].concat();
    assert!(!rendered.to_uppercase().contains(HASH));
    assert!(!rendered.to_uppercase().contains(&OTHER.to_uppercase()));
    Ok(())
}

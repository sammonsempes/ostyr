#[path = "common/types.rs"]
mod types;


use intel_feeds::error::EntryError;
use intel_feeds::limits::MAX_LINE_BYTES;
use intel_feeds::lines::{numbered_lines, NumberedLine};
use std::io::{self, BufReader, Cursor, Read};
use types::TestResult;


const FIRST: u64 = 1;


const SECOND: u64 = 2;


const THIRD: u64 = 3;


const FOURTH: u64 = 4;


const INVALID_FIRST: u8 = 0xff;


const INVALID_SECOND: u8 = 0xfe;


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


struct FullThenBroken {
    sent: bool,
}


impl Read for FullThenBroken {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.sent {
            Err(io::Error::other("injected"))
        } else {
            self.sent = true;
            buffer.fill(b'x');
            Ok(buffer.len())
        }
    }
}


fn lines_of(bytes: Vec<u8>) -> io::Result<Vec<NumberedLine>> {
    numbered_lines(&mut Cursor::new(bytes)).collect()
}


fn text_of(line: &NumberedLine) -> Option<&str> {
    line.text.as_ref().ok().map(String::as_str)
}


#[test]
fn lines_are_numbered_and_stripped_of_their_terminator() -> TestResult {
    let lines = lines_of(b"a\r\nb\n\nlast".to_vec())?;
    let seen: Vec<(u64, Option<&str>)> = lines.iter().map(|line| (line.number, text_of(line))).collect();
    assert_eq!(
        seen,
        vec![(FIRST, Some("a")), (SECOND, Some("b")), (THIRD, Some("")), (FOURTH, Some("last"))]
    );
    Ok(())
}


#[test]
fn a_line_over_the_cap_is_skipped_to_its_end_and_reported() -> TestResult {
    let mut bytes = vec![b'x'; MAX_LINE_BYTES + 1];
    bytes.extend_from_slice(b"\nnext\n");
    let lines = lines_of(bytes)?;
    assert!(matches!(lines.first().map(|line| &line.text), Some(Err(EntryError::LineTooLong))));
    assert_eq!(lines.get(1).and_then(text_of), Some("next"));
    assert_eq!(lines.get(1).map(|line| line.number), Some(SECOND));
    Ok(())
}


#[test]
fn a_line_at_the_cap_is_kept_with_or_without_terminator() -> TestResult {
    let mut terminated = vec![b'y'; MAX_LINE_BYTES];
    terminated.push(b'\n');
    let unterminated = vec![b'z'; MAX_LINE_BYTES];
    assert_eq!(lines_of(terminated)?.first().and_then(text_of).map(str::len), Some(MAX_LINE_BYTES));
    assert_eq!(lines_of(unterminated)?.first().and_then(text_of).map(str::len), Some(MAX_LINE_BYTES));
    let unterminated_over = vec![b'z'; MAX_LINE_BYTES + 1];
    assert!(matches!(
        lines_of(unterminated_over)?.first().map(|line| &line.text),
        Some(Err(EntryError::LineTooLong))
    ));
    Ok(())
}


#[test]
fn invalid_utf8_is_reported_and_the_next_line_is_read() -> TestResult {
    let lines = lines_of(vec![INVALID_FIRST, INVALID_SECOND, b'\n', b'o', b'k', b'\n'])?;
    assert!(matches!(lines.first().map(|line| &line.text), Some(Err(EntryError::InvalidUtf8(_)))));
    assert_eq!(lines.get(1).and_then(text_of), Some("ok"));
    Ok(())
}


#[test]
fn read_errors_surface_from_the_read_and_from_the_skip() -> TestResult {
    assert!(numbered_lines(&mut BufReader::new(Broken)).collect::<io::Result<Vec<_>>>().is_err());
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 1, FullThenBroken { sent: false });
    assert!(numbered_lines(&mut reader).collect::<io::Result<Vec<_>>>().is_err());
    Ok(())
}

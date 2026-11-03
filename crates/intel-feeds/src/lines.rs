use crate::error::EntryError;
use crate::limits::MAX_LINE_BYTES;
use std::io::{self, BufRead, Read};


pub const NEWLINE: u8 = b'\n';


#[derive(Debug)]
pub struct NumberedLine {
    pub number: u64,
    pub text: Result<String, EntryError>,
}


pub fn decode_line(bytes: &[u8]) -> Result<String, EntryError> {
    std::str::from_utf8(bytes)
        .map(|text| text.trim_end_matches(['\n', '\r']).to_owned())
        .map_err(EntryError::InvalidUtf8)
}


/// Reads one line of at most `MAX_LINE_BYTES`; a longer line is skipped to its end and reported, never held in memory.
pub fn read_line(reader: &mut dyn BufRead, buffer: &mut Vec<u8>) -> io::Result<Option<Result<String, EntryError>>> {
    buffer.clear();
    let read = Read::take(&mut *reader, MAX_LINE_BYTES as u64 + 1).read_until(NEWLINE, buffer)?;
    let terminated = buffer.last() == Some(&NEWLINE);
    if read == 0 {
        Ok(None)
    } else if !terminated && read > MAX_LINE_BYTES {
        reader.skip_until(NEWLINE)?;
        Ok(Some(Err(EntryError::LineTooLong)))
    } else {
        Ok(Some(decode_line(buffer)))
    }
}


/// Numbered lines from 1; the first read error ends the use of the iterator by the consumer's `try_fold`.
pub fn numbered_lines(reader: &mut dyn BufRead) -> impl Iterator<Item = io::Result<NumberedLine>> + '_ {
    let mut buffer = Vec::new();
    let mut number = 0;
    std::iter::from_fn(move || {
        number += 1;
        read_line(reader, &mut buffer)
            .transpose()
            .map(|line| line.map(|text| NumberedLine { number, text }))
    })
}

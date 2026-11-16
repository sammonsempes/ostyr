use crate::error::ListError;
use crate::model::{Entry, Located, NtHash, DECIMAL_BASE, HASH_BYTES, HASH_HEX_LEN, MAX_LINE_BYTES};
use data_encoding::HEXLOWER_PERMISSIVE;
use zeroize::Zeroizing;


/// 32 hex digits (any case) as a hash.
pub fn decode_hash(hex: &[u8]) -> Option<NtHash> {
    if hex.len() == HASH_HEX_LEN {
        let mut bytes = Zeroizing::new([0u8; HASH_BYTES]);
        let decoded = HEXLOWER_PERMISSIVE.decode_mut(hex, bytes.as_mut_slice());
        decoded.is_ok().then_some(NtHash(bytes))
    } else {
        None
    }
}


/// A non-empty run of decimal digits that fits in a `u64`.
pub fn parse_count(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        None
    } else {
        digits.iter().try_fold(0u64, |total, byte| {
            let digit = char::from(*byte).to_digit(DECIMAL_BASE)?;
            total.checked_mul(u64::from(DECIMAL_BASE))?.checked_add(u64::from(digit))
        })
    }
}


/// `<32 hex>:<decimal count>` without its newline (a trailing CR is dropped).
pub fn parse_line(line: &[u8], offset: u64) -> Result<(NtHash, u64), ListError> {
    let text = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = text.split(|byte| *byte == b':');
    let fields = (parts.next(), parts.next(), parts.next());
    let parsed = match fields {
        (Some(hash), Some(count), None) => decode_hash(hash).zip(parse_count(count)),
        _ => None,
    };
    parsed.ok_or(ListError::Malformed { offset })
}


/// The index of the first line start in the window: 0 when the window starts on a line, else after the first newline.
pub fn first_line_start(window: &[u8], read_offset: u64, aligned: bool, at_eof: bool) -> Result<Option<usize>, ListError> {
    if aligned {
        Ok(Some(0))
    } else {
        match window.iter().position(|byte| *byte == b'\n') {
            Some(position) => Ok(Some(position + 1)),
            None if at_eof => Ok(None),
            None => Err(ListError::LineTooLong { offset: read_offset }),
        }
    }
}


/// The length of the line before its newline, bounded by `MAX_LINE_BYTES`.
pub fn terminated_length(rest: &[u8], start: u64, at_eof: bool) -> Result<usize, ListError> {
    match rest.iter().position(|byte| *byte == b'\n') {
        Some(length) if length <= MAX_LINE_BYTES => Ok(length),
        Some(_) => Err(ListError::LineTooLong { offset: start }),
        None if at_eof => Err(ListError::Unterminated { offset: start }),
        None => Err(ListError::LineTooLong { offset: start }),
    }
}


/// The first whole line starting at the window's start (`aligned`) or after its first newline.
pub fn locate(window: &[u8], read_offset: u64, aligned: bool, at_eof: bool) -> Result<Located, ListError> {
    match first_line_start(window, read_offset, aligned, at_eof)? {
        None => Ok(Located::Missing),
        Some(index) => {
            let tail: Zeroizing<Vec<u8>> = Zeroizing::new(window.iter().skip(index).copied().collect());
            if tail.is_empty() && at_eof {
                Ok(Located::Missing)
            } else {
                let start = read_offset + index as u64;
                let length = terminated_length(&tail, start, at_eof)?;
                let line: Zeroizing<Vec<u8>> = Zeroizing::new(tail.iter().take(length).copied().collect());
                let (hash, count) = parse_line(&line, start)?;
                Ok(Located::Line(Entry {
                    start,
                    next: start + length as u64 + 1,
                    hash,
                    count,
                }))
            }
        }
    }
}

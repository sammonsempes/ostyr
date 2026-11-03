use crate::canonical::{compute_hash, render_line};
use crate::error::{AuditError, BrokenReason};
use crate::model::{Record, GENESIS_HASH};
use std::io::{self, BufRead};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: usize,
    pub head: String,
}


/// Parses one stored line and checks form, chain link and hash; returns the record.
pub fn check_line(bytes: &[u8], previous_hash: &str) -> Result<Record, BrokenReason> {
    bytes.strip_suffix(b"\n").ok_or(BrokenReason::Unterminated)?;
    let record: Record = serde_json::from_slice(bytes).map_err(BrokenReason::Malformed)?;
    let canonical = render_line(&record).as_bytes() == bytes;
    let linked = record.previous_hash == previous_hash;
    let hashed = compute_hash(&record) == record.hash;
    match (canonical, linked, hashed) {
        (false, _, _) => Err(BrokenReason::NonCanonical),
        (true, false, _) => Err(BrokenReason::ChainMismatch),
        (true, true, false) => Err(BrokenReason::HashMismatch),
        (true, true, true) => Ok(record),
    }
}


/// Raw lines including their newline; an I/O error is yielded as an item and stops a `try_fold`.
pub fn raw_lines<Input: BufRead>(mut input: Input) -> impl Iterator<Item = io::Result<Vec<u8>>> {
    std::iter::from_fn(move || {
        let mut line = Vec::new();
        match input.read_until(b'\n', &mut line) {
            Ok(0) => None,
            Ok(_) => Some(Ok(line)),
            Err(error) => Some(Err(error)),
        }
    })
}


/// Reports the first broken record by 1-based line; `expected_head` also refuses a truncated tail.
pub fn verify<Input: BufRead>(input: Input, expected_head: Option<&str>) -> Result<VerifyReport, AuditError> {
    let (records, head) = raw_lines(input)
        .enumerate()
        .try_fold((0, GENESIS_HASH.to_owned()), |(_, previous), (index, line)| {
            let bytes = line?;
            let line_number = index + 1;
            check_line(&bytes, &previous)
                .map(|record| (line_number, record.hash))
                .map_err(|reason| AuditError::Broken { line: line_number, reason })
        })?;
    check_head(expected_head, head).map(|actual| VerifyReport { records, head: actual })
}


/// Passes the head through when no anchor is given or it matches the anchor.
pub fn check_head(expected_head: Option<&str>, head: String) -> Result<String, AuditError> {
    match expected_head {
        Some(expected) if expected != head => Err(AuditError::HeadMismatch {
            expected: expected.to_owned(),
            actual: head,
        }),
        _ => Ok(head),
    }
}

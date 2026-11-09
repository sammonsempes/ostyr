//! Bounded reading and line classification shared by every parser.

use crate::error::InventoryError;
use crate::model::{Limits, Outcome, Scanned, SkipReason};
use std::collections::BTreeMap;
use std::io::Read;


const NEWLINE: u8 = b'\n';


pub fn read_input<Source: Read>(reader: Source, limits: &Limits) -> Result<Vec<u8>, InventoryError> {
    let mut buffer = Vec::new();
    reader.take((limits.max_bytes as u64).saturating_add(1)).read_to_end(&mut buffer)?;
    if buffer.len() > limits.max_bytes {
        Err(InventoryError::TooLarge { limit: limits.max_bytes })
    } else {
        Ok(buffer)
    }
}


pub fn classify<Item>(buffer: &[u8], limits: &Limits, parse: impl Fn(&str) -> Outcome<Item>) -> Result<Scanned<Item>, InventoryError> {
    let line_count = buffer.split(|byte| *byte == NEWLINE).count();
    if line_count > limits.max_lines {
        Err(InventoryError::TooManyLines { limit: limits.max_lines })
    } else {
        Ok(buffer
            .split(|byte| *byte == NEWLINE)
            .map(|line| outcome_of(line, limits, &parse))
            .take_while(|outcome| !matches!(outcome, Outcome::Stop))
            .fold(
                Scanned {
                    records: Vec::new(),
                    skipped: BTreeMap::new(),
                },
                |mut scanned, outcome| {
                    match outcome {
                        Outcome::Record(item) => scanned.records.push(item),
                        Outcome::Skipped(reason) => *scanned.skipped.entry(reason).or_insert(0) += 1,
                        Outcome::Ignored | Outcome::Stop => {}
                    }
                    scanned
                },
            ))
    }
}


pub fn outcome_of<Item>(line: &[u8], limits: &Limits, parse: &impl Fn(&str) -> Outcome<Item>) -> Outcome<Item> {
    match std::str::from_utf8(line) {
        _ if line.len() > limits.max_line_bytes => Outcome::Skipped(SkipReason::LineTooLong),
        Err(_) => Outcome::Skipped(SkipReason::Malformed),
        Ok(text) => {
            let trimmed = text.strip_suffix('\r').unwrap_or(text);
            if trimmed.chars().any(char::is_control) {
                Outcome::Skipped(SkipReason::ControlCharacters)
            } else {
                parse(trimmed)
            }
        }
    }
}

//! The one pre-scan of a JSON list: its elements are counted byte by byte against a cap before any of them is materialised.

use serde_json::error::Category;
use serde_json::value::RawValue;
use thiserror::Error;


/// Fixed text only: serde's own message repeats the offending value, which is peer text.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("more elements than the cap")]
    TooMany,
    #[error("invalid JSON ({category:?} at line {line} column {column})")]
    Json { category: Category, line: usize, column: usize },
}


#[derive(Debug, Clone, Copy, Default)]
pub struct ScanState {
    pub depth: usize,
    pub in_string: bool,
    pub escaped: bool,
    pub commas: usize,
    pub cap: usize,
}


pub fn scan_start(cap: usize) -> ScanState {
    ScanState { cap, ..ScanState::default() }
}


/// Category, line and column only.
pub fn json_error(error: &serde_json::Error) -> ScanError {
    ScanError::Json {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// Counts the commas of the top-level list byte by byte; more than `state.cap` elements is refused at the comma that proves it.
pub fn scan_byte(state: ScanState, byte: u8) -> Result<ScanState, ScanError> {
    if state.in_string {
        Ok(ScanState {
            escaped: !state.escaped && byte == b'\\',
            in_string: state.escaped || byte != b'"',
            ..state
        })
    } else {
        match byte {
            b'"' => Ok(ScanState { in_string: true, ..state }),
            b'[' | b'{' => Ok(ScanState {
                depth: state.depth.saturating_add(1),
                ..state
            }),
            b']' | b'}' => Ok(ScanState {
                depth: state.depth.saturating_sub(1),
                ..state
            }),
            b',' if state.depth == 1 && state.commas + 1 >= state.cap => Err(ScanError::TooMany),
            b',' if state.depth == 1 => Ok(ScanState {
                commas: state.commas + 1,
                ..state
            }),
            _ => Ok(state),
        }
    }
}


/// The elements of a raw list as raw text, at most `cap` of them, counted before the vector is built.
pub fn raw_elements(list: &RawValue, cap: usize) -> Result<Vec<&RawValue>, ScanError> {
    list.get().bytes().try_fold(scan_start(cap), scan_byte)?;
    let elements: Vec<&RawValue> = serde_json::from_str(list.get()).map_err(|error| json_error(&error))?;
    if elements.len() > cap {
        Err(ScanError::TooMany)
    } else {
        Ok(elements)
    }
}

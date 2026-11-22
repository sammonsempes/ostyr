//! Missing Windows updates from the Windows Update Agent search envelope (see `wua_script`).

use crate::error::WindowsError;
use crate::limits::MAX_WINDOWS_UPDATES;
use crate::model::{Device, Limits, WindowsInventory, WindowsSkip};
use crate::scan::read_input;
use crate::types::{UpdatesById, WindowsSkipCounts};
use crate::wua_wire::{decode_update, is_object, Counted, Envelope};
use serde_json::value::RawValue;
use std::collections::btree_map::Entry;
use std::io::Read;


pub const RESULT_SUCCEEDED: i64 = 2;


pub const RESULT_SUCCEEDED_WITH_ERRORS: i64 = 3;


#[derive(Debug, Default)]
pub struct Collected {
    pub updates: UpdatesById,
    pub skipped: WindowsSkipCounts,
}


pub fn parse_windows_updates<Source: Read>(device: &Device, reader: Source, limits: &Limits) -> Result<WindowsInventory, WindowsError> {
    let buffer = read_input(reader, limits)?;
    let text = ascii_text(&buffer)?;
    let malformed = |error: serde_json::Error| WindowsError::Malformed {
        line: error.line(),
        column: error.column(),
    };
    if !is_object(text) {
        Err(WindowsError::Malformed { line: 1, column: 1 })?;
    }
    let counted: Counted = serde_json::from_str(text).map_err(malformed)?;
    let partial = match counted.result_code {
        RESULT_SUCCEEDED => Ok(false),
        RESULT_SUCCEEDED_WITH_ERRORS => Ok(true),
        code => Err(WindowsError::SearchFailed { code }),
    }?;
    let count = counted.updates.ok_or(WindowsError::Malformed { line: 1, column: 1 })?.len();
    if count > MAX_WINDOWS_UPDATES {
        Err(WindowsError::TooManyUpdates { limit: MAX_WINDOWS_UPDATES })
    } else {
        let envelope: Envelope = serde_json::from_str(text).map_err(malformed)?;
        let collected = envelope
            .updates
            .into_iter()
            .fold(Collected::default(), |state, element| add_element(device, state, element));
        Ok(WindowsInventory {
            updates: collected.updates.into_values().collect(),
            skipped: collected.skipped,
            partial,
        })
    }
}


pub fn ascii_text(buffer: &[u8]) -> Result<&str, WindowsError> {
    let text = std::str::from_utf8(buffer).map_err(|_| WindowsError::NotAscii)?;
    if !text.chars().all(|character| matches!(character, ' '..='~' | '\t' | '\r' | '\n')) {
        Err(WindowsError::NotAscii)
    } else if text.trim().is_empty() {
        Err(WindowsError::NoOutput)
    } else {
        Ok(text)
    }
}


pub fn add_element(device: &Device, mut state: Collected, element: &RawValue) -> Collected {
    match decode_update(device, element.get()) {
        Err(reason) => bump(&mut state.skipped, reason),
        Ok(decoded) => {
            if decoded.unknown_severity {
                bump(&mut state.skipped, WindowsSkip::UnknownSeverity);
            }
            match state.updates.entry(decoded.update.update_id.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(decoded.update);
                }
                Entry::Occupied(mut slot) => {
                    bump(&mut state.skipped, WindowsSkip::Duplicate);
                    if slot.get().revision < decoded.update.revision {
                        slot.insert(decoded.update);
                    }
                }
            }
        }
    }
    state
}


pub fn bump(skipped: &mut WindowsSkipCounts, reason: WindowsSkip) {
    *skipped.entry(reason).or_insert(0) += 1;
}

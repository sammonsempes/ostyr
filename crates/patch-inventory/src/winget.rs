//! Updatable winget packages from the `Get-WinGetPackage` envelope (see `winget_script`).

use crate::error::{WindowsError, WingetError};
use crate::limits::MAX_WINGET_UPDATES;
use crate::model::{Device, Limits, WingetInventory, WingetSkip};
use crate::scan::read_input;
use crate::types::{UpdatesByPackage, WingetSkipCounts};
use crate::windows::ascii_text;
use crate::winget_wire::{decode_package, is_object, Counted, Envelope};
use serde_json::value::RawValue;
use std::collections::btree_map::Entry;
use std::io::Read;


#[derive(Debug, Default)]
pub struct Collected {
    pub updates: UpdatesByPackage,
    pub skipped: WingetSkipCounts,
}


pub fn parse_winget_updates<Source: Read>(device: &Device, reader: Source, limits: &Limits) -> Result<WingetInventory, WingetError> {
    let buffer = read_input(reader, limits)?;
    let text = ascii_text(&buffer).map_err(refusal_of)?;
    let malformed = |error: serde_json::Error| WingetError::Malformed {
        line: error.line(),
        column: error.column(),
    };
    if !is_object(text) {
        Err(WingetError::Malformed { line: 1, column: 1 })?;
    }
    let counted: Counted = serde_json::from_str(text).map_err(malformed)?;
    let count = counted.updates.ok_or(WingetError::Malformed { line: 1, column: 1 })?.len();
    if count > MAX_WINGET_UPDATES {
        Err(WingetError::TooManyUpdates { limit: MAX_WINGET_UPDATES })
    } else {
        let envelope: Envelope = serde_json::from_str(text).map_err(malformed)?;
        let collected = envelope
            .updates
            .into_iter()
            .fold(Collected::default(), |state, element| add_element(device, state, element));
        Ok(WingetInventory {
            updates: collected.updates.into_values().collect(),
            skipped: collected.skipped,
        })
    }
}


pub fn refusal_of(error: WindowsError) -> WingetError {
    match error {
        WindowsError::NoOutput => WingetError::NoOutput,
        _ => WingetError::NotAscii,
    }
}


pub fn add_element(device: &Device, mut state: Collected, element: &RawValue) -> Collected {
    match decode_package(device, element.get()) {
        Err(reason) => bump(&mut state.skipped, reason),
        Ok(decoded) => {
            if decoded.unknown_installed {
                bump(&mut state.skipped, WingetSkip::UnknownInstalledVersion);
            }
            if decoded.other_source {
                bump(&mut state.skipped, WingetSkip::OtherSource);
            }
            match state.updates.entry(decoded.update.package.to_ascii_lowercase()) {
                Entry::Vacant(slot) => {
                    slot.insert(decoded.update);
                }
                Entry::Occupied(_) => bump(&mut state.skipped, WingetSkip::Duplicate),
            }
        }
    }
    state
}


pub fn bump(skipped: &mut WingetSkipCounts, reason: WingetSkip) {
    *skipped.entry(reason).or_insert(0) += 1;
}

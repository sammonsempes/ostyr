//! Expectations file, strict parse of `systemctl show` for one unit, and the health of a unit.

use crate::error::NtpError;
use crate::grammar::{is_sub_state, is_unit_name};
use crate::limits::{MAX_EXPECTATIONS_BYTES, MAX_FLAP_RESTARTS, MAX_UNITS};
use crate::model::{ActiveState, Expectation, ExpectationsFile, LoadState, UnitFileState, UnitHealth, UnitState};
use crate::parse::read_bounded;
use core_config::parse::parse_document;
use std::collections::BTreeMap;
use std::io::Read;


pub const SHOW_KEYS: [&str; 7] = [
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "NRestarts",
    "ExecMainStatus",
];


pub fn load_expectations(text: &str, file: &str) -> Result<Vec<Expectation>, NtpError> {
    if text.len() > MAX_EXPECTATIONS_BYTES {
        Err(NtpError::Oversized {
            limit: MAX_EXPECTATIONS_BYTES as u64,
        })
    } else {
        let document: ExpectationsFile = parse_document(text, file)?;
        if document.units.len() > MAX_UNITS {
            Err(NtpError::OutOfRange { field: "units" })
        } else {
            document.units.iter().try_for_each(check_expectation)?;
            Ok(document.units)
        }
    }
}


fn check_expectation(expectation: &Expectation) -> Result<(), NtpError> {
    if !is_unit_name(&expectation.unit) {
        Err(NtpError::OutOfRange { field: "unit" })
    } else if !(1..=MAX_FLAP_RESTARTS).contains(&expectation.flap_restarts) {
        Err(NtpError::OutOfRange { field: "flap_restarts" })
    } else {
        Ok(())
    }
}


pub fn load_state(text: &str) -> Option<LoadState> {
    match text {
        "loaded" => Some(LoadState::Loaded),
        "not-found" => Some(LoadState::NotFound),
        "masked" => Some(LoadState::Masked),
        "error" => Some(LoadState::Error),
        "bad-setting" => Some(LoadState::BadSetting),
        "stub" => Some(LoadState::Stub),
        "merged" => Some(LoadState::Merged),
        _ => None,
    }
}


pub fn active_state(text: &str) -> Option<ActiveState> {
    match text {
        "active" => Some(ActiveState::Active),
        "inactive" => Some(ActiveState::Inactive),
        "failed" => Some(ActiveState::Failed),
        "activating" => Some(ActiveState::Activating),
        "deactivating" => Some(ActiveState::Deactivating),
        "reloading" => Some(ActiveState::Reloading),
        "maintenance" => Some(ActiveState::Maintenance),
        "refreshing" => Some(ActiveState::Refreshing),
        _ => None,
    }
}


fn file_state(text: &str) -> Option<UnitFileState> {
    match text {
        "enabled" => Some(UnitFileState::Enabled),
        "enabled-runtime" => Some(UnitFileState::EnabledRuntime),
        "linked" => Some(UnitFileState::Linked),
        "linked-runtime" => Some(UnitFileState::LinkedRuntime),
        "alias" => Some(UnitFileState::Alias),
        "masked" => Some(UnitFileState::Masked),
        "masked-runtime" => Some(UnitFileState::MaskedRuntime),
        "static" => Some(UnitFileState::Static),
        "indirect" => Some(UnitFileState::Indirect),
        "disabled" => Some(UnitFileState::Disabled),
        "generated" => Some(UnitFileState::Generated),
        "transient" => Some(UnitFileState::Transient),
        "bad" => Some(UnitFileState::Bad),
        "" => Some(UnitFileState::Empty),
        _ => None,
    }
}


pub fn count(text: &str) -> Result<u32, NtpError> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    digits
        .then_some(text)
        .and_then(|digits_only| digits_only.parse::<u32>().ok())
        .ok_or(NtpError::Malformed { reason: "bad counter" })
}


/// Splits on `\n` only into `key=value` pairs; a key outside `keys`, a repeated key or a value ending in `\r` is `Malformed`.
pub fn collect_pairs<'a>(text: &'a str, keys: &[&str]) -> Result<BTreeMap<&'a str, &'a str>, NtpError> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    text.split_terminator('\n').try_for_each(|line| {
        let (key, value) = line
            .split_once('=')
            .filter(|(key, value)| keys.contains(key) && !value.ends_with('\r'))
            .ok_or(NtpError::Malformed { reason: "unexpected line" })?;
        match seen.insert(key, value) {
            Some(_) => Err(NtpError::Malformed { reason: "duplicate key" }),
            None => Ok(()),
        }
    })?;
    Ok(seen)
}


/// Exactly the seven requested keys, each once, `Id` equal to `expected_unit`; a value outside its known set is `None` and counted.
pub fn parse_unit_show<Input: Read>(mut reader: Input, max_bytes: u64, expected_unit: &str) -> Result<UnitState, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let pairs = collect_pairs(&text, &SHOW_KEYS)?;
    let field = |key: &str| pairs.get(key).copied().ok_or(NtpError::Malformed { reason: "missing key" });
    if field("Id")? != expected_unit {
        Err(NtpError::Malformed { reason: "unexpected unit" })
    } else {
        let load = load_state(field("LoadState")?);
        let active = active_state(field("ActiveState")?);
        let sub_state = Some(field("SubState")?).filter(|value| is_sub_state(value)).map(str::to_string);
        let file = file_state(field("UnitFileState")?);
        let unknown_values =
            usize::from(load.is_none()) + usize::from(active.is_none()) + usize::from(sub_state.is_none()) + usize::from(file.is_none());
        Ok(UnitState {
            load,
            active,
            sub_state,
            file_state: file,
            restarts: count(field("NRestarts")?)?,
            exec_main_status: count(field("ExecMainStatus")?)?,
            unknown_values,
        })
    }
}


/// Precedence: NotFound > Failed > Flapping > Stopped > Disabled > Healthy. A restarting unit is `activating`, so Flapping outranks Stopped.
pub fn assess_unit(expectation: &Expectation, previous: Option<&UnitState>, current: &UnitState) -> UnitHealth {
    let grown = previous.and_then(|before| current.restarts.checked_sub(before.restarts));
    let flapping = grown.filter(|restarts| *restarts >= expectation.flap_restarts);
    let enabled = matches!(current.file_state, Some(UnitFileState::Enabled | UnitFileState::EnabledRuntime));
    if current.load == Some(LoadState::NotFound) {
        UnitHealth::NotFound
    } else if current.active == Some(ActiveState::Failed) {
        UnitHealth::Failed
    } else if let Some(restarts) = flapping {
        UnitHealth::Flapping { restarts }
    } else if expectation.should_run && current.active != Some(ActiveState::Active) {
        UnitHealth::Stopped
    } else if expectation.should_be_enabled && !enabled {
        UnitHealth::Disabled
    } else {
        UnitHealth::Healthy
    }
}

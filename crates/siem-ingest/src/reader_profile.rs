//! What a ClickHouse reader may trust about its own user: pins in each statement's `SETTINGS` clause and a check of the changed settings.

use crate::types::Limits;
use std::io::{self, Read};


/// `readonly=2`: a write is still refused, but the in-query `SETTINGS` pins may differ from the profile (under `readonly=1` ClickHouse 26.8 refuses them).
pub const READONLY_VALUE: &str = "2";


pub const EXCEPTION_IN_BODY: &str = "0";


pub const OVERFLOW_MODE: &str = "throw";


/// Every `*_overflow_mode` of ClickHouse 26.8 (`SELECT name FROM system.settings WHERE name LIKE '%overflow_mode%'` lists exactly these).
pub const OVERFLOW_MODES: [&str; 11] = [
    "timeout_overflow_mode",
    "timeout_overflow_mode_leaf",
    "read_overflow_mode",
    "read_overflow_mode_leaf",
    "group_by_overflow_mode",
    "result_overflow_mode",
    "sort_overflow_mode",
    "set_overflow_mode",
    "distinct_overflow_mode",
    "join_overflow_mode",
    "transfer_overflow_mode",
];


/// Profile settings that cut or reshape a reply without an error, reset to no effect.
pub const RESET_SETTINGS: [(&str, &str); 6] = [
    ("limit", "0"),
    ("offset", "0"),
    ("additional_result_filter", "''"),
    ("filter", "''"),
    ("additional_table_filters", "{}"),
    ("date_time_output_format", "'simple'"),
];


pub const RESULT_ROWS: &str = "max_result_rows";


pub const RESULT_OVERFLOW_MODE: &str = "result_overflow_mode";


/// The settings-check statement may list this many names (the server throws above it) and its reply is read through `CHECK_MAX_BYTES`.
pub const CHECK_MAX_ROWS: u64 = 64;


pub const CHECK_MAX_BYTES: u64 = 4096;


/// Settings a reader's profile may legitimately change: the default database (metric-alerts and hunt-packs name their tables unqualified).
pub const PROFILE_ALLOWED: [&str; 1] = ["database"];


/// Exception codes that mean the profile refused or cut the check itself: rows (158, 396), read-only (164), constraint (452).
pub const PROFILE_CODES: [u32; 4] = [158, 164, 396, 452];


/// The two settings the URL carries: `readonly` (a query may not change it) and the exception format.
pub fn url_settings() -> Vec<(&'static str, String)> {
    vec![
        ("readonly", READONLY_VALUE.to_owned()),
        ("http_write_exception_in_output_format", EXCEPTION_IN_BODY.to_owned()),
    ]
}


/// Every pin of one statement, in order: the reader's limits, the result rows, every overflow mode `throw`, every reset.
pub fn pins(limits: Limits<'_>, result_rows: u64) -> Vec<(&'static str, String)> {
    let mode = format!("'{OVERFLOW_MODE}'");
    limits
        .iter()
        .cloned()
        .chain([(RESULT_ROWS, result_rows.to_string())])
        .chain(OVERFLOW_MODES.iter().map(|name| (*name, mode.clone())))
        .chain(RESET_SETTINGS.iter().map(|(name, value)| (*name, (*value).to_owned())))
        .collect()
}


/// The pins as ` SETTINGS a = b, ...`, to put before `FORMAT`.
pub fn pin_clause(limits: Limits<'_>, result_rows: u64) -> String {
    let listed: Vec<String> = pins(limits, result_rows)
        .iter()
        .map(|(name, value)| format!("{name} = {value}"))
        .collect();
    format!(" SETTINGS {}", listed.join(", "))
}


/// What the check statement itself pins: its row cap and the one overflow mode that could cut its own reply.
pub fn check_pins() -> Vec<(&'static str, String)> {
    vec![
        (RESULT_ROWS, CHECK_MAX_ROWS.to_string()),
        (RESULT_OVERFLOW_MODE, format!("'{OVERFLOW_MODE}'")),
    ]
}


/// The first statement of every read: the changed settings, one name per line; it pins only `check_pins`, so a profile's other pins show.
pub fn changed_statement() -> String {
    let listed: Vec<String> = check_pins().iter().map(|(name, value)| format!("{name} = {value}")).collect();
    format!(
        "SELECT `name` FROM `system`.`settings` WHERE `changed` SETTINGS {} FORMAT TabSeparated",
        listed.join(", ")
    )
}


/// The reply of the check is read through `CHECK_MAX_BYTES + 1` bytes.
pub fn read_changed_bytes<Source: Read>(reader: Source) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(CHECK_MAX_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}


/// True for an error reply of the check that the user's profile caused.
pub fn profile_refused(code: Option<u32>) -> bool {
    code.is_some_and(|found| PROFILE_CODES.contains(&found))
}


/// Names outside the allowed list, required names missing (an unfiltered `system.settings` lists them all), plus one for an oversized reply.
pub fn violations(bytes: &[u8], limits: Limits<'_>) -> usize {
    let checked: Vec<&str> = check_pins().iter().map(|(name, _)| *name).collect();
    let url: Vec<&str> = url_settings().iter().map(|(name, _)| *name).collect();
    let own: Vec<&str> = limits.iter().map(|(name, _)| *name).collect();
    let text = String::from_utf8_lossy(bytes);
    let listed: Vec<&str> = text.lines().collect();
    let outside = listed
        .iter()
        .filter(|name| !checked.contains(name) && !url.contains(name) && !own.contains(name) && !PROFILE_ALLOWED.contains(name))
        .count();
    let missing = checked.iter().chain(url.iter().take(1)).filter(|name| !listed.contains(name)).count();
    outside + missing + usize::from(bytes.len() as u64 > CHECK_MAX_BYTES)
}

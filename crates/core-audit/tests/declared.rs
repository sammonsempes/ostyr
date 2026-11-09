#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::ecs::export;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, genesis_log, MAX_KEY_BYTES, MAX_PARAMETERS};
use core_audit::model::NewEntry;
use core_audit::verify::verify;
use core_redact::value::REDACTED;
use sample::entry;
use std::io::Cursor;
use types::TestResult;


const SECRETS: [(&str, &str); 4] = [
    ("note_a", "hunter2-clear-password"),
    ("note_b", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"),
    ("note_c", "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\n-----END PRIVATE KEY-----"),
    ("note_d", "k9Zq7Xw2Lm4Pv8Rt"),
];


#[test]
fn undeclared_keys_are_redacted_in_log_and_export() -> TestResult {
    let log = genesis_log(Vec::new());
    let mut new_entry = entry(0)?;
    new_entry.parameters = SECRETS.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect();
    new_entry.parameters.insert("name".to_owned(), "visible".to_owned());
    new_entry.parameters.insert("header".to_owned(), "Bearer abc123token".to_owned());
    let record = append_declared(&log, new_entry, &["name", "header"])?;
    let bytes = log.state.lock().map_err(|_| "poisoned")?.writer.clone();
    let mut exported = Vec::new();
    export(|| Ok(Cursor::new(bytes.clone())), &mut exported, None)?;
    let text = format!("{}{}", String::from_utf8(bytes.clone())?, String::from_utf8(exported)?);
    SECRETS.iter().for_each(|(_, secret)| assert!(!text.contains(secret)));
    assert!(!text.contains("abc123token"));
    assert_eq!(record.parameters.get("note_a").map(String::as_str), Some(REDACTED));
    assert_eq!(record.parameters.get("name").map(String::as_str), Some("visible"));
    assert!(text.contains("visible"));
    assert_eq!(verify(Cursor::new(bytes), None)?.head, record.hash);
    Ok(())
}


const SHORT_KEY: usize = 4;


fn with_parameters(count: usize, key_length: usize) -> Result<NewEntry, Box<dyn std::error::Error>> {
    let mut new_entry = entry(0)?;
    new_entry.parameters = (0..count).map(|index| (format!("{index:0>key_length$}"), "v".to_owned())).collect();
    Ok(new_entry)
}


#[test]
fn parameter_count_cap_holds_at_equality_and_refuses_one_over() -> TestResult {
    let log = genesis_log(Vec::new());
    append_declared(&log, with_parameters(MAX_PARAMETERS, SHORT_KEY)?, &[])?;
    let refused = append_declared(&log, with_parameters(MAX_PARAMETERS + 1, SHORT_KEY)?, &[]);
    assert!(matches!(refused, Err(AuditError::TooManyParameters { count, max }) if count == MAX_PARAMETERS + 1 && max == MAX_PARAMETERS));
    Ok(())
}


#[test]
fn key_length_cap_holds_at_equality_and_refuses_one_over() -> TestResult {
    let log = genesis_log(Vec::new());
    append_declared(&log, with_parameters(1, MAX_KEY_BYTES)?, &[])?;
    let refused = append_declared(&log, with_parameters(1, MAX_KEY_BYTES + 1)?, &[]);
    assert!(matches!(refused, Err(AuditError::KeyTooLong { length, max }) if length == MAX_KEY_BYTES + 1 && max == MAX_KEY_BYTES));
    assert!(refused.is_err_and(|error| error.to_string().contains("128")));
    Ok(())
}

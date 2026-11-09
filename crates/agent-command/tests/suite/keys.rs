use crate::common::types::TestResult;
use crate::common::{engine_at, key_entry, keys_text, public_hex, replace_file, KEY_COUNT, LIFETIME, NOW, ROUTINE_SEED, SECOND, SEED_LENGTH};
use agent_command::error::KeyFileError;
use agent_command::keys::{keys_state, parse_public_key, trusted_key};
use agent_command::model::{KeyClass, RawKey};
use core_config::reload::{current_config, reload, ReloadOutcome};
use tempfile::tempdir;


fn engine_error(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, text)?;
    Ok(engine_at(&path).err().ok_or("the file was accepted")?.to_string())
}


fn raw(public_key: &str, not_before: u64, not_after: u64) -> RawKey {
    RawKey {
        id: "k".to_owned(),
        class: KeyClass::Routine,
        public_key: public_key.to_owned(),
        not_before,
        not_after,
        revoked: false,
    }
}


#[test]
fn a_valid_file_loads_with_both_classes() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &keys_text(false, NOW + LIFETIME))?;
    let engine = engine_at(&path)?;
    let keys = current_config(&engine);
    assert_eq!(keys.keys.get("routine-1").map(|key| key.class), Some(KeyClass::Routine));
    assert_eq!(keys.keys.get("sensitive-1").map(|key| key.class), Some(KeyClass::Sensitive));
    let state = keys_state(&keys);
    let line = state.get("keys.routine-1").ok_or("missing state")?;
    assert!(
        line.contains("class=routine") && line.contains("revoked=false") && line.contains(&public_hex(ROUTINE_SEED)),
        "{line}"
    );
    assert!(state.get("keys.sensitive-1").ok_or("missing state")?.contains("class=sensitive"));
    Ok(())
}


#[test]
fn unknown_fields_and_classes_are_refused() -> TestResult {
    let extra = format!("{}    comment: x\n", keys_text(false, NOW + LIFETIME));
    assert!(engine_error(&extra)?.contains("unknown field"));
    let class = keys_text(false, NOW + LIFETIME).replace("class: routine", "class: admin");
    assert!(engine_error(&class)?.contains("unknown variant"));
    assert!(engine_error("keys: []\nextra: 1\n")?.contains("unknown field"));
    Ok(())
}


#[test]
fn a_bad_public_key_names_the_key() -> TestResult {
    let text = |public: &str| format!("keys:\n  - id: bad\n    class: routine\n    public_key: {public}\n    not_before: 0\n    not_after: 1\n");
    assert!(engine_error(&text("zz"))?.contains("key `bad`: public key is not hexadecimal"));
    assert!(engine_error(&text("abcd"))?.contains("key `bad`: public key must be 32 bytes"));
    assert!(engine_error(&text(&"02".repeat(SEED_LENGTH)))?.contains("key `bad`: invalid public key"));
    Ok(())
}


#[test]
fn a_duplicate_id_and_an_inverted_period_are_refused() -> TestResult {
    let twice = format!(
        "keys:\n{}{}",
        key_entry("a", "routine", 1, 0, 1, false),
        key_entry("a", "sensitive", ROUTINE_SEED, 0, 1, false)
    );
    assert!(engine_error(&twice)?.contains("key `a` appears twice"));
    let inverted = format!("keys:\n{}", key_entry("a", "routine", 1, SECOND, 1, false));
    assert!(engine_error(&inverted)?.contains("not_before is after not_after"));
    Ok(())
}


#[test]
fn parsing_helpers_report_typed_errors() -> TestResult {
    assert!(matches!(parse_public_key("k", "zz"), Err(KeyFileError::Hex { .. })));
    assert!(matches!(parse_public_key("k", "ab"), Err(KeyFileError::Length { .. })));
    assert!(matches!(
        parse_public_key("k", &"02".repeat(SEED_LENGTH)),
        Err(KeyFileError::PublicKey { .. })
    ));
    assert!(matches!(trusted_key(&raw(&public_hex(1), SECOND, 1)), Err(KeyFileError::Validity { .. })));
    assert!(trusted_key(&raw(&public_hex(1), 1, 1)).is_ok());
    Ok(())
}


#[test]
fn a_reload_with_an_invalid_file_keeps_the_old_keys() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &keys_text(false, NOW + LIFETIME))?;
    let engine = engine_at(&path)?;
    replace_file(&path, "keys:\n  - id: x\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).keys.len(), KEY_COUNT);
    Ok(())
}


#[test]
fn the_same_public_key_under_two_ids_is_refused_at_load_and_at_reload() -> TestResult {
    let twice = format!(
        "keys:\n{}{}",
        key_entry("a", "routine", ROUTINE_SEED, 0, 1, false),
        key_entry("b", "sensitive", ROUTINE_SEED, 0, 1, false)
    );
    assert!(engine_error(&twice)?.contains("public key of `b` is already listed under `a`"));
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &keys_text(false, NOW + LIFETIME))?;
    let engine = engine_at(&path)?;
    replace_file(&path, &twice)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).keys.len(), KEY_COUNT);
    Ok(())
}

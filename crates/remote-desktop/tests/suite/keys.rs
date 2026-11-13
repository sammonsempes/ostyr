use crate::common::types::TestResult;
use crate::common::{
    agent_keys_text, engine_at, key_entry, public_hex, relay_keys_text, replace_file, valid_keys_text, AGENT_SEED, EARLIER, KEY_ID, LATER, LIFETIME,
    NOW, OTHER_SEED, RELAY_SEED,
};
use agent_command::model::TrustedKeys;
use core_config::load::load_file;
use core_config::reload::{current_config, reload, ReloadOutcome};
use remote_desktop::error::ShareError;
use remote_desktop::keys::{find_shared, keys_state, relay_key};
use remote_desktop::model::{RawKey, RelayClass};
use tempfile::tempdir;


fn engine_error(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, text)?;
    Ok(engine_at(&path, None).err().ok_or("the file was accepted")?.to_string())
}


fn raw(public_key: &str, not_before: u64, not_after: u64) -> RawKey {
    RawKey {
        id: "k".to_owned(),
        class: RelayClass::Relay,
        public_key: public_key.to_owned(),
        not_before,
        not_after,
        revoked: false,
    }
}


#[test]
fn a_valid_file_loads_and_describes_each_key() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &valid_keys_text())?;
    let engine = engine_at(&path, None)?;
    let keys = current_config(&engine);
    assert!(keys.keys.contains_key(KEY_ID));
    let state = keys_state(&keys);
    let line = state.get("keys.relay-1").ok_or("missing state")?;
    assert!(line.contains("revoked=false") && line.contains(&public_hex(RELAY_SEED)), "{line}");
    Ok(())
}


#[test]
fn unknown_fields_and_other_classes_are_refused() -> TestResult {
    let extra = format!("{}    comment: x\n", valid_keys_text());
    assert!(engine_error(&extra)?.contains("unknown field"));
    let routine = valid_keys_text().replace("class: relay", "class: routine");
    assert!(engine_error(&routine)?.contains("unknown variant"));
    let sensitive = valid_keys_text().replace("class: relay", "class: sensitive");
    assert!(engine_error(&sensitive)?.contains("unknown variant"));
    assert!(engine_error("keys: []\nextra: 1\n")?.contains("unknown field"));
    Ok(())
}


#[test]
fn bad_validity_duplicates_and_bad_public_keys_are_refused() -> TestResult {
    assert!(engine_error(&relay_keys_text(NOW + 1, NOW, false))?.contains("not_before is after not_after"));
    let duplicate = format!(
        "{}{}",
        valid_keys_text(),
        key_entry(KEY_ID, "relay", OTHER_SEED, NOW - LIFETIME, NOW + LIFETIME, false)
    );
    assert!(engine_error(&duplicate)?.contains("appears twice"));
    let same_key = format!(
        "{}{}",
        valid_keys_text(),
        key_entry("relay-2", "relay", RELAY_SEED, NOW - LIFETIME, NOW + LIFETIME, false)
    );
    assert!(engine_error(&same_key)?.contains("already listed under `relay-1`"));
    let short = valid_keys_text().replace(&public_hex(RELAY_SEED), "abcd");
    assert!(engine_error(&short)?.contains("must be 32 bytes"));
    let not_hex = valid_keys_text().replace(&public_hex(RELAY_SEED), "zz");
    assert!(engine_error(&not_hex)?.contains("not hexadecimal"));
    Ok(())
}


#[test]
fn relay_key_checks_the_validity_order_and_the_public_key() -> TestResult {
    assert!(relay_key(&raw(&public_hex(RELAY_SEED), EARLIER, LATER)).is_ok());
    assert!(relay_key(&raw(&public_hex(RELAY_SEED), LATER, EARLIER)).is_err());
    assert!(relay_key(&raw("zz", EARLIER, LATER)).is_err());
    Ok(())
}


#[test]
fn a_relay_file_sharing_an_id_with_the_agent_command_file_is_refused_at_load() -> TestResult {
    let dir = tempdir()?;
    let relay = dir.path().join("relay.yaml");
    let agent = dir.path().join("agent.yaml");
    replace_file(&relay, &valid_keys_text())?;
    replace_file(&agent, &agent_keys_text(KEY_ID, AGENT_SEED))?;
    let refusal = engine_at(&relay, Some(&agent)).err().ok_or("accepted")?.to_string();
    assert!(refusal.contains("key id `relay-1` is also an agent-command key id"), "{refusal}");
    Ok(())
}


#[test]
fn a_relay_file_sharing_a_public_key_with_the_agent_command_file_is_refused_at_load() -> TestResult {
    let dir = tempdir()?;
    let relay = dir.path().join("relay.yaml");
    let agent = dir.path().join("agent.yaml");
    replace_file(&relay, &valid_keys_text())?;
    replace_file(&agent, &agent_keys_text("routine-1", RELAY_SEED))?;
    let refusal = engine_at(&relay, Some(&agent)).err().ok_or("accepted")?.to_string();
    assert!(refusal.contains("public key of `relay-1` is also an agent-command key"), "{refusal}");
    Ok(())
}


#[test]
fn disjoint_files_load_and_a_missing_or_broken_agent_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let relay = dir.path().join("relay.yaml");
    let agent = dir.path().join("agent.yaml");
    replace_file(&relay, &valid_keys_text())?;
    replace_file(&agent, &agent_keys_text("routine-1", AGENT_SEED))?;
    assert!(engine_at(&relay, Some(&agent)).is_ok());
    replace_file(&agent, "keys: [")?;
    assert!(engine_at(&relay, Some(&agent)).is_err());
    let missing = dir.path().join("missing.yaml");
    assert!(engine_at(&relay, Some(&missing)).is_err());
    Ok(())
}


#[test]
fn a_reload_that_shares_a_key_is_refused_and_keeps_the_old_keys() -> TestResult {
    let dir = tempdir()?;
    let relay = dir.path().join("relay.yaml");
    let agent = dir.path().join("agent.yaml");
    replace_file(&relay, &valid_keys_text())?;
    replace_file(&agent, &agent_keys_text("routine-1", AGENT_SEED))?;
    let engine = engine_at(&relay, Some(&agent))?;
    replace_file(&agent, &agent_keys_text(KEY_ID, AGENT_SEED))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(current_config(&engine).keys.contains_key(KEY_ID));
    Ok(())
}


#[test]
fn find_shared_reports_nothing_for_disjoint_sets() -> TestResult {
    let dir = tempdir()?;
    let relay = dir.path().join("relay.yaml");
    let agent = dir.path().join("agent.yaml");
    replace_file(&relay, &valid_keys_text())?;
    replace_file(&agent, &agent_keys_text("routine-1", AGENT_SEED))?;
    let relay_keys = current_config(&*engine_at(&relay, None)?);
    let agent_keys = load_file::<TrustedKeys>(&agent)?;
    assert_eq!(find_shared(&relay_keys, &agent_keys), None);
    replace_file(&agent, &agent_keys_text(KEY_ID, AGENT_SEED))?;
    let same_id = load_file::<TrustedKeys>(&agent)?;
    assert_eq!(find_shared(&relay_keys, &same_id), Some(ShareError::SharedId { id: KEY_ID.to_owned() }));
    Ok(())
}

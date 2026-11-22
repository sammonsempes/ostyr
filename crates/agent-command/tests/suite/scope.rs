use crate::common::types::TestResult;
use crate::common::{
    engine_at, key_entry, public_hex, replace_file, sensitive_command, sensitive_envelope, verifier_with, NOW, ROUTINE_SEED, SENSITIVE_ID,
    SENSITIVE_SEED,
};
use agent_command::error::{CommandError, KeyFileError};
use agent_command::keys::{keys_state, scope_of, trusted_key_with};
use agent_command::model::{Action, KeyClass, PackageSelection, RawKey, RebootPolicy};
use agent_command::verify::verify_command;
use core_config::reload::{current_config, reload, ReloadOutcome};
use tempfile::tempdir;


const LAST_SEQUENCE: u64 = 0;


const BEFORE: u64 = 0;


const AFTER: u64 = u64::MAX;


fn scoped_text(actions: &str) -> String {
    format!(
        "keys:\n{}    actions: {actions}\n",
        key_entry(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, BEFORE, AFTER, false)
    )
}


fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}


fn raw(actions: Option<Vec<String>>) -> RawKey {
    RawKey {
        id: "k".to_owned(),
        class: KeyClass::Sensitive,
        public_key: public_hex(ROUTINE_SEED),
        not_before: 0,
        not_after: 1,
        revoked: false,
        actions,
    }
}


fn install() -> Action {
    Action::InstallUpdates {
        packages: PackageSelection::AllAllowed,
        reboot: RebootPolicy::Never,
    }
}


#[test]
fn a_scoped_key_signs_in_scope_and_is_refused_out_of_scope_without_burning_the_sequence() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &scoped_text("[install_updates, reboot]"))?;
    let verifier = verifier_with(engine_at(&path)?, LAST_SEQUENCE);
    let refused = verify_command(&verifier, &sensitive_envelope(&sensitive_command(1, Action::Isolate))?, NOW);
    assert!(matches!(refused, Err(CommandError::ActionOutOfScope("isolate"))), "{refused:?}");
    let accepted = verify_command(&verifier, &sensitive_envelope(&sensitive_command(1, install()))?, NOW);
    assert!(accepted.is_ok(), "{accepted:?}");
    Ok(())
}


#[test]
fn a_key_without_actions_signs_every_action_of_its_class() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(
        &path,
        &format!("keys:\n{}", key_entry(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, BEFORE, AFTER, false)),
    )?;
    let engine = engine_at(&path)?;
    let state = keys_state(&current_config(&engine));
    assert!(state.get("keys.sensitive-1").ok_or("state")?.contains("actions=all"));
    let verifier = verifier_with(engine, LAST_SEQUENCE);
    assert!(verify_command(&verifier, &sensitive_envelope(&sensitive_command(1, Action::Isolate))?, NOW).is_ok());
    Ok(())
}


#[test]
fn a_bad_actions_list_is_refused_at_load_and_the_old_keys_are_kept_on_reload() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    let other = dir.path().join("other.yaml");
    replace_file(&path, &scoped_text("[reboot]"))?;
    let engine = engine_at(&path)?;
    let before = keys_state(&current_config(&engine)).get("keys.sensitive-1").cloned();
    assert!(before.as_deref().is_some_and(|text| text.contains("actions=reboot")));
    ["[]", "[Reboot]", "[reboot, reboot]", "[nothing]"]
        .iter()
        .try_for_each(|bad| -> TestResult {
            replace_file(&path, &scoped_text(bad))?;
            assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }), "{bad}");
            assert_eq!(keys_state(&current_config(&engine)).get("keys.sensitive-1").cloned(), before);
            replace_file(&other, &scoped_text(bad))?;
            assert!(engine_at(&other).is_err(), "{bad}");
            Ok(())
        })
}


#[test]
fn scope_of_reports_each_refusal() -> TestResult {
    assert!(matches!(scope_of("k", &[], &[]), Err(KeyFileError::ActionsEmpty { .. })));
    assert!(matches!(scope_of("k", &names(&["x"]), &[]), Err(KeyFileError::ActionsUnknown { .. })));
    assert!(matches!(
        scope_of("k", &names(&["kill", "kill"]), &[]),
        Err(KeyFileError::ActionsDuplicate { .. })
    ));
    assert!(matches!(
        scope_of("k", &names(&["kill", "reboot"]), &["kill"]),
        Err(KeyFileError::ActionsExclusive { .. })
    ));
    assert!(scope_of("k", &names(&["kill"]), &["kill"]).is_ok());
    assert!(scope_of("k", &names(&["kill", "reboot"]), &["update"]).is_ok());
    Ok(())
}


#[test]
fn an_exclusive_kind_beside_another_kind_is_refused_for_a_key() -> TestResult {
    let both = raw(Some(names(&["reboot", "ping"])));
    assert!(matches!(trusted_key_with(&both, &["reboot"]), Err(KeyFileError::ActionsExclusive { .. })));
    assert!(trusted_key_with(&raw(Some(names(&["reboot"]))), &["reboot"]).is_ok());
    assert!(trusted_key_with(&raw(None), &["reboot"])?.actions.is_none());
    Ok(())
}

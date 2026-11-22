use crate::common::types::TestResult;
use crate::common::{
    engine_at, key_entry, public_hex, replace_file, sensitive_command, sensitive_envelope, verifier_with, NOW, ROUTINE_SEED, SENSITIVE_ID,
    SENSITIVE_SEED,
};
use agent_command::error::{CommandError, KeyFileError};
use agent_command::keys::{keys_state, scope_of, trusted_key_with};
use agent_command::model::{Action, KeyClass, PackageSelection, RawKey, RebootPolicy, Verifier, ACTION_NAMES, SENSITIVE_ACTION_NAMES};
use agent_command::verify::{action_is_sensitive, action_name, check_with, verify_command};
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::path::Path;
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


fn raw(actions: Option<Option<Vec<String>>>) -> RawKey {
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
    let both = raw(Some(Some(names(&["reboot", "ping"]))));
    assert!(matches!(trusted_key_with(&both, &["reboot"]), Err(KeyFileError::ActionsExclusive { .. })));
    assert!(trusted_key_with(&raw(Some(Some(names(&["reboot"])))), &["reboot"]).is_ok());
    assert!(trusted_key_with(&raw(None), &["reboot"])?.actions.is_none());
    Ok(())
}


fn reboot() -> Action {
    Action::Reboot {
        prompt_user: false,
        deadline: NOW,
    }
}


fn all_actions() -> Vec<Action> {
    vec![
        Action::Ping,
        Action::CollectStatus,
        Action::Isolate,
        Action::Kill { process_id: 1 },
        Action::RunScript { script: "s".to_owned() },
        Action::Update { version: "1".to_owned() },
        Action::Uninstall,
        Action::ChangePolicy { policy: "p".to_owned() },
        install(),
        reboot(),
        Action::OpenShell {
            session_id: "s".to_owned(),
            asset: "a".to_owned(),
            ticket: "t".to_owned(),
            requester: "r".to_owned(),
            approvers: Vec::new(),
            max_seconds: 1,
            idle_seconds: 1,
        },
    ]
}


fn no_hook(_verifier: &Verifier) {}


fn unscoped_text() -> String {
    format!("keys:\n{}", key_entry(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, BEFORE, AFTER, false))
}


#[test]
fn an_exclusive_kind_needs_a_key_scoped_to_exactly_that_kind() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    let exclusive = ["reboot"];
    let envelope = sensitive_envelope(&sensitive_command(1, reboot()))?;
    let other = sensitive_envelope(&sensitive_command(1, Action::Isolate))?;
    replace_file(&path, &unscoped_text())?;
    let unscoped = verifier_with(engine_at(&path)?, LAST_SEQUENCE);
    let refused = check_with(&unscoped, &envelope, NOW, &exclusive, &no_hook);
    assert!(matches!(refused, Err(CommandError::ActionOutOfScope("reboot"))), "{refused:?}");
    assert!(check_with(&unscoped, &other, NOW, &exclusive, &no_hook).is_ok());
    replace_file(&path, &scoped_text("[reboot]"))?;
    let scoped = verifier_with(engine_at(&path)?, LAST_SEQUENCE);
    assert!(check_with(&scoped, &envelope, NOW, &exclusive, &no_hook).is_ok());
    let beside = raw(Some(Some(names(&["reboot", "ping"]))));
    assert!(matches!(
        trusted_key_with(&beside, &exclusive),
        Err(KeyFileError::ActionsExclusive { .. })
    ));
    Ok(())
}


#[test]
fn a_present_but_null_actions_field_is_refused_at_load_and_on_reload() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    let other = dir.path().join("other.yaml");
    replace_file(&path, &scoped_text("[reboot]"))?;
    let engine = engine_at(&path)?;
    let before = keys_state(&current_config(&engine)).get("keys.sensitive-1").cloned();
    ["", "~", "null"].iter().try_for_each(|bad| -> TestResult {
        replace_file(&path, &scoped_text(bad))?;
        assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }), "{bad:?}");
        assert_eq!(keys_state(&current_config(&engine)).get("keys.sensitive-1").cloned(), before);
        replace_file(&other, &scoped_text(bad))?;
        assert!(engine_at(&other).is_err(), "{bad:?}");
        Ok(())
    })?;
    assert!(matches!(trusted_key_with(&raw(Some(None)), &[]), Err(KeyFileError::ActionsNull { .. })));
    Ok(())
}


fn swap_after_check(path: &Path, text: String) -> impl Fn(&Verifier) + '_ {
    move |verifier| {
        assert!(replace_file(path, &text).is_ok());
        assert!(matches!(reload(&verifier.keys), ReloadOutcome::Applied { .. }));
    }
}


#[test]
fn a_reload_between_the_check_and_the_lock_refuses_the_command() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    let envelope = sensitive_envelope(&sensitive_command(1, Action::Isolate))?;
    let key = |id: &str, class: &str, seed: u8, revoked: bool| format!("keys:\n{}", key_entry(id, class, seed, BEFORE, AFTER, revoked));
    let swaps = [
        (key(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, true), "revoked"),
        (scoped_text("[reboot]"), "narrowed"),
        (key(SENSITIVE_ID, "sensitive", ROUTINE_SEED, false), "replaced"),
        (key(SENSITIVE_ID, "routine", SENSITIVE_SEED, false), "class"),
        (key("another", "sensitive", SENSITIVE_SEED, false), "removed"),
    ];
    swaps.iter().try_for_each(|(text, label)| -> TestResult {
        replace_file(&path, &unscoped_text())?;
        let verifier = verifier_with(engine_at(&path)?, LAST_SEQUENCE);
        let refused = check_with(&verifier, &envelope, NOW, &[], &swap_after_check(&path, text.clone()));
        assert!(refused.is_err(), "{label}: {refused:?}");
        assert_eq!(verifier.last_sequences.lock().map_err(|_| "lock")?.sensitive, LAST_SEQUENCE, "{label}");
        Ok(())
    })
}


#[test]
fn a_reload_that_keeps_the_key_does_not_refuse_the_command() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("keys.yaml");
    replace_file(&path, &scoped_text("[isolate]"))?;
    let verifier = verifier_with(engine_at(&path)?, LAST_SEQUENCE);
    let envelope = sensitive_envelope(&sensitive_command(1, Action::Isolate))?;
    let hook = swap_after_check(&path, scoped_text("[isolate, reboot]"));
    assert!(check_with(&verifier, &envelope, NOW, &[], &hook).is_ok());
    Ok(())
}


#[test]
fn action_names_match_the_variants() -> TestResult {
    let actions = all_actions();
    assert_eq!(actions.len(), ACTION_NAMES.len());
    actions.iter().for_each(|action| {
        assert!(ACTION_NAMES.contains(&action_name(action)), "{action:?}");
        assert_eq!(
            SENSITIVE_ACTION_NAMES.contains(&action_name(action)),
            action_is_sensitive(action),
            "{action:?}"
        );
    });
    ACTION_NAMES
        .iter()
        .for_each(|name| assert!(actions.iter().any(|action| action_name(action) == *name), "{name}"));
    assert_eq!(
        SENSITIVE_ACTION_NAMES.len(),
        actions.iter().filter(|action| action_is_sensitive(action)).count()
    );
    Ok(())
}


#[test]
fn a_routine_key_listing_a_sensitive_kind_is_refused_at_load() -> TestResult {
    let routine = |actions: &[&str]| RawKey {
        class: KeyClass::Routine,
        ..raw(Some(Some(names(actions))))
    };
    let refused = trusted_key_with(&routine(&["ping", "reboot"]), &[]);
    assert!(matches!(refused, Err(KeyFileError::ActionsSensitiveOnRoutine { .. })));
    assert!(trusted_key_with(&routine(&["ping", "collect_status"]), &[]).is_ok());
    assert!(trusted_key_with(&raw(Some(Some(names(&["ping", "reboot"])))), &[]).is_ok());
    Ok(())
}

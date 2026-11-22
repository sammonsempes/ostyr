use crate::common::types::TestResult;
use crate::common::{
    command, engine_at, key_entry, public_hex, replace_file, routine_envelope, sensitive_command, sensitive_envelope, setup, signing_key,
    verifier_with, NOW, SEED_LENGTH, SENSITIVE_ID, SENSITIVE_SEED,
};
use agent_command::action::{valid_session_id, valid_shell_reference, valid_shell_subject, validate_action};
use agent_command::cli::{parse_action, write_signed};
use agent_command::codec::signing_message;
use agent_command::error::{ActionError, CliError, CommandError, KeyFileError, SignError};
use agent_command::keys::trusted_key_with;
use agent_command::model::{
    Action, Envelope, KeyClass, PackageSelection, RawKey, RebootPolicy, Verifier, ACTION_NAMES, EXCLUSIVE_ACTIONS, MAX_SHELL_APPROVERS,
    MAX_SHELL_IDLE_SECONDS, MAX_SHELL_SECONDS, MAX_SUBJECT_BYTES, SENSITIVE_ACTION_NAMES,
};
use agent_command::sign::{memory_signer, os_random, sign_command};
use agent_command::verify::{action_is_sensitive, action_name, verify_command};
use data_encoding::HEXLOWER;
use ed25519_dalek::Signer;
use std::path::Path;
use tempfile::tempdir;


const BEFORE: u64 = 0;


const AFTER: u64 = u64::MAX;


const MARKER: &str = "zq9marker";


const EDGE_LENGTH: usize = 129;


const SHORT: u64 = 1;


const SESSION_IDLE: u32 = 600;


fn open_shell() -> Action {
    shell(
        "s-1",
        "asset-1",
        "INC-1",
        "alice",
        &["bob", "carol"],
        (MAX_SHELL_IDLE_SECONDS, SESSION_IDLE),
    )
}


fn shell(session_id: &str, asset: &str, ticket: &str, requester: &str, approvers: &[&str], limits: (u32, u32)) -> Action {
    Action::OpenShell {
        session_id: session_id.to_owned(),
        asset: asset.to_owned(),
        ticket: ticket.to_owned(),
        requester: requester.to_owned(),
        approvers: approvers.iter().map(|name| (*name).to_owned()).collect(),
        max_seconds: limits.0,
        idle_seconds: limits.1,
    }
}


fn scoped_verifier(dir: &Path, actions: Option<&str>) -> Result<Verifier, Box<dyn std::error::Error>> {
    let path = dir.join("keys.yaml");
    let suffix = actions.map_or_else(String::new, |list| format!("    actions: {list}\n"));
    let entry = key_entry(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, BEFORE, AFTER, false);
    replace_file(&path, &format!("keys:\n{entry}{suffix}"))?;
    Ok(verifier_with(engine_at(&path)?, 0))
}


fn hand_built(action: Action, sequence: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = postcard::to_stdvec(&sensitive_command(sequence, action))?;
    let signature = signing_key(SENSITIVE_SEED).sign(&signing_message(&bytes)).to_bytes().to_vec();
    Ok(postcard::to_stdvec(&Envelope {
        key_id: SENSITIVE_ID.to_owned(),
        command: bytes,
        signature,
    })?)
}


fn refused_at_both(action: &Action, expected: &ActionError, dir: &Path) -> TestResult {
    let signer = memory_signer(signing_key(SENSITIVE_SEED));
    let at_signing = sign_command(&sensitive_command(1, action.clone()), SENSITIVE_ID, &signer);
    let signing_text = at_signing.as_ref().err().map(ToString::to_string).ok_or("signed")?;
    assert!(
        matches!(&at_signing, Err(SignError::Action(found)) if found == expected),
        "{at_signing:?}"
    );
    let verifier = scoped_verifier(dir, Some("[open_shell]"))?;
    let at_check = verify_command(&verifier, &hand_built(action.clone(), 1)?, NOW);
    let check_text = at_check.as_ref().err().map(ToString::to_string).ok_or("accepted")?;
    assert!(
        matches!(&at_check, Err(CommandError::InvalidAction(found)) if found == expected),
        "{at_check:?}"
    );
    assert!(!signing_text.contains(MARKER) && !check_text.contains(MARKER));
    assert_eq!(validate_action(action).as_ref(), Err(expected));
    Ok(())
}


#[test]
fn a_scoped_key_opens_a_shell_once_and_a_replay_is_refused() -> TestResult {
    let dir = tempdir()?;
    let verifier = scoped_verifier(dir.path(), Some("[open_shell]"))?;
    let sent = sensitive_command(1, open_shell());
    let envelope = sensitive_envelope(&sent)?;
    assert_eq!(verify_command(&verifier, &envelope, NOW)?, sent);
    assert!(matches!(verify_command(&verifier, &envelope, NOW), Err(CommandError::ReplayedSequence)));
    Ok(())
}


#[test]
fn a_routine_key_cannot_open_a_shell() -> TestResult {
    let setup = setup()?;
    let envelope = routine_envelope(&command(1, open_shell()))?;
    let refused = verify_command(&setup.verifier, &envelope, NOW);
    assert!(matches!(refused, Err(CommandError::SensitiveActionNeedsSensitiveKey)), "{refused:?}");
    Ok(())
}


#[test]
fn an_unscoped_or_other_scoped_sensitive_key_cannot_open_a_shell() -> TestResult {
    let dir = tempdir()?;
    let envelope = sensitive_envelope(&sensitive_command(1, open_shell()))?;
    ["[install_updates, reboot]", "[isolate]"].iter().try_for_each(|scope| -> TestResult {
        let verifier = scoped_verifier(dir.path(), Some(scope))?;
        let refused = verify_command(&verifier, &envelope, NOW);
        assert!(matches!(refused, Err(CommandError::ActionOutOfScope("open_shell"))), "{refused:?}");
        Ok(())
    })?;
    let unscoped = scoped_verifier(dir.path(), None)?;
    let refused = verify_command(&unscoped, &envelope, NOW);
    assert!(matches!(refused, Err(CommandError::ActionOutOfScope("open_shell"))), "{refused:?}");
    let scoped = scoped_verifier(dir.path(), Some("[open_shell]"))?;
    let other = sensitive_envelope(&sensitive_command(1, Action::Isolate))?;
    assert!(matches!(
        verify_command(&scoped, &other, NOW),
        Err(CommandError::ActionOutOfScope("isolate"))
    ));
    Ok(())
}


#[test]
fn an_open_shell_scope_beside_another_kind_is_refused_at_load() -> TestResult {
    let raw = |list: &[&str]| RawKey {
        id: "k".to_owned(),
        class: KeyClass::Sensitive,
        public_key: public_hex(SENSITIVE_SEED),
        not_before: BEFORE,
        not_after: SHORT,
        revoked: false,
        actions: Some(Some(list.iter().map(|name| (*name).to_owned()).collect())),
    };
    assert!(matches!(
        trusted_key_with(&raw(&["open_shell", "reboot"]), EXCLUSIVE_ACTIONS),
        Err(KeyFileError::ActionsExclusive { .. })
    ));
    assert!(trusted_key_with(&raw(&["open_shell"]), EXCLUSIVE_ACTIONS).is_ok());
    Ok(())
}


#[test]
fn the_session_id_grammar_has_sharp_edges() -> TestResult {
    let dir = tempdir()?;
    let longest = "a".repeat(EDGE_LENGTH - 1);
    assert!(valid_session_id("a") && valid_session_id("Z9_.-x") && valid_session_id(&longest));
    let too_long = "a".repeat(EDGE_LENGTH);
    let bad = [
        "",
        "a/b",
        "a:b",
        "-x",
        "_x",
        ".x",
        "a\0b",
        "a\u{3164}b",
        "caf\u{e9}",
        "a b",
        too_long.as_str(),
    ];
    bad.iter().try_for_each(|session| -> TestResult {
        assert!(!valid_session_id(session), "{session:?}");
        refused_at_both(
            &shell(session, "asset-1", "INC-1", "alice", &[], (1, 1)),
            &ActionError::ShellSessionId,
            dir.path(),
        )
    })
}


#[test]
fn the_reference_and_subject_grammars_have_sharp_edges() -> TestResult {
    let dir = tempdir()?;
    assert!(valid_shell_reference("INC-1/a:b_c.d") && valid_shell_subject("auth0|12@x.org") && valid_shell_subject("a-b"));
    ["", "-x", ":x", "a b", "a\0", "a\u{3164}", "a;b"]
        .iter()
        .try_for_each(|text| -> TestResult {
            assert!(!valid_shell_reference(text), "{text:?}");
            refused_at_both(&shell("s", text, "INC-1", "alice", &[], (1, 1)), &ActionError::ShellAsset, dir.path())?;
            refused_at_both(&shell("s", "asset", text, "alice", &[], (1, 1)), &ActionError::ShellTicket, dir.path())
        })?;
    let long_subject = "a".repeat(MAX_SUBJECT_BYTES + 1);
    ["", "-x", "a b", "a\0", "a\u{3164}", "a;b", long_subject.as_str()]
        .iter()
        .try_for_each(|text| -> TestResult {
            assert!(!valid_shell_subject(text), "{text:?}");
            refused_at_both(&shell("s", "asset", "INC-1", text, &[], (1, 1)), &ActionError::ShellRequester, dir.path())?;
            refused_at_both(
                &shell("s", "asset", "INC-1", "alice", &[text], (1, 1)),
                &ActionError::ShellApprover,
                dir.path(),
            )
        })
}


#[test]
fn the_approver_rules_are_enforced() -> TestResult {
    let dir = tempdir()?;
    let marked = format!("{MARKER}-alice");
    refused_at_both(
        &shell("s", "asset", "INC-1", &marked, &["bob", &marked], (1, 1)),
        &ActionError::ShellApproverIsRequester,
        dir.path(),
    )?;
    refused_at_both(
        &shell("s", "asset", "INC-1", "alice", &["bob", "carol", "bob"], (1, 1)),
        &ActionError::ShellApproverDuplicate,
        dir.path(),
    )?;
    let names: Vec<String> = (0..=MAX_SHELL_APPROVERS).map(|index| format!("approver{index}")).collect();
    let many: Vec<&str> = names.iter().map(String::as_str).collect();
    refused_at_both(
        &shell("s", "asset", "INC-1", "alice", &many, (1, 1)),
        &ActionError::ShellTooManyApprovers,
        dir.path(),
    )?;
    let invalid_beyond_cap: Vec<&str> = many.iter().map(|_| "-bad").collect();
    refused_at_both(
        &shell("s", "asset", "INC-1", "alice", &invalid_beyond_cap, (1, 1)),
        &ActionError::ShellTooManyApprovers,
        dir.path(),
    )?;
    let at_cap = many.get(..MAX_SHELL_APPROVERS).ok_or("cap")?;
    validate_action(&shell("s", "asset", "INC-1", "alice", at_cap, (1, 1)))?;
    validate_action(&shell("s", "asset", "INC-1", "alice", &[], (1, 1)))?;
    Ok(())
}


#[test]
fn the_duration_limits_are_enforced() -> TestResult {
    let dir = tempdir()?;
    [0, MAX_SHELL_SECONDS + 1, u32::MAX].iter().try_for_each(|max| -> TestResult {
        refused_at_both(&shell("s", "a", "t", "alice", &[], (*max, 1)), &ActionError::ShellMaxSeconds, dir.path())
    })?;
    [0, MAX_SHELL_IDLE_SECONDS + 1, u32::MAX].iter().try_for_each(|idle| -> TestResult {
        refused_at_both(
            &shell("s", "a", "t", "alice", &[], (1, *idle)),
            &ActionError::ShellIdleSeconds,
            dir.path(),
        )
    })?;
    validate_action(&shell("s", "a", "t", "alice", &[], (MAX_SHELL_SECONDS, MAX_SHELL_IDLE_SECONDS)))?;
    validate_action(&shell("s", "a", "t", "alice", &[], (1, 1)))?;
    Ok(())
}


#[test]
fn open_shell_is_sensitive_exclusive_and_named() -> TestResult {
    let action = open_shell();
    assert!(action_is_sensitive(&action));
    assert_eq!(action_name(&action), "open_shell");
    assert!(ACTION_NAMES.contains(&"open_shell") && SENSITIVE_ACTION_NAMES.contains(&"open_shell"));
    assert_eq!(EXCLUSIVE_ACTIONS, ["open_shell"]);
    Ok(())
}


#[test]
fn the_cli_signs_and_verifies_an_open_shell() -> TestResult {
    let seed = HEXLOWER.encode(&[SENSITIVE_SEED; SEED_LENGTH]);
    let parameter = "s-1,asset-1,INC-1,alice,3600,600,bob,carol";
    assert_eq!(parse_action("open_shell", Some(parameter)).ok(), Some(open_shell()));
    assert_eq!(
        parse_action("open_shell", Some("s,a,t,alice,1,1")).ok(),
        Some(shell("s", "a", "t", "alice", &[], (1, 1)))
    );
    assert!(matches!(parse_action("open_shell", Some("s,a,t,alice,1")), Err(CliError::Parameter(_))));
    assert!(matches!(parse_action("open_shell", None), Err(CliError::Parameter(_))));
    assert!(matches!(parse_action("open_shell", Some("s,a,t,alice,x,1")), Err(CliError::Number)));
    assert!(matches!(parse_action("open_shell", Some("s,a,t,alice,1,x")), Err(CliError::Number)));
    let mut out = Vec::new();
    let valid = [seed.as_str(), SENSITIVE_ID, "sensitive", "agent-1", "acme", "1", "open_shell", parameter];
    write_signed(&valid, NOW, os_random, &mut out)?;
    assert!(!out.is_empty());
    let invalid = [
        seed.as_str(),
        SENSITIVE_ID,
        "sensitive",
        "agent-1",
        "acme",
        "1",
        "open_shell",
        "s/x,a,t,alice,1,1",
    ];
    let refused = write_signed(&invalid, NOW, os_random, &mut Vec::new());
    assert!(matches!(refused, Err(CliError::Sign(SignError::Action(ActionError::ShellSessionId)))));
    Ok(())
}


#[test]
fn every_action_name_maps_to_exactly_one_variant() -> TestResult {
    let actions = [
        Action::Ping,
        Action::CollectStatus,
        Action::Isolate,
        Action::Kill { process_id: 1 },
        Action::RunScript { script: "s".to_owned() },
        Action::Update { version: "1".to_owned() },
        Action::Uninstall,
        Action::ChangePolicy { policy: "p".to_owned() },
        Action::InstallUpdates {
            packages: PackageSelection::AllAllowed,
            reboot: RebootPolicy::Never,
        },
        Action::Reboot {
            prompt_user: false,
            deadline: 0,
        },
        open_shell(),
    ];
    assert_eq!(actions.len(), ACTION_NAMES.len());
    ACTION_NAMES.iter().for_each(|name| {
        assert_eq!(actions.iter().filter(|action| action_name(action) == *name).count(), 1, "{name}");
    });
    actions
        .iter()
        .for_each(|action| assert!(ACTION_NAMES.contains(&action_name(action)), "{action:?}"));
    EXCLUSIVE_ACTIONS
        .iter()
        .for_each(|name| assert!(SENSITIVE_ACTION_NAMES.contains(name), "{name}"));
    Ok(())
}

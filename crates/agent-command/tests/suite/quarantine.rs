use crate::common::types::TestResult;
use crate::common::{
    command, engine_at, key_entry, replace_file, routine_envelope, sensitive_command, sensitive_envelope, setup, signing_key, verifier_with, NOW,
    SENSITIVE_ID, SENSITIVE_SEED,
};
use agent_command::action::{valid_agent_path, valid_sha256, validate_action};
use agent_command::cli::{parse_action, write_signed};
use agent_command::codec::signing_message;
use agent_command::error::{ActionError, CliError, CommandError, SignError};
use agent_command::model::{
    Action, Envelope, Verifier, ACTION_NAMES, MAX_AGENT_PATH_BYTES, MAX_QUARANTINE_BYTES, MAX_STOP_SECONDS, MIN_STOP_SECONDS, SENSITIVE_ACTION_NAMES,
};
use agent_command::sign::{memory_signer, os_random, sign_command};
use agent_command::verify::{action_is_sensitive, action_name, verify_command};
use ed25519_dalek::Signer;
use std::path::Path;
use tempfile::tempdir;


const GOOD_SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


const MARKER: &str = "zq9marker";


const UNKNOWN_VARIANT: u8 = 14;


const ENTRY: u64 = 7;


const SIZE: u64 = 5;


const CLI_SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";


fn quarantine(path: &str, sha256: &str, size: u64) -> Action {
    Action::Quarantine {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        size,
    }
}


fn scan(path: &str) -> Action {
    Action::Scan { path: path.to_owned() }
}


fn restore(entry: u64, sha256: &str) -> Action {
    Action::RestoreQuarantine {
        entry,
        sha256: sha256.to_owned(),
    }
}


fn stop(seconds: u32) -> Action {
    Action::Stop {
        resume_after_seconds: seconds,
    }
}


fn all_four() -> Vec<Action> {
    vec![
        stop(MIN_STOP_SECONDS),
        quarantine("/tmp/a", GOOD_SHA, 1),
        restore(ENTRY, GOOD_SHA),
        scan("/tmp"),
    ]
}


fn scoped_verifier(dir: &Path, actions: &str) -> Result<Verifier, Box<dyn std::error::Error>> {
    let path = dir.join("keys.yaml");
    let entry = key_entry(SENSITIVE_ID, "sensitive", SENSITIVE_SEED, 0, u64::MAX, false);
    replace_file(&path, &format!("keys:\n{entry}    actions: {actions}\n"))?;
    Ok(verifier_with(engine_at(&path)?, 0))
}


fn hand_built(action: Action) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = postcard::to_stdvec(&sensitive_command(1, action))?;
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
    let verifier = scoped_verifier(dir, &format!("[{}]", action_name(action)))?;
    let at_check = verify_command(&verifier, &hand_built(action.clone())?, NOW);
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
fn the_four_names_are_appended_sensitive_and_unique() -> TestResult {
    let actions = all_four();
    actions.iter().for_each(|action| {
        assert!(ACTION_NAMES.contains(&action_name(action)) && SENSITIVE_ACTION_NAMES.contains(&action_name(action)));
        assert!(action_is_sensitive(action));
        assert_eq!(validate_action(action), Ok(()));
    });
    let names: Vec<&str> = actions.iter().map(action_name).collect();
    assert_eq!(names, vec!["stop", "quarantine", "restore_quarantine", "scan"]);
    assert!(ACTION_NAMES.ends_with(&["stop", "quarantine", "restore_quarantine", "scan"]));
    Ok(())
}


#[test]
fn a_routine_key_cannot_sign_any_of_them() -> TestResult {
    let setup = setup()?;
    all_four().into_iter().enumerate().try_for_each(|(index, action)| -> TestResult {
        let envelope = routine_envelope(&command(index as u64 + 1, action))?;
        let refused = verify_command(&setup.verifier, &envelope, NOW);
        assert!(matches!(refused, Err(CommandError::SensitiveActionNeedsSensitiveKey)), "{refused:?}");
        Ok(())
    })
}


#[test]
fn a_scoped_sensitive_key_signs_each_and_a_foreign_scope_is_refused() -> TestResult {
    let dir = tempdir()?;
    all_four().into_iter().try_for_each(|action| -> TestResult {
        let verifier = scoped_verifier(dir.path(), &format!("[{}]", action_name(&action)))?;
        let sent = sensitive_command(1, action.clone());
        assert_eq!(verify_command(&verifier, &sensitive_envelope(&sent)?, NOW)?, sent);
        let other = scoped_verifier(dir.path(), "[scan]")?;
        let envelope = sensitive_envelope(&sensitive_command(1, quarantine("/tmp/a", GOOD_SHA, 1)))?;
        let refused = verify_command(&other, &envelope, NOW);
        assert!(matches!(refused, Err(CommandError::ActionOutOfScope("quarantine"))), "{refused:?}");
        Ok(())
    })
}


#[test]
fn an_unknown_variant_is_refused_at_decode() -> TestResult {
    let mut bytes = postcard::to_stdvec(&sensitive_command(1, Action::Ping))?;
    *bytes.last_mut().ok_or("empty")? = UNKNOWN_VARIANT;
    let signature = signing_key(SENSITIVE_SEED).sign(&signing_message(&bytes)).to_bytes().to_vec();
    let envelope = postcard::to_stdvec(&Envelope {
        key_id: SENSITIVE_ID.to_owned(),
        command: bytes,
        signature,
    })?;
    let dir = tempdir()?;
    let verifier = scoped_verifier(dir.path(), "[scan]")?;
    assert!(matches!(verify_command(&verifier, &envelope, NOW), Err(CommandError::Malformed(_))));
    Ok(())
}


#[test]
fn the_path_grammar_has_sharp_edges() -> TestResult {
    let dir = tempdir()?;
    let longest = format!("/{}", "a".repeat(MAX_AGENT_PATH_BYTES - 1));
    let too_long = format!("/{}", "a".repeat(MAX_AGENT_PATH_BYTES));
    assert!(valid_agent_path("/a") && valid_agent_path("/tmp/a b/c.d") && valid_agent_path("/caf\u{e9}/\u{4e2d}") && valid_agent_path(&longest));
    assert!(valid_agent_path("/.hidden") && valid_agent_path("/a/..b") && valid_agent_path("/a/b.") && valid_agent_path("/a\\b"));
    let bad = [
        "",
        "/",
        "a",
        "tmp/a",
        "./a",
        "/a/../etc/shadow",
        "/a/./b",
        "/..",
        "/.",
        "/a//b",
        "//a",
        "/a/",
        "C:\\a",
        "\\\\server\\share",
        "\\\\?\\C:\\a",
        "/a\0b",
        "/a\nb",
        "/a\u{7f}b",
        "/a\u{85}b",
        "/tmp/a\u{202e}b",
        "/tmp/a\u{200f}b",
        "/tmp/a\u{2028}b",
        "/tmp/a\u{2029}b",
        "/tmp/\u{e0041}",
        "/tmp/a\u{61c}b",
        "/tmp/a\u{feff}b",
        "/tmp/a\u{e000}b",
        "/tmp/a\u{378}b",
        too_long.as_str(),
    ];
    bad.iter().try_for_each(|path| -> TestResult {
        assert!(!valid_agent_path(path), "{path:?}");
        refused_at_both(&scan(path), &ActionError::ScanPath, dir.path())?;
        refused_at_both(&quarantine(path, GOOD_SHA, 1), &ActionError::QuarantinePath, dir.path())
    })
}


#[test]
fn the_sha256_grammar_is_pinned() -> TestResult {
    let dir = tempdir()?;
    let upper = GOOD_SHA.to_uppercase();
    let short = &GOOD_SHA[1..];
    let long = format!("{GOOD_SHA}0");
    let not_hex = format!("g{}", &GOOD_SHA[1..]);
    assert!(valid_sha256(GOOD_SHA));
    [upper.as_str(), short, long.as_str(), not_hex.as_str(), ""]
        .iter()
        .try_for_each(|sha| -> TestResult {
            assert!(!valid_sha256(sha), "{sha:?}");
            refused_at_both(&quarantine("/tmp/a", sha, 1), &ActionError::QuarantineSha256, dir.path())?;
            refused_at_both(&restore(1, sha), &ActionError::RestoreSha256, dir.path())
        })
}


#[test]
fn the_numeric_bounds_are_pinned() -> TestResult {
    let dir = tempdir()?;
    [0, MAX_QUARANTINE_BYTES + 1, u64::MAX]
        .iter()
        .try_for_each(|size| -> TestResult { refused_at_both(&quarantine("/tmp/a", GOOD_SHA, *size), &ActionError::QuarantineSize, dir.path()) })?;
    [1, MAX_QUARANTINE_BYTES]
        .iter()
        .for_each(|size| assert_eq!(validate_action(&quarantine("/tmp/a", GOOD_SHA, *size)), Ok(())));
    [0, MIN_STOP_SECONDS - 1, MAX_STOP_SECONDS + 1, u32::MAX]
        .iter()
        .try_for_each(|seconds| -> TestResult { refused_at_both(&stop(*seconds), &ActionError::StopSeconds, dir.path()) })?;
    [MIN_STOP_SECONDS, MAX_STOP_SECONDS]
        .iter()
        .for_each(|seconds| assert_eq!(validate_action(&stop(*seconds)), Ok(())));
    refused_at_both(&restore(0, GOOD_SHA), &ActionError::RestoreEntry, dir.path())?;
    assert_eq!(validate_action(&restore(1, GOOD_SHA)), Ok(()));
    Ok(())
}


#[test]
fn a_sign_and_verify_round_trip_keeps_every_field() -> TestResult {
    let dir = tempdir()?;
    let actions = [
        stop(MAX_STOP_SECONDS),
        quarantine("/tmp/a,b", GOOD_SHA, MAX_QUARANTINE_BYTES),
        restore(u64::MAX, GOOD_SHA),
        scan("/var/www"),
    ];
    actions.into_iter().try_for_each(|action| -> TestResult {
        let verifier = scoped_verifier(dir.path(), &format!("[{}]", action_name(&action)))?;
        let sent = sensitive_command(1, action);
        assert_eq!(verify_command(&verifier, &sensitive_envelope(&sent)?, NOW)?, sent);
        Ok(())
    })
}


#[test]
fn the_command_line_builds_each_action_and_never_echoes_a_path() -> TestResult {
    assert_eq!(parse_action("stop", Some("60"))?, stop(MIN_STOP_SECONDS));
    assert_eq!(
        parse_action("quarantine", Some(&format!("{GOOD_SHA},{SIZE},/tmp/a,b c")))?,
        quarantine("/tmp/a,b c", GOOD_SHA, SIZE)
    );
    assert_eq!(
        parse_action("restore_quarantine", Some(&format!("{ENTRY},{GOOD_SHA}")))?,
        restore(ENTRY, GOOD_SHA)
    );
    assert_eq!(parse_action("scan", Some("/srv"))?, scan("/srv"));
    assert!(matches!(parse_action("stop", Some("x")), Err(CliError::Number)));
    assert!(matches!(parse_action("stop", None), Err(CliError::Number)));
    assert!(matches!(
        parse_action("quarantine", Some(&format!("{GOOD_SHA},x,/a"))),
        Err(CliError::Number)
    ));
    assert!(matches!(
        parse_action("restore_quarantine", Some(&format!("x,{GOOD_SHA}"))),
        Err(CliError::Number)
    ));
    let refused = [
        parse_action("quarantine", Some(&format!("{GOOD_SHA}{MARKER}"))),
        parse_action("quarantine", Some(&format!("{GOOD_SHA},1{MARKER}"))),
        parse_action("restore_quarantine", Some(MARKER)),
        parse_action("restore_quarantine", Some(&format!("1,{GOOD_SHA},{MARKER}"))),
    ];
    refused.iter().for_each(|result| {
        assert!(matches!(result, Err(CliError::Parameter(_))), "{result:?}");
        assert!(!format!("{result:?}").contains(MARKER));
    });
    let mut out = Vec::new();
    let signed = write_signed(
        &[CLI_SEED, "k", "sensitive", "a", "t", "1", "scan", &format!("/x/../{MARKER}")],
        NOW,
        os_random,
        &mut out,
    );
    assert!(
        matches!(&signed, Err(CliError::Sign(SignError::Action(ActionError::ScanPath)))),
        "{signed:?}"
    );
    assert!(!signed.err().map(|error| error.to_string()).ok_or("signed")?.contains(MARKER));
    assert!(out.is_empty());
    Ok(())
}

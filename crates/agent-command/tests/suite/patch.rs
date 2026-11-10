use crate::common::types::TestResult;
use crate::common::{
    command, routine_envelope, sensitive_command, sensitive_envelope, setup, signing_key, NOW, SEED_LENGTH, SENSITIVE_ID, SENSITIVE_SEED,
};
use agent_command::action::{validate_action, validate_package_name};
use agent_command::cli::{parse_action, write_signed};
use agent_command::codec::{decode_exact, signing_message};
use agent_command::error::{ActionError, CliError, CommandError, SignError};
use agent_command::model::{Action, Envelope, PackageSelection, RebootPolicy, MAX_PACKAGES, MAX_PACKAGE_NAME_LENGTH};
use agent_command::sign::{memory_signer, os_random, sign_command};
use agent_command::verify::{action_is_sensitive, action_name, verify_command};
use data_encoding::HEXLOWER;
use ed25519_dalek::Signer;


const DEADLINE: u64 = 1_700_000_300;


const SHORT_DEADLINE: u64 = 5;


const UPDATE_TAG: u8 = 5;


const UNINSTALL_TAG: u8 = 6;


const CHANGE_POLICY_TAG: u8 = 7;


const INSTALL_TAG: u8 = 8;


const REBOOT_TAG: u8 = 9;


fn named(names: &[&str]) -> PackageSelection {
    PackageSelection::Named(names.iter().map(|name| (*name).to_owned()).collect())
}


fn install(packages: PackageSelection) -> Action {
    Action::InstallUpdates {
        packages,
        reboot: RebootPolicy::InWindow,
    }
}


fn hand_built_envelope(action: Action) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = postcard::to_stdvec(&sensitive_command(1, action))?;
    let signature = signing_key(SENSITIVE_SEED).sign(&signing_message(&bytes)).to_bytes().to_vec();
    Ok(postcard::to_stdvec(&Envelope {
        key_id: SENSITIVE_ID.to_owned(),
        command: bytes,
        signature,
    })?)
}


#[test]
fn new_actions_round_trip_and_are_sensitive() -> TestResult {
    let setup = setup()?;
    let actions = [
        (install(named(&["curl", "libssl3:amd64"])), "install_updates"),
        (install(PackageSelection::AllAllowed), "install_updates"),
        (
            Action::Reboot {
                prompt_user: true,
                deadline: DEADLINE,
            },
            "reboot",
        ),
    ];
    actions.iter().zip(1..).try_for_each(|((action, name), sequence)| -> TestResult {
        let sent = sensitive_command(sequence, action.clone());
        assert_eq!(verify_command(&setup.verifier, &sensitive_envelope(&sent)?, NOW)?, sent);
        assert!(action_is_sensitive(action));
        assert_eq!(action_name(action), *name);
        Ok(())
    })
}


#[test]
fn a_routine_key_cannot_issue_patch_actions() -> TestResult {
    let setup = setup()?;
    let envelope = routine_envelope(&command(1, install(PackageSelection::AllAllowed)))?;
    assert!(matches!(
        verify_command(&setup.verifier, &envelope, NOW),
        Err(CommandError::SensitiveActionNeedsSensitiveKey)
    ));
    Ok(())
}


#[test]
fn envelopes_encoded_before_the_change_still_decode() -> TestResult {
    let old_update: Action = decode_exact(&[UPDATE_TAG, 1, b'1'])?;
    assert_eq!(old_update, Action::Update { version: "1".to_owned() });
    assert_eq!(decode_exact::<Action>(&[UNINSTALL_TAG])?, Action::Uninstall);
    let old_policy: Action = decode_exact(&[CHANGE_POLICY_TAG, 1, b'p'])?;
    assert_eq!(old_policy, Action::ChangePolicy { policy: "p".to_owned() });
    assert_eq!(postcard::to_stdvec(&Action::Uninstall)?, vec![UNINSTALL_TAG]);
    assert_eq!(
        postcard::to_stdvec(&Action::Reboot {
            prompt_user: false,
            deadline: 0
        })?,
        vec![REBOOT_TAG, 0, 0]
    );
    assert_eq!(postcard::to_stdvec(&install(PackageSelection::AllAllowed))?, vec![INSTALL_TAG, 0, 1]);
    Ok(())
}


#[test]
fn the_package_grammar_has_sharp_edges() -> TestResult {
    ["curl", "libstdc++6", "a.b-c_d:e~f", "0", "Z9"]
        .iter()
        .try_for_each(|name| validate_package_name(name))?;
    assert_eq!(validate_package_name(""), Err(ActionError::EmptyPackageName));
    assert_eq!(validate_package_name("-rf"), Err(ActionError::PackageNameLeadingDash));
    assert_eq!(validate_package_name("a b"), Err(ActionError::PackageNameCharacter));
    assert_eq!(validate_package_name("a;b"), Err(ActionError::PackageNameCharacter));
    assert_eq!(validate_package_name("caf\u{e9}"), Err(ActionError::PackageNameCharacter));
    assert_eq!(validate_package_name("a\0"), Err(ActionError::PackageNameCharacter));
    let longest = "a".repeat(MAX_PACKAGE_NAME_LENGTH);
    validate_package_name(&longest)?;
    assert_eq!(validate_package_name(&format!("{longest}a")), Err(ActionError::PackageNameTooLong));
    Ok(())
}


#[test]
fn the_package_list_is_bounded_and_empty_named_lists_are_refused() -> TestResult {
    validate_action(&install(PackageSelection::Named(vec!["a".to_owned(); MAX_PACKAGES])))?;
    let over = PackageSelection::Named(vec!["a".to_owned(); MAX_PACKAGES + 1]);
    assert_eq!(validate_action(&install(over)), Err(ActionError::TooManyPackages));
    assert_eq!(validate_action(&install(named(&[]))), Err(ActionError::NoPackages));
    assert_eq!(validate_action(&install(named(&["ok", "-x"]))), Err(ActionError::PackageNameLeadingDash));
    validate_action(&install(PackageSelection::AllAllowed))?;
    validate_action(&Action::Ping)?;
    Ok(())
}


#[test]
fn signing_refuses_a_bad_selection() -> TestResult {
    let signer = memory_signer(signing_key(1));
    let refused = sign_command(&sensitive_command(1, install(named(&["-x"]))), "k", &signer);
    assert!(matches!(refused, Err(SignError::Action(ActionError::PackageNameLeadingDash))));
    Ok(())
}


#[test]
fn a_hand_built_bad_selection_is_refused_at_verify_without_burning_the_sequence() -> TestResult {
    let setup = setup()?;
    let refusal = verify_command(&setup.verifier, &hand_built_envelope(install(named(&["-x"])))?, NOW);
    let text = refusal.as_ref().err().map(ToString::to_string).ok_or("accepted")?;
    assert!(matches!(refusal, Err(CommandError::InvalidAction(ActionError::PackageNameLeadingDash))));
    assert!(!text.contains("-x"), "{text}");
    let good = sensitive_command(1, Action::Isolate);
    assert_eq!(verify_command(&setup.verifier, &sensitive_envelope(&good)?, NOW)?, good);
    Ok(())
}


#[test]
fn the_cli_parses_patch_actions() -> TestResult {
    assert_eq!(
        parse_action("install_updates", Some("required=curl,openssl")).ok(),
        Some(Action::InstallUpdates {
            packages: named(&["curl", "openssl"]),
            reboot: RebootPolicy::Required
        })
    );
    assert_eq!(
        parse_action("install_updates", Some("never")).ok(),
        Some(Action::InstallUpdates {
            packages: PackageSelection::AllAllowed,
            reboot: RebootPolicy::Never
        })
    );
    assert_eq!(
        parse_action("install_updates", Some("in_window")).ok(),
        Some(install(PackageSelection::AllAllowed))
    );
    assert!(matches!(parse_action("install_updates", Some("later")), Err(CliError::Parameter(_))));
    assert!(matches!(parse_action("install_updates", None), Err(CliError::Parameter(_))));
    assert_eq!(
        parse_action("reboot", Some("true,5")).ok(),
        Some(Action::Reboot {
            prompt_user: true,
            deadline: SHORT_DEADLINE
        })
    );
    assert!(matches!(parse_action("reboot", Some("true")), Err(CliError::Parameter(_))));
    assert!(matches!(parse_action("reboot", Some("maybe,5")), Err(CliError::Parameter(_))));
    assert!(matches!(parse_action("reboot", Some("true,x")), Err(CliError::Number)));
    Ok(())
}


#[test]
fn the_cli_signs_valid_and_refuses_invalid_selections() -> TestResult {
    let seed = HEXLOWER.encode(&[1; SEED_LENGTH]);
    let mut out = Vec::new();
    write_signed(
        &[&seed, "k", "sensitive", "a", "t", "1", "install_updates", "never=curl"],
        NOW,
        os_random,
        &mut out,
    )?;
    assert!(!out.is_empty());
    let refused = write_signed(
        &[&seed, "k", "sensitive", "a", "t", "1", "install_updates", "never=-x"],
        NOW,
        os_random,
        &mut Vec::new(),
    );
    assert!(matches!(
        refused,
        Err(CliError::Sign(SignError::Action(ActionError::PackageNameLeadingDash)))
    ));
    Ok(())
}

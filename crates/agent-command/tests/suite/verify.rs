use crate::common::types::TestResult;
use crate::common::{
    command, replace_file, routine_envelope, sensitive_envelope, setup, sign_with, signing_key, Setup, LIFETIME, NOW, ROUTINE_ID, ROUTINE_SEED,
    SENSITIVE_ID,
};
use crate::common::{SECOND, THIRD};
use agent_command::codec::signing_message;
use agent_command::error::CommandError;
use agent_command::model::{Action, Command, Envelope, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS};
use agent_command::verify::{action_is_sensitive, action_name, verify_command};
use ed25519_dalek::Signer;


const BITS_PER_BYTE: usize = 8;


const GARBAGE: [u8; 3] = [0xff; 3];


const SHORT_SIGNATURE_LENGTH: usize = 10;


const PROCESS_ID: u32 = 4;


const ACCEPTED: u64 = 5;


const BEHIND: u64 = 4;


const AHEAD: u64 = 6;


fn verify(setup: &Setup, bytes: &[u8]) -> Result<Command, CommandError> {
    verify_command(&setup.verifier, bytes, NOW)
}


fn with(mut base: Command, change: impl FnOnce(&mut Command)) -> Command {
    change(&mut base);
    base
}


#[test]
fn routine_command_round_trips() -> TestResult {
    let setup = setup()?;
    let sent = command(1, Action::Ping);
    let received = verify(&setup, &routine_envelope(&sent)?)?;
    assert_eq!(received, sent);
    Ok(())
}


#[test]
fn sensitive_action_with_sensitive_key_is_accepted() -> TestResult {
    let setup = setup()?;
    let sent = command(1, Action::Isolate);
    assert_eq!(verify(&setup, &sensitive_envelope(&sent)?)?, sent);
    Ok(())
}


#[test]
fn every_sensitive_action_is_refused_with_a_routine_key() -> TestResult {
    let setup = setup()?;
    let actions = [
        Action::Isolate,
        Action::Kill { process_id: PROCESS_ID },
        Action::RunScript { script: "id".to_owned() },
        Action::Update { version: "1.0".to_owned() },
        Action::Uninstall,
        Action::ChangePolicy { policy: "p".to_owned() },
    ];
    actions.iter().zip(1..).try_for_each(|(action, sequence)| -> TestResult {
        let refusal = verify(&setup, &routine_envelope(&command(sequence, action.clone()))?);
        assert!(
            matches!(refusal, Err(CommandError::SensitiveActionNeedsSensitiveKey)),
            "{}",
            action_name(action)
        );
        assert!(action_is_sensitive(action));
        Ok(())
    })
}


#[test]
fn routine_actions_are_not_sensitive() -> TestResult {
    assert!(!action_is_sensitive(&Action::Ping) && !action_is_sensitive(&Action::CollectStatus));
    let names = [
        (Action::Ping, "ping"),
        (Action::CollectStatus, "collect_status"),
        (Action::Isolate, "isolate"),
        (Action::Kill { process_id: PROCESS_ID }, "kill"),
        (Action::RunScript { script: String::new() }, "run_script"),
        (Action::Update { version: String::new() }, "update"),
        (Action::Uninstall, "uninstall"),
        (Action::ChangePolicy { policy: String::new() }, "change_policy"),
    ];
    names.iter().for_each(|(action, name)| assert_eq!(action_name(action), *name));
    Ok(())
}


#[test]
fn unknown_key_id_is_refused() -> TestResult {
    let setup = setup()?;
    let bytes = sign_with(&command(1, Action::Ping), "nobody", ROUTINE_SEED)?;
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::UnknownKey)));
    Ok(())
}


#[test]
fn signature_by_another_key_is_refused() -> TestResult {
    let setup = setup()?;
    let bytes = sign_with(&command(1, Action::Ping), ROUTINE_ID, 1)?;
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::BadSignature)));
    Ok(())
}


#[test]
fn other_agent_and_other_tenant_are_refused() -> TestResult {
    let setup = setup()?;
    let agent = routine_envelope(&with(command(1, Action::Ping), |value| value.agent_id = "agent-2".to_owned()))?;
    let tenant = routine_envelope(&with(command(1, Action::Ping), |value| value.tenant = "other".to_owned()))?;
    assert!(matches!(verify(&setup, &agent), Err(CommandError::WrongAgent)));
    assert!(matches!(verify(&setup, &tenant), Err(CommandError::WrongTenant)));
    Ok(())
}


#[test]
fn expired_command_is_refused() -> TestResult {
    let setup = setup()?;
    let bytes = routine_envelope(&with(command(1, Action::Ping), |value| {
        value.issued_at = NOW - LIFETIME - 1;
        value.expires_at = NOW;
    }))?;
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::Expired)));
    Ok(())
}


#[test]
fn issue_time_in_the_future_is_refused_beyond_the_skew_only() -> TestResult {
    let setup = setup()?;
    let at_skew = routine_envelope(&with(command(1, Action::Ping), |value| {
        value.issued_at = NOW + CLOCK_SKEW_SECONDS;
        value.expires_at = NOW + CLOCK_SKEW_SECONDS + LIFETIME;
    }))?;
    let beyond = routine_envelope(&with(command(SECOND, Action::Ping), |value| {
        value.issued_at = NOW + CLOCK_SKEW_SECONDS + 1;
        value.expires_at = NOW + CLOCK_SKEW_SECONDS + 1 + LIFETIME;
    }))?;
    assert!(verify(&setup, &at_skew).is_ok());
    assert!(matches!(verify(&setup, &beyond), Err(CommandError::IssuedInFuture)));
    Ok(())
}


#[test]
fn lifetime_longer_than_the_maximum_is_refused() -> TestResult {
    let setup = setup()?;
    let at_max = routine_envelope(&with(command(1, Action::Ping), |value| value.expires_at = NOW + MAX_LIFETIME_SECONDS))?;
    let too_long = routine_envelope(&with(command(SECOND, Action::Ping), |value| {
        value.expires_at = NOW + MAX_LIFETIME_SECONDS + 1
    }))?;
    assert!(verify(&setup, &at_max).is_ok());
    assert!(matches!(verify(&setup, &too_long), Err(CommandError::LifetimeTooLong)));
    Ok(())
}


#[test]
fn expiry_not_after_issue_is_refused() -> TestResult {
    let setup = setup()?;
    let bytes = routine_envelope(&with(command(1, Action::Ping), |value| value.expires_at = NOW))?;
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::InvalidLifetime)));
    Ok(())
}


#[test]
fn sequence_must_strictly_increase() -> TestResult {
    let setup = setup()?;
    let envelope_of = |sequence| routine_envelope(&command(sequence, Action::Ping));
    assert!(verify(&setup, &envelope_of(ACCEPTED)?).is_ok());
    assert!(matches!(verify(&setup, &envelope_of(ACCEPTED)?), Err(CommandError::ReplayedSequence)));
    assert!(matches!(verify(&setup, &envelope_of(BEHIND)?), Err(CommandError::ReplayedSequence)));
    assert!(matches!(verify(&setup, &envelope_of(0)?), Err(CommandError::ReplayedSequence)));
    assert!(verify(&setup, &envelope_of(AHEAD)?).is_ok());
    Ok(())
}


#[test]
fn a_replayed_envelope_is_refused() -> TestResult {
    let setup = setup()?;
    let bytes = routine_envelope(&command(1, Action::Ping))?;
    assert!(verify(&setup, &bytes).is_ok());
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::ReplayedSequence)));
    Ok(())
}


#[test]
fn malformed_input_is_refused() -> TestResult {
    let setup = setup()?;
    let mut trailing = routine_envelope(&command(1, Action::Ping))?;
    trailing.push(0);
    assert!(matches!(verify(&setup, &[]), Err(CommandError::Malformed(_))));
    assert!(matches!(verify(&setup, &trailing), Err(CommandError::Malformed(_))));
    Ok(())
}


#[test]
fn signed_garbage_command_is_refused_after_the_signature_check() -> TestResult {
    let setup = setup()?;
    let garbage = GARBAGE.to_vec();
    let signature = signing_key(ROUTINE_SEED).sign(&signing_message(&garbage)).to_bytes().to_vec();
    let bytes = postcard::to_stdvec(&Envelope {
        key_id: ROUTINE_ID.to_owned(),
        command: garbage,
        signature,
    })?;
    assert!(matches!(verify(&setup, &bytes), Err(CommandError::Malformed(_))));
    Ok(())
}


#[test]
fn short_signature_is_refused() -> TestResult {
    let setup = setup()?;
    let mut envelope: Envelope = postcard::from_bytes(&routine_envelope(&command(1, Action::Ping))?)?;
    envelope.signature.truncate(SHORT_SIGNATURE_LENGTH);
    assert!(matches!(
        verify(&setup, &postcard::to_stdvec(&envelope)?),
        Err(CommandError::BadSignature)
    ));
    Ok(())
}


#[test]
fn a_flipped_bit_in_each_part_is_refused() -> TestResult {
    let setup = setup()?;
    let original: Envelope = postcard::from_bytes(&sensitive_envelope(&command(1, Action::Kill { process_id: PROCESS_ID }))?)?;
    let flip = |bytes: &[u8]| {
        bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| if index == 0 { byte ^ 1 } else { *byte })
            .collect::<Vec<u8>>()
    };
    let in_key = Envelope {
        key_id: SENSITIVE_ID.replacen('s', "t", 1),
        ..original.clone()
    };
    let in_command = Envelope {
        command: flip(&original.command),
        ..original.clone()
    };
    let in_signature = Envelope {
        signature: flip(&original.signature),
        ..original.clone()
    };
    assert!(matches!(verify(&setup, &postcard::to_stdvec(&in_key)?), Err(CommandError::UnknownKey)));
    assert!(matches!(
        verify(&setup, &postcard::to_stdvec(&in_command)?),
        Err(CommandError::BadSignature)
    ));
    assert!(matches!(
        verify(&setup, &postcard::to_stdvec(&in_signature)?),
        Err(CommandError::BadSignature)
    ));
    assert!(verify(&setup, &postcard::to_stdvec(&original)?).is_ok());
    Ok(())
}


#[test]
fn flipping_any_single_bit_of_the_envelope_never_verifies() -> TestResult {
    let setup = setup()?;
    let bytes = sensitive_envelope(&command(1, Action::Isolate))?;
    let all_refused = (0..bytes.len() * BITS_PER_BYTE).all(|bit| {
        let mut copy = bytes.clone();
        if let Some(byte) = copy.get_mut(bit / BITS_PER_BYTE) {
            *byte ^= 1 << (bit % BITS_PER_BYTE);
        }
        verify(&setup, &copy).is_err()
    });
    assert!(all_refused);
    assert!(verify(&setup, &bytes).is_ok());
    Ok(())
}


#[test]
fn revoked_key_is_refused_from_the_next_command_after_a_live_reload() -> TestResult {
    let setup = setup()?;
    assert!(verify(&setup, &routine_envelope(&command(1, Action::Ping))?).is_ok());
    replace_file(&setup.keys_path, &crate::common::keys_text(true, NOW + LIFETIME * LIFETIME))?;
    core_config::reload::reload(&setup.engine);
    let refusal = verify(&setup, &routine_envelope(&command(SECOND, Action::Ping))?);
    assert!(matches!(refusal, Err(CommandError::KeyRevoked)));
    assert!(verify(&setup, &sensitive_envelope(&command(THIRD, Action::Isolate))?).is_ok());
    Ok(())
}


#[test]
fn expired_and_not_yet_valid_keys_are_refused_after_a_live_reload() -> TestResult {
    let setup = setup()?;
    replace_file(&setup.keys_path, &crate::common::keys_text(false, NOW - 1))?;
    core_config::reload::reload(&setup.engine);
    let expired = verify(&setup, &routine_envelope(&command(1, Action::Ping))?);
    assert!(matches!(expired, Err(CommandError::KeyOutsideValidity)));
    let early = agent_command::verify::verify_command(&setup.verifier, &routine_envelope(&command(SECOND, Action::Ping))?, NOW - LIFETIME - 1);
    assert!(matches!(early, Err(CommandError::KeyOutsideValidity)));
    Ok(())
}

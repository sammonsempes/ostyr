use crate::common::types::TestResult;
use crate::common::{command, signing_key, SEED_LENGTH};
use agent_command::error::SignError;
use agent_command::model::{Action, NONCE_LENGTH};
use agent_command::sign::{memory_signer, new_nonce, os_random, sign_command};


fn failing_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn the_signer_is_injected() -> TestResult {
    let sent = command(1, Action::Ping);
    let first = sign_command(&sent, "k", &memory_signer(signing_key(1)))?;
    let second = sign_command(&sent, "k", &memory_signer(signing_key(1)))?;
    assert_eq!(first, second, "the encoding and the signature are deterministic");
    let calls = sign_command(&sent, "k", &|message: &[u8]| Ok(message.to_vec()))?;
    assert_ne!(first, calls);
    Ok(())
}


#[test]
fn a_failing_signer_is_reported() -> TestResult {
    let result = sign_command(&command(1, Action::Ping), "k", &|_message: &[u8]| Err("hsm offline".into()));
    assert!(matches!(result, Err(SignError::Signer(_))));
    Ok(())
}


#[test]
fn nonces_are_random_and_failures_are_reported() -> TestResult {
    let first = new_nonce(os_random)?;
    let second = new_nonce(os_random)?;
    assert_eq!(first.len(), NONCE_LENGTH);
    assert_ne!(first, second);
    assert!(new_nonce(failing_fill).is_err());
    let mut seed = [0; SEED_LENGTH];
    os_random(&mut seed)?;
    assert_ne!(seed, [0; SEED_LENGTH]);
    Ok(())
}

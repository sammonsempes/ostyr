use crate::common::types::TestResult;
use crate::common::{claims, setup, token_for, LIFETIME, NOW, PEER, SLACK, SMALL_CAP, TENANT};
use remote_desktop::error::TokenError;
use remote_desktop::model::{ReplaySet, DEFAULT_LIVE_TOKENS, MAX_PRUNE_PER_CALL, NONCE_LENGTH};
use remote_desktop::replay::{admit, live_tokens, prune, refused_full};
use remote_desktop::token::verify_token;


const TOKEN_COUNT: u64 = 200_000;


const EXPIRY: u64 = 1_000;


fn nonce(number: u64) -> [u8; NONCE_LENGTH] {
    let mut bytes = [0; NONCE_LENGTH];
    bytes.iter_mut().zip(number.to_be_bytes()).for_each(|(slot, byte)| *slot = byte);
    bytes
}


#[test]
fn a_full_set_refuses_new_tokens_and_never_evicts_a_live_nonce() -> TestResult {
    let mut set = ReplaySet::default();
    (0..SMALL_CAP as u64).try_for_each(|number| admit(&mut set, nonce(number), EXPIRY, 0, SMALL_CAP))?;
    let full = admit(&mut set, nonce(TOKEN_COUNT), EXPIRY, 0, SMALL_CAP).err().ok_or("admitted")?;
    assert!(matches!(full, TokenError::ReplayFull));
    assert_eq!(set.nonces.len(), SMALL_CAP);
    assert_eq!(set.refused_full, 1);
    let replay = admit(&mut set, nonce(0), EXPIRY, 0, SMALL_CAP).err().ok_or("admitted")?;
    assert!(matches!(replay, TokenError::Replayed));
    assert_eq!(set.refused_full, 1);
    Ok(())
}


#[test]
fn the_set_recovers_once_tokens_expire() -> TestResult {
    let mut set = ReplaySet::default();
    (0..SMALL_CAP as u64).try_for_each(|number| admit(&mut set, nonce(number), EXPIRY, 0, SMALL_CAP))?;
    assert!(admit(&mut set, nonce(TOKEN_COUNT), EXPIRY + SLACK, EXPIRY - 1, SMALL_CAP).is_err());
    admit(&mut set, nonce(TOKEN_COUNT), EXPIRY + SLACK, EXPIRY, SMALL_CAP)?;
    assert_eq!(set.nonces.len(), 1);
    assert_eq!(set.by_expiry.len(), 1);
    Ok(())
}


#[test]
fn pruning_does_at_most_the_bounded_work_per_call() -> TestResult {
    let mut set = ReplaySet::default();
    let total = MAX_PRUNE_PER_CALL as u64 + MAX_PRUNE_PER_CALL as u64;
    (0..total).try_for_each(|number| admit(&mut set, nonce(number), EXPIRY, 0, DEFAULT_LIVE_TOKENS))?;
    prune(&mut set, EXPIRY);
    assert_eq!(set.nonces.len(), MAX_PRUNE_PER_CALL);
    assert_eq!(set.by_expiry.len(), MAX_PRUNE_PER_CALL);
    prune(&mut set, EXPIRY - 1);
    assert_eq!(set.nonces.len(), MAX_PRUNE_PER_CALL);
    prune(&mut set, EXPIRY);
    assert!(set.nonces.is_empty());
    Ok(())
}


#[test]
fn two_hundred_thousand_distinct_tokens_never_grow_the_set_past_the_cap() -> TestResult {
    let mut set = ReplaySet::default();
    let refused = (0..TOKEN_COUNT)
        .filter(|number| admit(&mut set, nonce(*number), EXPIRY, 0, DEFAULT_LIVE_TOKENS).is_err())
        .count();
    assert_eq!(set.nonces.len(), DEFAULT_LIVE_TOKENS);
    assert_eq!(set.by_expiry.len(), DEFAULT_LIVE_TOKENS);
    assert_eq!(refused as u64, TOKEN_COUNT - DEFAULT_LIVE_TOKENS as u64);
    assert_eq!(set.refused_full, TOKEN_COUNT - DEFAULT_LIVE_TOKENS as u64);
    admit(&mut set, nonce(TOKEN_COUNT), EXPIRY + EXPIRY, EXPIRY, DEFAULT_LIVE_TOKENS)?;
    Ok(())
}


#[test]
fn the_verifier_counts_live_tokens_and_full_refusals_with_an_injected_clock() -> TestResult {
    let setup = setup()?;
    (0..SMALL_CAP as u8).try_for_each(|number| {
        verify_token(&setup.verifier, &token_for(&claims(number))?, PEER, TENANT, NOW)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(live_tokens(&setup.verifier), SMALL_CAP);
    let extra = token_for(&claims(SMALL_CAP as u8))?;
    let refused = verify_token(&setup.verifier, &extra, PEER, TENANT, NOW).err().ok_or("accepted")?;
    assert_eq!(refused.to_string(), "too many live tokens, token refused");
    assert_eq!(refused_full(&setup.verifier), 1);
    let later = NOW + LIFETIME + 1;
    let mut fresh = claims(SMALL_CAP as u8);
    fresh.not_before = later;
    fresh.expires_at = later + LIFETIME;
    verify_token(&setup.verifier, &token_for(&fresh)?, PEER, TENANT, later)?;
    assert_eq!(live_tokens(&setup.verifier), 1);
    Ok(())
}

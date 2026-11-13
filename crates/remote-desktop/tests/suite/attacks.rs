use crate::common::types::TestResult;
use crate::common::{claims, relay_keys_text, setup, setup_with, token_for, NOW, PEER, SECOND_NONCE, SLACK, SMALL_CAP, TENANT, THIRD_NONCE};
use data_encoding::BASE64URL_NOPAD;
use remote_desktop::model::CLOCK_SKEW_SECONDS;
use remote_desktop::token::verify_token;
use std::thread;


const REPLAYS: usize = 1_000;


const THREADS: usize = 8;


const PER_THREAD: usize = 125;


#[test]
fn flipping_one_bit_anywhere_in_the_token_refuses_it() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    let bytes = BASE64URL_NOPAD.decode(token.as_bytes())?;
    (0..bytes.len()).try_for_each(|position| {
        let mut flipped = bytes.clone();
        flipped.iter_mut().skip(position).take(1).for_each(|byte| *byte ^= 1);
        let accepted = verify_token(&setup.verifier, &BASE64URL_NOPAD.encode(&flipped), PEER, TENANT, NOW).is_ok();
        if accepted {
            Err(format!("a token flipped at byte {position} was accepted"))
        } else {
            Ok(())
        }
    })?;
    assert!(verify_token(&setup.verifier, &token, PEER, TENANT, NOW).is_ok());
    Ok(())
}


#[test]
fn a_token_replayed_a_thousand_times_is_accepted_exactly_once() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    let accepted = (0..REPLAYS)
        .filter(|_| verify_token(&setup.verifier, &token, PEER, TENANT, NOW).is_ok())
        .count();
    assert_eq!(accepted, 1);
    Ok(())
}


#[test]
fn a_token_replayed_from_eight_threads_is_accepted_exactly_once() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    let accepted = thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    (0..PER_THREAD)
                        .filter(|_| verify_token(&setup.verifier, &token, PEER, TENANT, NOW).is_ok())
                        .count()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "a worker panicked"))
            .sum::<Result<usize, &str>>()
    })?;
    assert_eq!(accepted, 1);
    Ok(())
}


#[test]
fn extreme_times_are_refused_without_overflow() -> TestResult {
    let setup = setup()?;
    let mut longest = claims(1);
    longest.not_before = 0;
    longest.expires_at = u64::MAX;
    assert_eq!(
        verify_token(&setup.verifier, &token_for(&longest)?, PEER, TENANT, NOW)
            .err()
            .ok_or("accepted")?
            .to_string(),
        "token lifetime is longer than the maximum"
    );
    let mut empty = claims(SECOND_NONCE);
    empty.not_before = u64::MAX;
    empty.expires_at = u64::MAX;
    assert_eq!(
        verify_token(&setup.verifier, &token_for(&empty)?, PEER, TENANT, NOW)
            .err()
            .ok_or("accepted")?
            .to_string(),
        "token expires at or before its start"
    );
    let wide = setup_with(&relay_keys_text(0, u64::MAX, false), SMALL_CAP)?;
    let mut far = claims(THIRD_NONCE);
    far.not_before = u64::MAX - 1;
    far.expires_at = u64::MAX;
    assert_eq!(
        verify_token(&wide.verifier, &token_for(&far)?, PEER, TENANT, u64::MAX - CLOCK_SKEW_SECONDS - SLACK)
            .err()
            .ok_or("accepted")?
            .to_string(),
        "token starts in the future beyond the clock skew"
    );
    Ok(())
}

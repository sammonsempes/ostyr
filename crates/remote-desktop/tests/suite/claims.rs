use crate::common::types::TestResult;
use crate::common::{claims, setup, signing_key, token_for, KEY_ID, NOW, PEER, RELAY_SEED, SECOND_NONCE, TENANT};
use remote_desktop::claims::{check_claims, check_expectation, check_issuable, check_key_id, check_peer, check_subject};
use remote_desktop::error::{ClaimError, IssueError, TokenError};
use remote_desktop::model::{MAX_KEY_ID_BYTES, MAX_LIFETIME_SECONDS, MAX_PEER_ID_DIGITS, MAX_SUBJECT_BYTES};
use remote_desktop::sign::memory_signer;
use remote_desktop::token::{issue_token, seal, verify_token};


const HOMOGLYPH_SUBJECT: &str = "alice\u{3164}";


#[test]
fn the_subject_grammar_is_an_ascii_allowlist_of_one_to_255_bytes() -> TestResult {
    assert!(check_subject("aZ09-_.@:+/=|").is_ok());
    assert!(check_subject(&"a".repeat(MAX_SUBJECT_BYTES)).is_ok());
    assert!(check_subject(&"a".repeat(MAX_SUBJECT_BYTES + 1)).is_err());
    assert!(check_subject("").is_err());
    assert!(check_subject(HOMOGLYPH_SUBJECT).is_err());
    assert!(check_subject("a b").is_err());
    assert!(check_subject("a\nb").is_err());
    Ok(())
}


#[test]
fn the_peer_grammar_is_one_to_twenty_digits() -> TestResult {
    assert!(check_peer("123456789").is_ok());
    assert!(check_peer(&"9".repeat(MAX_PEER_ID_DIGITS)).is_ok());
    assert!(check_peer(&"9".repeat(MAX_PEER_ID_DIGITS + 1)).is_err());
    assert!(check_peer("").is_err());
    assert!(check_peer("12a").is_err());
    assert!(check_peer("-1").is_err());
    ["abc_123", "a12345", "ab-cde", "abcdefghijklmnop"]
        .iter()
        .try_for_each(|peer| check_peer(peer).map_err(|_| *peer))?;
    ["1a", "_abc12", "abcde", "abcdefghijklmnopq", "12 34", "-abcde", "abcdé1"]
        .iter()
        .for_each(|peer| assert!(check_peer(peer).is_err(), "{peer}"));
    Ok(())
}


#[test]
fn the_key_id_grammar_starts_alphanumeric_and_stops_at_64_bytes() -> TestResult {
    assert!(check_key_id("relay-1.a_b").is_ok());
    assert!(check_key_id(&"k".repeat(MAX_KEY_ID_BYTES)).is_ok());
    assert!(check_key_id(&"k".repeat(MAX_KEY_ID_BYTES + 1)).is_err());
    assert!(check_key_id("").is_err());
    assert!(check_key_id("-k").is_err());
    assert!(check_key_id("../k").is_err());
    assert!(check_key_id("k k").is_err());
    Ok(())
}


#[test]
fn each_claim_is_checked_and_the_error_names_the_claim_only() -> TestResult {
    assert!(check_claims(&claims(1)).is_ok());
    let mut tenant = claims(1);
    tenant.tenant = "-x".to_owned();
    assert!(matches!(check_claims(&tenant), Err(ClaimError::Tenant(_))));
    let mut subject = claims(1);
    subject.viewer_subject = HOMOGLYPH_SUBJECT.to_owned();
    assert!(matches!(check_claims(&subject), Err(ClaimError::Subject)));
    let mut peer = claims(1);
    peer.device_peer_id = "12a".to_owned();
    assert!(matches!(check_claims(&peer), Err(ClaimError::Peer)));
    let mut key = claims(1);
    key.key_id = "../k".to_owned();
    let refused = check_claims(&key).err().ok_or("accepted")?;
    assert!(matches!(refused, ClaimError::KeyId));
    assert_eq!(refused.to_string(), "the key id claim is invalid");
    Ok(())
}


#[test]
fn issue_refuses_what_the_verifier_would_refuse() -> TestResult {
    let signer = memory_signer(signing_key(RELAY_SEED));
    let mut long = claims(1);
    long.expires_at = long.not_before + MAX_LIFETIME_SECONDS + 1;
    assert!(matches!(issue_token(&signer, &long), Err(IssueError::LifetimeTooLong)));
    let mut backwards = claims(1);
    backwards.expires_at = backwards.not_before - 1;
    assert!(matches!(issue_token(&signer, &backwards), Err(IssueError::InvalidLifetime)));
    let mut empty = claims(1);
    empty.expires_at = empty.not_before;
    assert!(matches!(issue_token(&signer, &empty), Err(IssueError::InvalidLifetime)));
    let mut edge = claims(1);
    edge.expires_at = edge.not_before + MAX_LIFETIME_SECONDS;
    assert!(issue_token(&signer, &edge).is_ok());
    let mut hostile = claims(1);
    hostile.viewer_subject = HOMOGLYPH_SUBJECT.to_owned();
    hostile.tenant = "-x".to_owned();
    hostile.device_peer_id = "12a".to_owned();
    hostile.key_id = "../k".to_owned();
    assert!(matches!(issue_token(&signer, &hostile), Err(IssueError::Claims(_))));
    assert!(matches!(check_issuable(&hostile), Err(IssueError::Claims(_))));
    Ok(())
}


#[test]
fn a_hand_signed_token_with_bad_claims_is_refused_at_verify() -> TestResult {
    let setup = setup()?;
    let signer = memory_signer(signing_key(RELAY_SEED));
    let mut hostile = claims(1);
    hostile.viewer_subject = HOMOGLYPH_SUBJECT.to_owned();
    let token = seal(&signer, KEY_ID, postcard::to_stdvec(&hostile)?)?;
    let refused = verify_token(&setup.verifier, &token, PEER, TENANT, NOW).err().ok_or("accepted")?;
    assert!(matches!(refused, TokenError::Claims(ClaimError::Subject)));
    let mut bad_key = claims(SECOND_NONCE);
    bad_key.key_id = "../k".to_owned();
    let key_token = seal(&signer, KEY_ID, postcard::to_stdvec(&bad_key)?)?;
    let key_refused = verify_token(&setup.verifier, &key_token, PEER, TENANT, NOW).err().ok_or("accepted")?;
    assert!(matches!(key_refused, TokenError::Claims(ClaimError::KeyId)));
    Ok(())
}


#[test]
fn an_invalid_expectation_is_refused_before_the_token_is_read() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    assert!(matches!(check_expectation("", TENANT), Err(TokenError::BadExpectation)));
    assert!(matches!(check_expectation(PEER, ""), Err(TokenError::BadExpectation)));
    assert!(check_expectation(PEER, TENANT).is_ok());
    ["!!not a token!!", token.as_str()].iter().try_for_each(|input| {
        [("", TENANT), (PEER, ""), ("12a", TENANT), (PEER, "-x")]
            .iter()
            .try_for_each(|(peer, tenant)| {
                let refused = verify_token(&setup.verifier, input, peer, tenant, NOW).err().ok_or("accepted")?;
                assert_eq!(refused.to_string(), "the expected peer or tenant is invalid");
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    })?;
    assert!(verify_token(&setup.verifier, &token, PEER, TENANT, NOW).is_ok());
    Ok(())
}

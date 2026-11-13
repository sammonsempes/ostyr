use crate::common::types::{ClaimsChange, RefusalCase, TestResult};
use crate::common::{
    claims, relay_keys_text, setup, setup_with, signing_key, token_for, token_with, Setup, AGENT_SEED, CASE_COUNT, GARBAGE_BYTE, GARBAGE_LENGTH,
    KEY_ID, LIFETIME, NOW, OTHER_SEED, PEER, RELAY_SEED, SECOND_NONCE, SHORT_SIGNATURE_LENGTH, SMALL_CAP, TENANT,
};
use data_encoding::BASE64URL_NOPAD;
use remote_desktop::error::{CodecError, IssueError, TokenError, VerifierError};
use remote_desktop::model::{Envelope, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS, MAX_LIVE_TOKENS_CEILING, MAX_TOKEN_BYTES};
use remote_desktop::sign::memory_signer;
use remote_desktop::token::{check_token, issue_token, open_verifier, seal, verify_token};


const OVERSIZE_SUBJECT: usize = 600;


fn refusal_at(setup: &Setup, token: &str, now: u64) -> Result<String, Box<dyn std::error::Error>> {
    Ok(verify_token(&setup.verifier, token, PEER, TENANT, now)
        .err()
        .ok_or("the token was accepted")?
        .to_string())
}


fn refusal_of(change: ClaimsChange, now: u64) -> Result<String, Box<dyn std::error::Error>> {
    let setup = setup()?;
    let mut changed = claims(1);
    change(&mut changed);
    refusal_at(&setup, &token_for(&changed)?, now)
}


fn seal_claims(claims_bytes: Vec<u8>, seed: u8) -> Result<String, Box<dyn std::error::Error>> {
    Ok(seal(&memory_signer(signing_key(seed)), KEY_ID, claims_bytes)?)
}


#[test]
fn a_valid_token_is_accepted_once_then_refused_as_replayed() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    let accepted = verify_token(&setup.verifier, &token, PEER, TENANT, NOW)?;
    assert_eq!(accepted, claims(1));
    assert_eq!(refusal_at(&setup, &token, NOW)?, "token was already used");
    Ok(())
}


#[test]
fn each_field_refuses_a_token_valid_in_every_other_field() -> TestResult {
    let cases: [RefusalCase; CASE_COUNT] = [
        (
            "token expires at or before its start",
            |claims| claims.expires_at = claims.not_before,
            NOW,
        ),
        (
            "token lifetime is longer than the maximum",
            |claims| claims.expires_at = claims.not_before + MAX_LIFETIME_SECONDS + 1,
            NOW,
        ),
        (
            "token starts in the future beyond the clock skew",
            |claims| claims.not_before = NOW + CLOCK_SKEW_SECONDS + 1,
            NOW,
        ),
        ("token is expired", |_claims| {}, NOW + LIFETIME),
        (
            "token is for another device",
            |claims| claims.device_peer_id = "987654321".to_owned(),
            NOW,
        ),
        ("token is for another tenant", |claims| claims.tenant = "other".to_owned(), NOW),
        ("token expires at or before its start", |claims| claims.expires_at = 0, NOW),
        ("token is expired", |claims| claims.not_before = NOW - 1, NOW + LIFETIME),
    ];
    cases.iter().try_for_each(|(expected, change, now)| {
        assert_eq!(refusal_of(*change, *now)?, *expected);
        Ok(())
    })
}


#[test]
fn claims_bound_to_another_key_id_than_the_envelope_are_refused() -> TestResult {
    let setup = setup()?;
    let mut other = claims(1);
    other.key_id = "relay-2".to_owned();
    let token = seal_claims(postcard::to_stdvec(&other)?, RELAY_SEED)?;
    assert_eq!(refusal_at(&setup, &token, NOW)?, "token is bound to another signing key");
    Ok(())
}


#[test]
fn a_lifetime_of_exactly_the_maximum_and_the_skew_edge_are_accepted() -> TestResult {
    let setup = setup()?;
    let mut edge = claims(1);
    edge.not_before = NOW + CLOCK_SKEW_SECONDS;
    edge.expires_at = edge.not_before + MAX_LIFETIME_SECONDS;
    assert_eq!(verify_token(&setup.verifier, &token_for(&edge)?, PEER, TENANT, NOW)?, edge);
    Ok(())
}


#[test]
fn a_refused_token_does_not_burn_its_nonce() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    assert_eq!(
        verify_token(&setup.verifier, &token, "987654321", TENANT, NOW)
            .err()
            .ok_or("accepted")?
            .to_string(),
        "token is for another device"
    );
    assert_eq!(verify_token(&setup.verifier, &token, PEER, TENANT, NOW)?, claims(1));
    Ok(())
}


#[test]
fn the_peer_is_checked_before_the_tenant() -> TestResult {
    let setup = setup()?;
    let token = token_for(&claims(1))?;
    let refused = verify_token(&setup.verifier, &token, "987654321", "other", NOW).err().ok_or("accepted")?;
    assert!(matches!(refused, TokenError::WrongPeer));
    Ok(())
}


#[test]
fn a_token_signed_by_another_key_is_refused() -> TestResult {
    let setup = setup()?;
    assert_eq!(refusal_at(&setup, &token_with(&claims(1), OTHER_SEED)?, NOW)?, "bad signature");
    assert_eq!(refusal_at(&setup, &token_with(&claims(SECOND_NONCE), AGENT_SEED)?, NOW)?, "bad signature");
    Ok(())
}


#[test]
fn an_unknown_key_id_is_refused() -> TestResult {
    let setup = setup()?;
    let mut unknown = claims(1);
    unknown.key_id = "routine-1".to_owned();
    let token = seal(&memory_signer(signing_key(AGENT_SEED)), "routine-1", postcard::to_stdvec(&unknown)?)?;
    assert_eq!(refusal_at(&setup, &token, NOW)?, "unknown signing key");
    Ok(())
}


#[test]
fn a_revoked_key_and_a_key_outside_its_validity_are_refused() -> TestResult {
    let token = token_for(&claims(1))?;
    let revoked = setup_with(&relay_keys_text(NOW - LIFETIME, NOW + LIFETIME, true), SMALL_CAP)?;
    assert_eq!(refusal_at(&revoked, &token, NOW)?, "signing key is revoked");
    let not_yet = setup_with(&relay_keys_text(NOW + 1, NOW + LIFETIME, false), SMALL_CAP)?;
    assert_eq!(refusal_at(&not_yet, &token, NOW)?, "signing key is outside its validity period");
    let ended = setup_with(&relay_keys_text(NOW - LIFETIME, NOW - 1, false), SMALL_CAP)?;
    assert_eq!(refusal_at(&ended, &token, NOW)?, "signing key is outside its validity period");
    let edge = setup_with(&relay_keys_text(NOW, NOW, false), SMALL_CAP)?;
    assert_eq!(verify_token(&edge.verifier, &token, PEER, TENANT, NOW)?, claims(1));
    Ok(())
}


#[test]
fn trailing_bytes_after_the_claims_are_refused() -> TestResult {
    let setup = setup()?;
    let padded = [postcard::to_stdvec(&claims(1))?, vec![0]].concat();
    let refusal = verify_token(&setup.verifier, &seal_claims(padded, RELAY_SEED)?, PEER, TENANT, NOW);
    assert!(matches!(refusal, Err(TokenError::Malformed(CodecError::TrailingBytes))));
    Ok(())
}


#[test]
fn claims_are_not_decoded_before_the_signature_is_verified() -> TestResult {
    let setup = setup()?;
    let garbage = vec![GARBAGE_BYTE; GARBAGE_LENGTH];
    assert_eq!(refusal_at(&setup, &seal_claims(garbage.clone(), OTHER_SEED)?, NOW)?, "bad signature");
    let decoded = verify_token(&setup.verifier, &seal_claims(garbage, RELAY_SEED)?, PEER, TENANT, NOW);
    assert!(matches!(decoded, Err(TokenError::Malformed(CodecError::Postcard(_)))));
    Ok(())
}


#[test]
fn a_wrong_length_signature_is_a_bad_signature() -> TestResult {
    let setup = setup()?;
    let envelope = Envelope {
        key_id: KEY_ID.to_owned(),
        claims: postcard::to_stdvec(&claims(1))?,
        signature: vec![1; SHORT_SIGNATURE_LENGTH],
    };
    let token = BASE64URL_NOPAD.encode(&postcard::to_stdvec(&envelope)?);
    assert_eq!(refusal_at(&setup, &token, NOW)?, "bad signature");
    Ok(())
}


#[test]
fn a_bad_envelope_and_bad_base64_are_refused() -> TestResult {
    let setup = setup()?;
    assert!(refusal_at(&setup, &BASE64URL_NOPAD.encode(&[GARBAGE_BYTE; SHORT_SIGNATURE_LENGTH]), NOW)?.starts_with("malformed token"));
    let trailing = [
        postcard::to_stdvec(&Envelope {
            key_id: KEY_ID.to_owned(),
            claims: Vec::new(),
            signature: Vec::new(),
        })?,
        vec![0],
    ]
    .concat();
    assert_eq!(
        refusal_at(&setup, &BASE64URL_NOPAD.encode(&trailing), NOW)?,
        "malformed token: trailing bytes after the encoded value"
    );
    assert_eq!(refusal_at(&setup, "not base64 !", NOW)?, "token is not base64url");
    Ok(())
}


#[test]
fn an_oversize_token_is_refused_before_any_decoding() -> TestResult {
    let setup = setup()?;
    let oversize = "!".repeat(MAX_TOKEN_BYTES + 1);
    let refused = check_token(&setup.verifier, &oversize, PEER, TENANT, NOW).err().ok_or("accepted")?;
    assert!(matches!(refused, TokenError::TooLarge));
    assert!(refusal_at(&setup, &"A".repeat(MAX_TOKEN_BYTES), NOW)?.starts_with("malformed token"));
    Ok(())
}


#[test]
fn issuing_refuses_a_failing_signer_and_an_oversize_token() -> TestResult {
    let failing = |_message: &[u8]| Err("vault down".into());
    let refused = issue_token(&failing, &claims(1)).err().ok_or("issued")?;
    assert!(matches!(refused, IssueError::Signer(_)));
    assert_eq!(refused.to_string(), "the signer failed: vault down");
    let mut large = claims(1);
    large.viewer_subject = "a".repeat(OVERSIZE_SUBJECT);
    let too_large = issue_token(&memory_signer(signing_key(RELAY_SEED)), &large).err().ok_or("issued")?;
    assert!(matches!(too_large, IssueError::TooLarge));
    Ok(())
}


#[test]
fn an_issued_token_fits_the_size_limit() -> TestResult {
    assert!(token_for(&claims(1))?.len() <= MAX_TOKEN_BYTES);
    Ok(())
}


#[test]
fn the_live_token_cap_is_bounded() -> TestResult {
    let setup = setup()?;
    let engine = setup.verifier.keys.clone();
    assert_eq!(open_verifier(engine.clone(), 0).err(), Some(VerifierError::LiveTokens));
    assert_eq!(
        open_verifier(engine.clone(), MAX_LIVE_TOKENS_CEILING + 1).err(),
        Some(VerifierError::LiveTokens)
    );
    assert!(open_verifier(engine.clone(), MAX_LIVE_TOKENS_CEILING).is_ok());
    assert!(open_verifier(engine, 1).is_ok());
    Ok(())
}

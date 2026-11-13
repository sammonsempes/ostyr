use crate::claims::{check_claims, check_expectation, check_issuable};
use crate::codec::{decode_exact, signing_message};
use crate::error::{IssueError, TokenError, VerifierError};
use crate::model::{
    Envelope, RelayClaims, RelayKey, RelayKeys, ReplaySet, Verifier, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS, MAX_LIVE_TOKENS_CEILING,
    MAX_TOKEN_BYTES,
};
use crate::replay::{accept_nonce, observe_clock};
use crate::types::SignerFn;
use core_config::reload::{current_config, ReloadEngine};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use std::sync::{Arc, Mutex};
use tracing::warn;


pub fn open_verifier(keys: Arc<ReloadEngine<RelayKeys>>, max_live_tokens: usize) -> Result<Verifier, VerifierError> {
    if max_live_tokens == 0 || max_live_tokens > MAX_LIVE_TOKENS_CEILING {
        Err(VerifierError::LiveTokens)
    } else {
        Ok(Verifier {
            keys,
            replay: Mutex::new(ReplaySet::default()),
            max_live_tokens,
        })
    }
}


/// Signs already-serialised claims; split out so tests can seal bytes that `issue_token` would never produce.
pub fn seal(signer: &SignerFn, key_id: &str, claims: Vec<u8>) -> Result<String, IssueError> {
    let signature = signer(&signing_message(&claims)).map_err(IssueError::Signer)?;
    let bytes = postcard::to_stdvec(&Envelope {
        key_id: key_id.to_owned(),
        claims,
        signature,
    })?;
    let token = BASE64URL_NOPAD.encode(&bytes);
    if token.len() > MAX_TOKEN_BYTES {
        Err(IssueError::TooLarge)
    } else {
        Ok(token)
    }
}


/// The signer is injected: the private key never has to live in this crate.
pub fn issue_token(signer: &SignerFn, claims: &RelayClaims) -> Result<String, IssueError> {
    check_issuable(claims)?;
    seal(signer, &claims.key_id, postcard::to_stdvec(claims)?)
}


pub fn check_size(token: &str) -> Result<(), TokenError> {
    if token.len() > MAX_TOKEN_BYTES {
        Err(TokenError::TooLarge)
    } else {
        Ok(())
    }
}


pub fn check_key(key: &RelayKey, now: u64) -> Result<(), TokenError> {
    if key.revoked {
        Err(TokenError::KeyRevoked)
    } else if now < key.not_before || now > key.not_after {
        Err(TokenError::KeyOutsideValidity)
    } else {
        Ok(())
    }
}


/// The key must cover the whole token life: a token never outlives its key.
pub fn check_key_covers(key: &RelayKey, claims: &RelayClaims) -> Result<(), TokenError> {
    if key.not_before > claims.not_before || key.not_after < claims.expires_at {
        Err(TokenError::KeyOutsideValidity)
    } else {
        Ok(())
    }
}


pub fn check_signature(key: &RelayKey, envelope: &Envelope) -> Result<(), TokenError> {
    let bytes = <[u8; SIGNATURE_LENGTH]>::try_from(envelope.signature.as_slice()).map_err(|_| TokenError::BadSignature)?;
    key.public_key
        .verify_strict(&signing_message(&envelope.claims), &Signature::from_bytes(&bytes))
        .map_err(|_| TokenError::BadSignature)
}


pub fn check_binding(key_id: &str, claims: &RelayClaims) -> Result<(), TokenError> {
    if claims.key_id == key_id {
        Ok(())
    } else {
        Err(TokenError::KeyIdMismatch)
    }
}


pub fn check_times(claims: &RelayClaims, now: u64) -> Result<(), TokenError> {
    if claims.expires_at <= claims.not_before {
        Err(TokenError::InvalidLifetime)
    } else if claims.expires_at - claims.not_before > MAX_LIFETIME_SECONDS {
        Err(TokenError::LifetimeTooLong)
    } else if now >= claims.expires_at {
        Err(TokenError::Expired)
    } else if claims.not_before > now.saturating_add(CLOCK_SKEW_SECONDS) {
        Err(TokenError::NotYetValid)
    } else {
        Ok(())
    }
}


pub fn check_target(claims: &RelayClaims, expected_peer: &str, expected_tenant: &str) -> Result<(), TokenError> {
    if claims.device_peer_id != expected_peer {
        Err(TokenError::WrongPeer)
    } else if claims.tenant != expected_tenant {
        Err(TokenError::WrongTenant)
    } else {
        Ok(())
    }
}


/// The signature is verified over the received bytes before the claims are decoded; the single-use check comes last so a refused token burns nothing.
pub fn check_token(verifier: &Verifier, token: &str, expected_peer: &str, expected_tenant: &str, now: u64) -> Result<RelayClaims, TokenError> {
    check_expectation(expected_peer, expected_tenant)?;
    check_size(token)?;
    let clock = observe_clock(verifier, now);
    let bytes = BASE64URL_NOPAD.decode(token.as_bytes()).map_err(TokenError::BadEncoding)?;
    let envelope: Envelope = decode_exact(&bytes)?;
    let keys = current_config(&verifier.keys);
    let key = keys.keys.get(&envelope.key_id).ok_or(TokenError::UnknownKey)?;
    check_key(key, clock)?;
    check_signature(key, &envelope)?;
    let claims: RelayClaims = decode_exact(&envelope.claims)?;
    check_claims(&claims)?;
    check_binding(&envelope.key_id, &claims)?;
    check_times(&claims, clock)?;
    check_key_covers(key, &claims)?;
    check_target(&claims, expected_peer, expected_tenant)?;
    accept_nonce(verifier, claims.nonce, claims.expires_at, clock)?;
    Ok(claims)
}


/// Fails closed; the refusal is logged with its reason only, never with the claims.
pub fn verify_token(verifier: &Verifier, token: &str, expected_peer: &str, expected_tenant: &str, now: u64) -> Result<RelayClaims, TokenError> {
    check_token(verifier, token, expected_peer, expected_tenant, now).inspect_err(|refusal| {
        let reason = refusal.to_string();
        warn!(reason = reason.as_str(), "relay token refused");
    })
}

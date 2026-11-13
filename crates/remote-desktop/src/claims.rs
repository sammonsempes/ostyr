use crate::error::{ClaimError, IssueError, TokenError};
use crate::model::{RelayClaims, MAX_KEY_ID_BYTES, MAX_LIFETIME_SECONDS, MAX_PEER_ID_DIGITS, MAX_SUBJECT_BYTES};
use core_pg::scope::tenant_scope;


pub fn is_subject_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@' | ':' | '+' | '/' | '=' | '|')
}


pub fn check_subject(subject: &str) -> Result<(), ClaimError> {
    if (1..=MAX_SUBJECT_BYTES).contains(&subject.len()) && subject.chars().all(is_subject_char) {
        Ok(())
    } else {
        Err(ClaimError::Subject)
    }
}


/// RustDesk peer ids are numeric, so the grammar is digits only.
pub fn check_peer(peer: &str) -> Result<(), ClaimError> {
    if (1..=MAX_PEER_ID_DIGITS).contains(&peer.len()) && peer.chars().all(|digit| digit.is_ascii_digit()) {
        Ok(())
    } else {
        Err(ClaimError::Peer)
    }
}


pub fn check_key_id(key_id: &str) -> Result<(), ClaimError> {
    let mut characters = key_id.chars();
    let valid = key_id.len() <= MAX_KEY_ID_BYTES
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '.' | '-'));
    if valid {
        Ok(())
    } else {
        Err(ClaimError::KeyId)
    }
}


/// The grammar of every identity claim, applied at issue and again at verify.
pub fn check_claims(claims: &RelayClaims) -> Result<(), ClaimError> {
    tenant_scope(&claims.tenant).map_err(ClaimError::Tenant)?;
    check_subject(&claims.viewer_subject)?;
    check_peer(&claims.device_peer_id)?;
    check_key_id(&claims.key_id)
}


/// The relay's own expectations are checked before the token is read.
pub fn check_expectation(expected_peer: &str, expected_tenant: &str) -> Result<(), TokenError> {
    if check_peer(expected_peer).is_ok() && tenant_scope(expected_tenant).is_ok() {
        Ok(())
    } else {
        Err(TokenError::BadExpectation)
    }
}


/// What the platform must not sign: a lifetime the verifier refuses, or claims it refuses on grammar.
pub fn check_issuable(claims: &RelayClaims) -> Result<(), IssueError> {
    if claims.expires_at <= claims.not_before {
        Err(IssueError::InvalidLifetime)
    } else if claims.expires_at - claims.not_before > MAX_LIFETIME_SECONDS {
        Err(IssueError::LifetimeTooLong)
    } else {
        Ok(check_claims(claims)?)
    }
}

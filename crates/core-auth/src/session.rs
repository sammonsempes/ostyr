use crate::error::AuthError;
use crate::model::Session;
use crate::random::random_array;
use crate::types::{AccountMap, RandomFn, SessionMap};
use data_encoding::HEXLOWER;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};


pub const SESSION_IDLE_SECONDS: i64 = 900;


pub const SESSION_ABSOLUTE_SECONDS: i64 = 28_800;


pub const TOKEN_BYTES: usize = 32;


pub fn hash_token(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}


pub fn is_live(session: &Session, now: OffsetDateTime) -> bool {
    now - session.last_seen < Duration::seconds(SESSION_IDLE_SECONDS) && now - session.created_at < Duration::seconds(SESSION_ABSOLUTE_SECONDS)
}


pub fn create_session(sessions: &mut SessionMap, user: &str, now: OffsetDateTime, random: RandomFn) -> Result<SecretString, AuthError> {
    let token = HEXLOWER.encode(&random_array::<TOKEN_BYTES>(random)?);
    sessions.insert(
        hash_token(&token),
        Session {
            user: user.to_owned(),
            created_at: now,
            last_seen: now,
        },
    );
    Ok(SecretString::from(token))
}


/// Returns the user of a live session and refreshes its idle timer; an expired session is dropped.
pub fn validate_session(sessions: &mut SessionMap, token: &str, now: OffsetDateTime) -> Result<String, AuthError> {
    let key = hash_token(token);
    let live = sessions.get(&key).is_some_and(|session| is_live(session, now));
    match sessions.get_mut(&key).filter(|_| live) {
        Some(session) => {
            session.last_seen = now;
            Ok(session.user.clone())
        }
        None => {
            sessions.remove(&key);
            Err(AuthError::SessionInvalid)
        }
    }
}


pub fn revoke_session(sessions: &mut SessionMap, token: &str) -> Option<String> {
    sessions.remove(&hash_token(token)).map(|session| session.user)
}


/// Nanoseconds since the epoch, the unit of `Account.sessions_valid_after`; out of range saturates, which revokes every session.
pub fn revocation_marker(now: OffsetDateTime) -> i64 {
    i64::try_from(now.unix_timestamp_nanos()).unwrap_or(i64::MAX)
}


/// Records that every session of `username` created at or before `now` is void, in the account itself so the store file carries it.
pub fn mark_sessions_revoked(accounts: &mut AccountMap, username: &str, now: OffsetDateTime) {
    accounts
        .get_mut(username)
        .into_iter()
        .for_each(|account| account.sessions_valid_after = Some(revocation_marker(now)));
}


/// True when the session was created at or before the owner's revocation marker.
pub fn is_revoked(accounts: &AccountMap, session: &Session) -> bool {
    accounts
        .get(&session.user)
        .and_then(|account| account.sessions_valid_after)
        .is_some_and(|marker| revocation_marker(session.created_at) <= marker)
}


pub fn revoke_user_sessions(sessions: &mut SessionMap, user: &str) -> usize {
    let before = sessions.len();
    sessions.retain(|_, session| session.user != user);
    before - sessions.len()
}


pub fn session_owner(sessions: &SessionMap, token: &str) -> Option<String> {
    sessions.get(&hash_token(token)).map(|session| session.user.clone())
}

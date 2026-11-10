use crate::error::SessionError;
use crate::model::{Opened, Principal, Session, WebState, Window};
use crate::types::Random;
use axum::http::header::COOKIE;
use axum::http::HeaderMap;
use core_api::middleware::rate_key;
use core_auth::random::random_array;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::PoisonError;
use subtle::ConstantTimeEq;


pub const SESSION_COOKIE: &str = "__Host-ostyr_session";


pub const LOGIN_COOKIE: &str = "__Host-ostyr_login";


pub const LANGUAGE_COOKIE: &str = "__Host-ostyr_lang";


pub const SECRET_BYTES: usize = 32;


pub const LOGIN_COOKIE_SECONDS: u64 = 600;


pub const LANGUAGE_COOKIE_SECONDS: u64 = 31_536_000;


/// 256 random bits, URL-safe.
pub fn new_secret(random: Random) -> Result<String, SessionError> {
    Ok(BASE64URL_NOPAD.encode(&random_array::<SECRET_BYTES>(random)?))
}


/// The table is keyed by a digest, so the browser value is never the key.
pub fn session_key(id: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(id.as_bytes()))
}


pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}


pub fn set_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!("{name}={value}; Max-Age={max_age}; Path=/; Secure; HttpOnly; SameSite=Strict")
}


pub fn clear_cookie(name: &str) -> String {
    set_cookie(name, "", 0)
}


pub fn csrf_matches(expected: &str, given: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
}


/// The oldest sessions of the account named exactly `username` (core-auth names are case-sensitive, never folded) beyond room for one more, removed; their API tokens are handed back to be logged out.
pub fn evict_oldest(sessions: &mut BTreeMap<String, Session>, username: &str, cap: usize) -> Vec<SecretString> {
    let mut owned: Vec<(u64, String)> = sessions
        .iter()
        .filter(|(_, session)| session.username == username)
        .map(|(key, session)| (session.expires, key.clone()))
        .collect();
    owned.sort();
    let surplus = (owned.len() + 1).saturating_sub(cap);
    owned
        .into_iter()
        .take(surplus)
        .filter_map(|(_, key)| sessions.remove(&key))
        .map(|session| session.token)
        .collect()
}


/// A fresh identifier and CSRF token for every login; any identifier presented before is never reused.
pub fn create_session(state: &WebState, username: &str, token: SecretString) -> Result<Opened, SessionError> {
    let now = (state.clock)();
    let id = new_secret(state.random)?;
    let csrf = new_secret(state.random)?;
    let mut sessions = state.sessions.lock().unwrap_or_else(PoisonError::into_inner);
    sessions.retain(|_, session| session.expires > now);
    if sessions.len() >= state.limits.max_sessions {
        Err(SessionError::Full)
    } else {
        let evicted = evict_oldest(&mut sessions, username, state.user_sessions_max.load(Ordering::SeqCst));
        sessions.insert(
            session_key(&id),
            Session {
                username: username.to_owned(),
                token,
                csrf: csrf.clone(),
                expires: now.saturating_add(state.limits.session_seconds),
            },
        );
        Ok(Opened { id, evicted })
    }
}


pub fn find_session(state: &WebState, headers: &HeaderMap) -> Option<Principal> {
    let now = (state.clock)();
    let key = session_key(&cookie_value(headers, SESSION_COOKIE)?);
    let sessions = state.sessions.lock().unwrap_or_else(PoisonError::into_inner);
    sessions.get(&key).filter(|session| session.expires > now).map(|session| Principal {
        key: key.clone(),
        token: session.token.clone(),
        csrf: session.csrf.clone(),
    })
}


pub fn drop_session(state: &WebState, key: &str) {
    state.sessions.lock().unwrap_or_else(PoisonError::into_inner).remove(key);
}


/// Counts one login attempt of `source`; `false` once the window holds more than `login_max` or the table of sources is full.
pub fn admit_login(state: &WebState, source: IpAddr) -> bool {
    let now = (state.clock)();
    let key = rate_key(source);
    let limits = &state.limits;
    let mut attempts = state.attempts.lock().unwrap_or_else(PoisonError::into_inner);
    attempts.retain(|_, window| now.saturating_sub(window.started) < limits.login_window_seconds);
    if !attempts.contains_key(&key) && attempts.len() >= limits.max_sources {
        false
    } else {
        let window = attempts.entry(key).or_insert(Window { started: now, count: 0 });
        window.count = window.count.saturating_add(1);
        window.count <= limits.login_max
    }
}

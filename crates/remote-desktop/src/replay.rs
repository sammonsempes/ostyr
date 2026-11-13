use crate::error::TokenError;
use crate::model::{ReplaySet, Verifier, MAX_PRUNE_PER_CALL};
use crate::types::Nonce;
use std::sync::PoisonError;


/// Drops at most `MAX_PRUNE_PER_CALL` entries whose token has expired, oldest first, so one call does bounded work.
pub fn prune(set: &mut ReplaySet, now: u64) {
    let expired: Vec<(u64, Nonce)> = set
        .by_expiry
        .iter()
        .take_while(|(expires_at, _)| *expires_at <= now)
        .take(MAX_PRUNE_PER_CALL)
        .copied()
        .collect();
    expired.iter().for_each(|entry| {
        set.by_expiry.remove(entry);
        set.nonces.remove(&entry.1);
    });
}


/// A full set refuses the new token: a live nonce is never evicted to make room.
pub fn admit(set: &mut ReplaySet, nonce: Nonce, expires_at: u64, now: u64, max_live_tokens: usize) -> Result<(), TokenError> {
    set.high_water = set.high_water.max(now);
    let horizon = set.high_water;
    prune(set, horizon);
    if set.nonces.contains(&nonce) {
        Err(TokenError::Replayed)
    } else if set.nonces.len() >= max_live_tokens {
        set.refused_full = set.refused_full.saturating_add(1);
        Err(TokenError::ReplayFull)
    } else {
        set.nonces.insert(nonce);
        set.by_expiry.insert((expires_at, nonce));
        Ok(())
    }
}


/// Records the clock reading and returns the highest one seen, so a clock stepped back never revives an expired token.
pub fn observe_clock(verifier: &Verifier, now: u64) -> u64 {
    let mut set = verifier.replay.lock().unwrap_or_else(PoisonError::into_inner);
    set.high_water = set.high_water.max(now);
    set.high_water
}


pub fn accept_nonce(verifier: &Verifier, nonce: Nonce, expires_at: u64, now: u64) -> Result<(), TokenError> {
    let mut set = verifier.replay.lock().unwrap_or_else(PoisonError::into_inner);
    admit(&mut set, nonce, expires_at, now, verifier.max_live_tokens)
}


pub fn live_tokens(verifier: &Verifier) -> usize {
    verifier.replay.lock().unwrap_or_else(PoisonError::into_inner).nonces.len()
}


/// How many tokens were refused because the set was full.
pub fn refused_full(verifier: &Verifier) -> u64 {
    verifier.replay.lock().unwrap_or_else(PoisonError::into_inner).refused_full
}

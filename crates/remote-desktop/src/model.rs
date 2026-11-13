use crate::types::Nonce;
use core_config::reload::ReloadEngine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};


pub const CLOCK_SKEW_SECONDS: u64 = 5;


pub const MAX_LIFETIME_SECONDS: u64 = 120;


pub const MAX_TOKEN_BYTES: usize = 512;


pub const DEFAULT_LIVE_TOKENS: usize = 10_000;


pub const MAX_LIVE_TOKENS_CEILING: usize = 100_000;


pub const MAX_PRUNE_PER_CALL: usize = 64;


pub const MAX_SUBJECT_BYTES: usize = 255;


pub const MAX_PEER_ID_DIGITS: usize = 20;


pub const MIN_CUSTOM_PEER_BYTES: usize = 6;


pub const MAX_CUSTOM_PEER_BYTES: usize = 16;


pub const MAX_KEY_ID_BYTES: usize = 64;


pub const MAX_SEED_FILE_BYTES: u64 = 128;


pub const GROUP_OTHER_MASK: u32 = 0o077;


pub const NONCE_LENGTH: usize = 16;


pub const SESSION_ID_LENGTH: usize = 16;


pub const IDENTIFIER_COUNT: usize = 2;


pub const RELAY_SIGNING_CONTEXT: &[u8] = b"ostyr-relay-token-v1\0";


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub key_id: String,
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayClaims {
    pub key_id: String,
    pub tenant: String,
    pub session_id: [u8; SESSION_ID_LENGTH],
    pub device_peer_id: String,
    pub viewer_subject: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub nonce: Nonce,
}


/// What the example tool reads as `<claims-json>`: the tool fills the session id, the nonce and the times.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    pub key_id: String,
    pub tenant: String,
    pub device_peer_id: String,
    pub viewer_subject: String,
    pub lifetime_seconds: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayClass {
    Relay,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayKey {
    pub public_key: VerifyingKey,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawKeyFile")]
pub struct RelayKeys {
    pub keys: BTreeMap<String, RelayKey>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKey {
    pub id: String,
    pub class: RelayClass,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(default)]
    pub revoked: bool,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKeyFile {
    pub keys: Vec<RawKey>,
}


/// `high_water` is the highest clock reading seen; `by_expiry` orders the nonces by `expires_at` so pruning never scans the set.
#[derive(Debug, Default)]
pub struct ReplaySet {
    pub nonces: BTreeSet<Nonce>,
    pub by_expiry: BTreeSet<(u64, Nonce)>,
    pub refused_full: u64,
    pub high_water: u64,
}


/// `replay` is locked from the check to the insertion, so two copies of one token never both pass.
pub struct Verifier {
    pub keys: Arc<ReloadEngine<RelayKeys>>,
    pub replay: Mutex<ReplaySet>,
    pub max_live_tokens: usize,
}


/// One line from the token stream: bounded, so a hostile peer cannot make the reader buffer an unbounded line.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Text(Vec<u8>),
    TooLong,
}

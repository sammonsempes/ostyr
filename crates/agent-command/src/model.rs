use crate::types::SaveFn;
use core_config::reload::ReloadEngine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};


pub const CLOCK_SKEW_SECONDS: u64 = 30;


pub const MAX_LIFETIME_SECONDS: u64 = 600;


pub const NONCE_LENGTH: usize = 16;


pub const SIGNING_CONTEXT: &[u8] = b"ostyr-agent-command-v1\0";


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub key_id: String,
    pub command: Vec<u8>,
    pub signature: Vec<u8>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Ping,
    CollectStatus,
    Isolate,
    Kill { process_id: u32 },
    RunScript { script: String },
    Update { version: String },
    Uninstall,
    ChangePolicy { policy: String },
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub agent_id: String,
    pub tenant: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub nonce: [u8; NONCE_LENGTH],
    pub action: Action,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyClass {
    Routine,
    Sensitive,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub class: KeyClass,
    pub public_key: VerifyingKey,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawKeyFile")]
pub struct TrustedKeys {
    pub keys: BTreeMap<String, TrustedKey>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKey {
    pub id: String,
    pub class: KeyClass,
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


/// `last_sequence` is held during the check and the durable save, so two commands never race.
pub struct Verifier {
    pub agent_id: String,
    pub tenant: String,
    pub keys: Arc<ReloadEngine<TrustedKeys>>,
    pub last_sequence: Mutex<u64>,
    pub save: Box<SaveFn>,
}

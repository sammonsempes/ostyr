use crate::types::SaveFn;
use core_config::reload::ReloadEngine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};


pub const CLOCK_SKEW_SECONDS: u64 = 30;


pub const MAX_LIFETIME_SECONDS: u64 = 600;


/// Largest step one accepted command may add to its class sequence; it only bounds how fast routine numbers can be burnt.
pub const MAX_SEQUENCE_ADVANCE: u64 = 1_000;


pub const MAX_PACKAGES: usize = 256;


pub const MAX_PACKAGE_NAME_LENGTH: usize = 128;


pub const PACKAGE_NAME_PUNCTUATION: &str = ".+-_:~";


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
    InstallUpdates { packages: PackageSelection, reboot: RebootPolicy },
    Reboot { prompt_user: bool, deadline: u64 },
}


/// `AllAllowed` is every update the patch policy allows; `Named` holds at least one validated package name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageSelection {
    AllAllowed,
    Named(Vec<String>),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebootPolicy {
    Never,
    InWindow,
    Required,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub key_id: String,
    pub key_class: KeyClass,
    pub agent_id: String,
    pub tenant: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub nonce: [u8; NONCE_LENGTH],
    pub action: Action,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sequences {
    pub routine: u64,
    pub sensitive: u64,
}


/// `last_sequences` is held during the check and the durable save, so two commands never race.
pub struct Verifier {
    pub agent_id: String,
    pub tenant: String,
    pub keys: Arc<ReloadEngine<TrustedKeys>>,
    pub last_sequences: Mutex<Sequences>,
    pub save: Box<SaveFn>,
}

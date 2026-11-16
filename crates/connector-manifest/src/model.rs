use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::Deserialize;
use std::collections::BTreeMap;


pub const MANIFEST_NAME: &str = "connector.yaml";


pub const SIGNATURE_NAME: &str = "connector.sig";


pub const MAX_MANIFEST_BYTES: usize = 65_536;


pub const MAX_ALIASES: usize = 16;


pub const MAX_REPLAYED_EVENTS: usize = 2_048;


pub const MAX_REPLAY_DEPTH: usize = 4;


pub const MAX_RIGHTS: usize = 64;


pub const MAX_ACTIONS: usize = 64;


pub const MAX_CONFIG_FIELDS: usize = 64;


pub const MAX_TARGETS: usize = 32;


pub const MAX_TRUSTED_KEYS: usize = 64;


pub const MAX_KEYS_BYTES: u64 = 65_536;


pub const MAX_KEY_FILE_BYTES: u64 = 256;


pub const MAX_SIGNATURE_BYTES: u64 = 131_072;


pub const MAX_NAME_BYTES: usize = 64;


pub const MAX_SCOPE_BYTES: usize = 96;


pub const MAX_DEFAULT_BYTES: usize = 256;


pub const MAX_FILE_NAME_BYTES: usize = 128;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Right {
    pub scope: String,
    pub access: Access,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    Automatic,
    AutomaticLimitedDuration,
    Human,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub name: String,
    #[serde(deserialize_with = "crate::bounded::targets")]
    pub targets: Vec<String>,
    pub default_approval: Approval,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigKind {
    String,
    Integer,
    Boolean,
    SecretFile,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigField {
    pub name: String,
    pub kind: ConfigKind,
    pub required: bool,
    pub default: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub version: Version,
    pub publisher: String,
    #[serde(deserialize_with = "crate::bounded::rights")]
    pub rights: Vec<Right>,
    #[serde(deserialize_with = "crate::bounded::actions")]
    pub actions: Vec<ActionSpec>,
    #[serde(deserialize_with = "crate::bounded::config")]
    pub config: Vec<ConfigField>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKey {
    pub id: String,
    pub publisher: String,
    pub public_key: String,
    pub not_after: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawKeyFile {
    #[serde(deserialize_with = "crate::bounded::keys")]
    pub keys: Vec<RawKey>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub publisher: String,
    pub public_key: VerifyingKey,
    pub not_after: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedKeys {
    pub keys: BTreeMap<String, TrustedKey>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    pub sha256: String,
    pub size: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Package {
    pub files: BTreeMap<String, FileDigest>,
    pub manifest: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub total_bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_package_bytes: u64,
}


pub const DEFAULT_LIMITS: Limits = Limits {
    max_files: 256,
    max_file_bytes: 16_777_216,
    max_package_bytes: 67_108_864,
};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFile {
    pub key_id: String,
    pub signature: ed25519_dalek::Signature,
    pub document: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    pub files: BTreeMap<String, FileDigest>,
}

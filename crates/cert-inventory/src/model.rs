use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Rsa,
    Ec,
    Other,
}


/// Inventory record; the SHA-256 fingerprint of the DER certificate is its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertRecord {
    pub fingerprint_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub key_type: KeyType,
    pub key_bits: Option<usize>,
    pub self_signed: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParseOutcome {
    pub records: Vec<CertRecord>,
    pub private_keys_refused: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryState {
    Valid,
    Crossed { threshold_days: u32 },
    Expired,
}

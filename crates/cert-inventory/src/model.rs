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


/// One parsed CT log entry; a precertificate's fingerprint is the SHA-256 of its TBS, not of a final certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtEntry {
    pub record: CertRecord,
    pub all_dns_names: Vec<String>,
    pub subject_cns: Vec<String>,
    pub undecodable_cn: bool,
    pub serial: String,
    pub issuer_der_hex: String,
    pub issuer_key_hash: Option<String>,
    pub precert: bool,
    pub timestamp_ms: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CtOutcome {
    pub entries: Vec<CtEntry>,
    pub skipped_malformed: usize,
    pub skipped_unsupported: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtLimits {
    pub max_json_bytes: usize,
    pub max_entries: usize,
    pub max_leaf_bytes: usize,
}


/// An inventoried precertificate identity: issuer DER hex, serial and RFC 6962 issuer key hash (hex), all required to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSerial {
    pub issuer_der_hex: String,
    pub serial: String,
    pub issuer_key_hash: String,
}

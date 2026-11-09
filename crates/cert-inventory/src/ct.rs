use crate::domain::matches_domain;
use crate::error::CtError;
use crate::model::{CertRecord, CtEntry, CtLimits, CtOutcome};
use crate::parse::{record_from_der, record_from_tbs};
use data_encoding::BASE64;
use serde::Deserialize;
use x509_parser::certificate::TbsCertificate;
use x509_parser::prelude::FromDer;


pub const DEFAULT_LIMITS: CtLimits = CtLimits {
    max_json_bytes: 1 << 24,
    max_entries: 1024,
    max_leaf_bytes: 1 << 16,
};


const ENTRY_TYPE_X509: u64 = 0;


const ENTRY_TYPE_PRECERT: u64 = 1;


const ISSUER_KEY_HASH_BYTES: usize = 32;


const LENGTH_BYTES: usize = 3;


const TIMESTAMP_BYTES: usize = 8;


const ENTRY_TYPE_BYTES: usize = 2;


const BYTE_BITS: u32 = 8;


#[derive(Debug, Deserialize)]
struct EntriesResponse {
    entries: Vec<RawEntry>,
}


#[derive(Debug, Deserialize)]
struct RawEntry {
    leaf_input: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafError {
    Malformed,
    Unsupported,
}


/// Parses an RFC 6962 get-entries response. Certificates and precertificate TBS are not signature-verified (inventory input only, as in `parse_input`).
pub fn parse_entries(bytes: &[u8], limits: &CtLimits) -> Result<CtOutcome, CtError> {
    if bytes.len() > limits.max_json_bytes {
        Err(CtError::JsonTooLarge {
            size: bytes.len(),
            max: limits.max_json_bytes,
        })
    } else {
        let response: EntriesResponse = serde_json::from_slice(bytes).map_err(|error| CtError::Json {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        })?;
        if response.entries.len() > limits.max_entries {
            Err(CtError::TooManyEntries { max: limits.max_entries })
        } else {
            let results = response.entries.iter().map(|entry| entry_of(entry, limits)).collect::<Vec<_>>();
            Ok(CtOutcome {
                skipped_malformed: results.iter().filter(|result| **result == Err(LeafError::Malformed)).count(),
                skipped_unsupported: results.iter().filter(|result| **result == Err(LeafError::Unsupported)).count(),
                entries: results.into_iter().filter_map(Result::ok).collect(),
            })
        }
    }
}


/// Records covering a watched domain whose fingerprint is not in `known_fingerprints`; both lists belong to one tenant.
pub fn unexpected_for_domains<'a>(records: &'a [CertRecord], watched_domains: &[String], known_fingerprints: &[String]) -> Vec<&'a CertRecord> {
    records
        .iter()
        .filter(|record| matches_domain(record, watched_domains) && !known_fingerprints.contains(&record.fingerprint_sha256))
        .collect()
}


fn entry_of(raw: &RawEntry, limits: &CtLimits) -> Result<CtEntry, LeafError> {
    let result = decode_leaf(&raw.leaf_input, limits.max_leaf_bytes).and_then(|leaf| parse_leaf(&leaf));
    if let Err(error) = result {
        tracing::debug!(?error, encoded_bytes = raw.leaf_input.len(), "skipped CT entry");
    }
    result
}


fn decode_leaf(encoded: &str, max_bytes: usize) -> Result<Vec<u8>, LeafError> {
    match BASE64.decode_len(encoded.len()) {
        Ok(decoded_len) if decoded_len <= max_bytes => BASE64.decode(encoded.as_bytes()).map_err(|_| LeafError::Malformed),
        _ => Err(LeafError::Malformed),
    }
}


fn take(bytes: &[u8], count: usize) -> Result<(&[u8], &[u8]), LeafError> {
    bytes.split_at_checked(count).ok_or(LeafError::Malformed)
}


fn take_number(bytes: &[u8], count: usize) -> Result<(u64, &[u8]), LeafError> {
    let (head, rest) = take(bytes, count)?;
    Ok((head.iter().fold(u64::MIN, |acc, byte| (acc << BYTE_BITS) | u64::from(*byte)), rest))
}


fn length_prefixed(bytes: &[u8]) -> Result<&[u8], LeafError> {
    let (length, rest) = take(bytes, LENGTH_BYTES)?;
    let size = length.iter().fold(usize::MIN, |acc, byte| (acc << BYTE_BITS) | usize::from(*byte));
    Ok(take(rest, size)?.0)
}


fn parse_leaf(leaf: &[u8]) -> Result<CtEntry, LeafError> {
    let (version, after_version) = take_number(leaf, 1)?;
    let (leaf_type, after_type) = take_number(after_version, 1)?;
    let (timestamp_ms, after_timestamp) = take_number(after_type, TIMESTAMP_BYTES)?;
    let (entry_type, rest) = take_number(after_timestamp, ENTRY_TYPE_BYTES)?;
    if version != 0 || leaf_type != 0 {
        Err(LeafError::Unsupported)
    } else {
        match entry_type {
            ENTRY_TYPE_X509 => Ok(CtEntry {
                record: record_from_der(length_prefixed(rest)?).map_err(|_| LeafError::Malformed)?,
                precert: false,
                timestamp_ms,
            }),
            ENTRY_TYPE_PRECERT => {
                let tbs_der = length_prefixed(take(rest, ISSUER_KEY_HASH_BYTES)?.1)?;
                let (_, tbs) = TbsCertificate::from_der(tbs_der).map_err(|_| LeafError::Malformed)?;
                Ok(CtEntry {
                    record: record_from_tbs(&tbs, tbs_der).map_err(|_| LeafError::Malformed)?,
                    precert: true,
                    timestamp_ms,
                })
            }
            _ => Err(LeafError::Unsupported),
        }
    }
}

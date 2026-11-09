use crate::domain::covers_zone;
use crate::error::CtError;
use crate::model::{CtEntry, CtLimits, CtOutcome, KnownSerial};
use crate::parse::{all_dns_names, record_with_names, serial_hex, MAX_DNS_NAMES};
use data_encoding::{BASE64, HEXLOWER};
use serde::Deserialize;
use x509_parser::certificate::TbsCertificate;
use x509_parser::der_parser::asn1_rs::Tag;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::AttributeTypeAndValue;


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


const BMP_UNIT_BYTES: usize = 2;


const UNIVERSAL_UNIT_BYTES: usize = 4;


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


/// Parses an RFC 6962 get-entries response. The entry count is checked after serde built the vector; memory is bounded by `max_json_bytes`. Certificates and precertificate TBS are not signature-verified (inventory input only, as in `parse_input`).
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


/// Entries covering a watched zone over every DNS SAN, neither a known fingerprint nor a known (issuer, serial); one tenant's lists.
pub fn unexpected_for_domains<'a>(
    entries: &'a [CtEntry],
    watched_domains: &[String],
    known_fingerprints: &[String],
    known_serials: &[KnownSerial],
) -> Vec<&'a CtEntry> {
    entries
        .iter()
        .filter(|entry| {
            (entry.undecodable_cn
                || watch_names(entry)
                    .iter()
                    .any(|name| watched_domains.iter().any(|zone| covers_zone(name, zone))))
                && !known_fingerprints.contains(&entry.record.fingerprint_sha256)
                && !known_serials.iter().any(|known| is_known_serial(known, entry))
        })
        .collect()
}


fn watch_names(entry: &CtEntry) -> &[String] {
    if entry.all_dns_names.is_empty() {
        &entry.subject_cns
    } else {
        &entry.all_dns_names
    }
}


fn is_known_serial(known: &KnownSerial, entry: &CtEntry) -> bool {
    entry.precert
        && known.issuer_der_hex == entry.issuer_der_hex
        && known.serial == entry.serial
        && entry.issuer_key_hash.as_deref() == Some(known.issuer_key_hash.as_str())
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
            ENTRY_TYPE_X509 => {
                let (_, certificate) = parse_x509_certificate(length_prefixed(rest)?).map_err(|_| LeafError::Malformed)?;
                entry_from_tbs(&certificate.tbs_certificate, certificate.as_ref(), None, timestamp_ms)
            }
            ENTRY_TYPE_PRECERT => {
                let (key_hash, after_hash) = take(rest, ISSUER_KEY_HASH_BYTES)?;
                let tbs_der = length_prefixed(after_hash)?;
                let (_, tbs) = TbsCertificate::from_der(tbs_der).map_err(|_| LeafError::Malformed)?;
                entry_from_tbs(&tbs, tbs_der, Some(key_hash), timestamp_ms)
            }
            _ => Err(LeafError::Unsupported),
        }
    }
}


/// The parse error is mapped to its kind on purpose: causes carry certificate bytes (criterion 3). The subject CNs are read only when there is no DNS SAN.
fn entry_from_tbs(tbs: &TbsCertificate<'_>, identity_bytes: &[u8], key_hash: Option<&[u8]>, timestamp_ms: u64) -> Result<CtEntry, LeafError> {
    let names = all_dns_names(tbs).map_err(|_| LeafError::Malformed)?;
    let (subject_cns, undecodable_cn) = if names.is_empty() { common_names(tbs) } else { (Vec::new(), false) };
    Ok(CtEntry {
        record: record_with_names(tbs, identity_bytes, names.iter().take(MAX_DNS_NAMES).cloned().collect()),
        all_dns_names: names,
        subject_cns,
        undecodable_cn,
        serial: serial_hex(tbs),
        issuer_der_hex: HEXLOWER.encode(tbs.issuer().as_raw()),
        issuer_key_hash: key_hash.map(|hash| HEXLOWER.encode(hash)),
        precert: key_hash.is_some(),
        timestamp_ms,
    })
}


fn common_names(tbs: &TbsCertificate<'_>) -> (Vec<String>, bool) {
    let decoded = tbs.subject().iter_common_name().map(common_name_text).collect::<Vec<_>>();
    (decoded.iter().flatten().cloned().collect(), decoded.iter().any(Option::is_none))
}


fn common_name_text(attribute: &AttributeTypeAndValue<'_>) -> Option<String> {
    let tag = attribute.attr_value().tag();
    if tag == Tag::BmpString {
        char::decode_utf16(
            attribute
                .as_slice()
                .chunks(BMP_UNIT_BYTES)
                .map(|unit| <[u8; BMP_UNIT_BYTES]>::try_from(unit).ok().map(u16::from_be_bytes))
                .collect::<Option<Vec<u16>>>()?,
        )
        .collect::<Result<String, _>>()
        .ok()
    } else if tag == Tag::UniversalString {
        attribute
            .as_slice()
            .chunks(UNIVERSAL_UNIT_BYTES)
            .map(|unit| {
                <[u8; UNIVERSAL_UNIT_BYTES]>::try_from(unit)
                    .ok()
                    .and_then(|bytes| char::from_u32(u32::from_be_bytes(bytes)))
            })
            .collect::<Option<String>>()
    } else {
        attribute.as_str().map(str::to_string).ok()
    }
}

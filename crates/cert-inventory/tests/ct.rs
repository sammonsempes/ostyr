#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use cert_inventory::ct::{parse_entries, unexpected_for_domains, DEFAULT_LIMITS};
use cert_inventory::error::CtError;
use cert_inventory::model::CtLimits;
use data_encoding::{BASE64, HEXLOWER};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use record::record_with;
use sha2::{Digest, Sha256};
use types::TestResult;
use x509_parser::parse_x509_certificate;


const TIMESTAMP_MS: u64 = 1_700_000_000_123;


const SAN_OID: [u64; 4] = [2, 5, 29, 17];


const NOT_A_NAME_LIST: [u8; 3] = [0x04, 0x01, 0x00];


const LENGTH_SKIP: usize = 5;


const ISSUER_HASH: [u8; 32] = [7; 32];


const UNKNOWN_ENTRY_TYPE: u16 = 9;


const SMALL_JSON_LIMIT: usize = 64;


const SMALL_LEAF_LIMIT: usize = 16;


const TWO_ENTRIES_LIMIT: usize = 1;


const BODY_COUNT: usize = 2;


const BAD_BASE64: &str = "!!!!";


const BAD_BASE64_LENGTH: &str = "A";


const TRUNCATED_LEAF: [u8; 5] = [0, 0, 0, 0, 0];


const OVERSTATED_LENGTH: [u8; 3] = [0xff, 0xff, 0xff];


struct Sample {
    der: Vec<u8>,
    tbs: Vec<u8>,
}


fn sample(names: &[&str]) -> Result<Sample, Box<dyn std::error::Error>> {
    let certificate = CertificateParams::new(names.iter().map(|name| (*name).to_string()).collect::<Vec<_>>())?.self_signed(&KeyPair::generate()?)?;
    let (_, parsed) = parse_x509_certificate(certificate.der())?;
    Ok(Sample {
        der: certificate.der().to_vec(),
        tbs: parsed.tbs_certificate.as_ref().to_vec(),
    })
}


fn u24(length: usize) -> Vec<u8> {
    length.to_be_bytes().iter().skip(LENGTH_SKIP).copied().collect()
}


fn header(version: u8, leaf_type: u8, entry_type: u16) -> Vec<u8> {
    [&[version, leaf_type][..], &TIMESTAMP_MS.to_be_bytes(), &entry_type.to_be_bytes()].concat()
}


fn x509_leaf(der: &[u8]) -> Vec<u8> {
    [header(0, 0, 0), u24(der.len()), der.to_vec()].concat()
}


fn precert_leaf(tbs: &[u8]) -> Vec<u8> {
    [header(0, 0, 1), ISSUER_HASH.to_vec(), u24(tbs.len()), tbs.to_vec()].concat()
}


fn response(leaves: &[Vec<u8>]) -> Vec<u8> {
    let entries = leaves
        .iter()
        .map(|leaf| serde_json::json!({ "leaf_input": BASE64.encode(leaf), "extra_data": "" }))
        .collect::<Vec<_>>();
    serde_json::json!({ "entries": entries }).to_string().into_bytes()
}


fn with_malformed_san() -> Result<Sample, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(&SAN_OID, NOT_A_NAME_LIST.to_vec()));
    let certificate = params.self_signed(&KeyPair::generate()?)?;
    let (_, parsed) = parse_x509_certificate(certificate.der())?;
    Ok(Sample {
        der: certificate.der().to_vec(),
        tbs: parsed.tbs_certificate.as_ref().to_vec(),
    })
}


#[test]
fn x509_and_precert_entries_become_records() -> TestResult {
    let certificate = sample(&["www.example.test", "*.example.test"])?;
    let precert = sample(&["pre.example.test"])?;
    let body = response(&[x509_leaf(&certificate.der), precert_leaf(&precert.tbs)]);
    let outcome = parse_entries(&body, &DEFAULT_LIMITS)?;
    assert_eq!(outcome.skipped_malformed, 0);
    assert_eq!(outcome.skipped_unsupported, 0);
    let first = outcome.entries.first().ok_or("no first")?;
    let second = outcome.entries.get(1).ok_or("no second")?;
    assert!(!first.precert);
    assert_eq!(first.timestamp_ms, TIMESTAMP_MS);
    assert_eq!(first.record.fingerprint_sha256, HEXLOWER.encode(&Sha256::digest(&certificate.der)));
    assert_eq!(first.record.dns_names, ["www.example.test", "*.example.test"]);
    assert!(second.precert);
    assert_eq!(second.record.fingerprint_sha256, HEXLOWER.encode(&Sha256::digest(&precert.tbs)));
    assert_eq!(second.record.dns_names, ["pre.example.test"]);
    Ok(())
}


#[test]
fn oversized_json_is_refused() -> TestResult {
    let limits = CtLimits {
        max_json_bytes: SMALL_JSON_LIMIT,
        ..DEFAULT_LIMITS
    };
    let body = response(&[x509_leaf(&sample(&["a.example.test"])?.der)]);
    assert!(matches!(parse_entries(&body, &limits), Err(CtError::JsonTooLarge { .. })));
    Ok(())
}


#[test]
fn too_many_entries_are_refused() -> TestResult {
    let limits = CtLimits {
        max_entries: TWO_ENTRIES_LIMIT,
        ..DEFAULT_LIMITS
    };
    let leaf = x509_leaf(&sample(&["a.example.test"])?.der);
    let body = response(&[leaf.clone(), leaf]);
    assert!(matches!(parse_entries(&body, &limits), Err(CtError::TooManyEntries { .. })));
    Ok(())
}


#[test]
fn invalid_json_errors_carry_no_input_bytes() -> TestResult {
    let secret = "SECRETMARKER";
    let wrong_type = format!("{{\"entries\":[{{\"leaf_input\":{{\"{secret}\":1}}}}]}}");
    let syntax = format!("{{\"entries\": {secret}");
    let errors = [wrong_type, syntax]
        .iter()
        .map(|body| parse_entries(body.as_bytes(), &DEFAULT_LIMITS))
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), BODY_COUNT);
    assert!(errors.iter().all(|error| matches!(error, CtError::Json { .. })));
    assert!(errors
        .iter()
        .all(|error| !error.to_string().contains(secret) && error.to_string().contains("line")));
    Ok(())
}


fn leaf_body(encoded: &str) -> Vec<u8> {
    serde_json::json!({ "entries": [{ "leaf_input": encoded }] }).to_string().into_bytes()
}


#[test]
fn oversized_leaf_is_counted_and_skipped() -> TestResult {
    let limits = CtLimits {
        max_leaf_bytes: SMALL_LEAF_LIMIT,
        ..DEFAULT_LIMITS
    };
    let body = response(&[x509_leaf(&sample(&["a.example.test"])?.der)]);
    let outcome = parse_entries(&body, &limits)?;
    assert_eq!(outcome.skipped_malformed, 1);
    assert!(outcome.entries.is_empty());
    Ok(())
}


#[test]
fn undecodable_and_truncated_leaves_are_malformed() -> TestResult {
    let good = sample(&["a.example.test"])?;
    let truncated_precert = [header(0, 0, 1), ISSUER_HASH.iter().take(1).copied().collect()].concat();
    let overstated = [header(0, 0, 0), OVERSTATED_LENGTH.to_vec(), good.der.clone()].concat();
    let junk_certificate = x509_leaf(&good.der.iter().take(SMALL_LEAF_LIMIT).copied().collect::<Vec<_>>());
    let junk_tbs = precert_leaf(&good.tbs.iter().take(SMALL_LEAF_LIMIT).copied().collect::<Vec<_>>());
    let bad_san = with_malformed_san()?;
    let encoded = [
        BAD_BASE64.to_string(),
        BAD_BASE64_LENGTH.to_string(),
        BASE64.encode(&TRUNCATED_LEAF),
        BASE64.encode(&truncated_precert),
        BASE64.encode(&overstated),
        BASE64.encode(&junk_certificate),
        BASE64.encode(&junk_tbs),
        BASE64.encode(&x509_leaf(&bad_san.der)),
        BASE64.encode(&precert_leaf(&bad_san.tbs)),
    ];
    let outcomes = encoded
        .iter()
        .map(|leaf| parse_entries(&leaf_body(leaf), &DEFAULT_LIMITS))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(outcomes
        .iter()
        .all(|outcome| outcome.skipped_malformed == 1 && outcome.entries.is_empty()));
    assert_eq!(outcomes.len(), encoded.len());
    Ok(())
}


#[test]
fn unknown_leaf_types_are_counted_unsupported() -> TestResult {
    let der = sample(&["a.example.test"])?.der;
    let leaves = [
        [header(1, 0, 0), u24(der.len()), der.clone()].concat(),
        [header(0, 1, 0), u24(der.len()), der.clone()].concat(),
        [header(0, 0, UNKNOWN_ENTRY_TYPE), u24(der.len()), der].concat(),
    ];
    let outcome = parse_entries(&response(&leaves), &DEFAULT_LIMITS)?;
    assert_eq!(outcome.skipped_unsupported, leaves.len());
    assert_eq!(outcome.skipped_malformed, 0);
    assert!(outcome.entries.is_empty());
    Ok(())
}


#[test]
fn unexpected_certificates_cover_watched_domains_only() -> TestResult {
    let wildcard = record_with(&["*.example.test"], 0);
    let exact = record_with(&["www.example.test"], 0);
    let other = record_with(&["www.other.test"], 0);
    let mut known = record_with(&["www.example.test"], 0);
    known.fingerprint_sha256 = "known".to_string();
    let records = [wildcard.clone(), exact.clone(), other, known];
    let watched = ["www.example.test".to_string(), "api.example.test".to_string()];
    let unexpected = unexpected_for_domains(&records, &watched, &["known".to_string()]);
    assert_eq!(unexpected, [&wildcard, &exact]);
    assert!(unexpected_for_domains(&records, &[], &[]).is_empty());
    Ok(())
}

#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use cert_inventory::ct::{parse_entries, unexpected_for_domains, DEFAULT_LIMITS};
use cert_inventory::error::CtError;
use cert_inventory::model::{CtEntry, CtLimits, KnownSerial};
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


const MANY_SANS: usize = 150;


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


fn entry_with(names: &[&str], fingerprint: &str, issuer: &str, serial: &str) -> CtEntry {
    let mut record = record_with(names, 0);
    record.fingerprint_sha256 = fingerprint.to_string();
    record.issuer = issuer.to_string();
    CtEntry {
        record,
        all_dns_names: strings(names),
        serial: serial.to_string(),
        precert: false,
        timestamp_ms: 0,
    }
}


fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}


fn fingerprints<'a>(entries: &[&'a CtEntry]) -> Vec<&'a str> {
    entries.iter().map(|entry| entry.record.fingerprint_sha256.as_str()).collect()
}


#[test]
fn unexpected_certificates_cover_watched_zones_only() -> TestResult {
    let entries = [
        entry_with(&["*.example.test"], "a", "", ""),
        entry_with(&["www.example.test"], "b", "", ""),
        entry_with(&["login.example.test"], "c", "", ""),
        entry_with(&["EXAMPLE.test."], "d", "", ""),
        entry_with(&["www.other.test"], "e", "", ""),
        entry_with(&["www.example.test"], "known", "", ""),
    ];
    let watched = strings(&["example.test.", ""]);
    let unexpected = unexpected_for_domains(&entries, &watched, &strings(&["known"]), &[]);
    assert_eq!(fingerprints(&unexpected), ["a", "b", "c", "d"]);
    assert!(unexpected_for_domains(&entries, &[], &[], &[]).is_empty());
    Ok(())
}


#[test]
fn known_issuer_serial_pair_filters_precertificates() -> TestResult {
    let mut precert = entry_with(&["www.example.test"], "tbs-digest", "CN=ca", "0a0b");
    precert.precert = true;
    let entries = [
        precert,
        entry_with(&["www.example.test"], "x", "CN=ca", "ffff"),
        entry_with(&["www.example.test"], "y", "CN=other", "0a0b"),
    ];
    let known = [KnownSerial {
        issuer: "CN=ca".to_string(),
        serial: "0a0b".to_string(),
    }];
    let unexpected = unexpected_for_domains(&entries, &strings(&["example.test"]), &[], &known);
    assert_eq!(fingerprints(&unexpected), ["x", "y"]);
    Ok(())
}


#[test]
fn watched_name_after_many_decoy_sans_is_still_reported() -> TestResult {
    let mut names = (0..MANY_SANS).map(|index| format!("decoy{index}.other.test")).collect::<Vec<_>>();
    names.push("login.example.test".to_string());
    let certificate = sample(&names.iter().map(String::as_str).collect::<Vec<_>>())?;
    let outcome = parse_entries(&response(&[x509_leaf(&certificate.der)]), &DEFAULT_LIMITS)?;
    let entry = outcome.entries.first().ok_or("no entry")?;
    assert!(!entry.record.dns_names.contains(&"login.example.test".to_string()));
    assert_eq!(entry.all_dns_names.len(), MANY_SANS + 1);
    assert_eq!(unexpected_for_domains(&outcome.entries, &strings(&["example.test"]), &[], &[]).len(), 1);
    assert!(!entry.serial.is_empty() && !entry.serial.starts_with("00"));
    Ok(())
}

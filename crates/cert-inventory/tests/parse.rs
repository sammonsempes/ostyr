#[path = "common/types.rs"]
mod types;


use cert_inventory::error::CertError;
use cert_inventory::model::KeyType;
use cert_inventory::parse::{parse_input, MAX_CERTIFICATES, MAX_DNS_NAMES, MAX_INPUT_BYTES, MAX_PEM_BLOCKS};
use data_encoding::HEXLOWER;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, Issuer, KeyPair, SanType};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use types::TestResult;


const RSA_PEM: &[u8] = include_bytes!("fixtures/rsa.pem");


struct Generated {
    pem: String,
    der: Vec<u8>,
    key_pem: String,
}


const EC_BITS: usize = 256;


const RSA_BITS: usize = 2048;


const BUNDLE_CERTIFICATES: usize = 2;


const KEY_BLOCKS: usize = 2;


const TRUNCATED_DER_BYTES: usize = 20;


const HALF: usize = 2;


const SAN_OID: [u64; 4] = [2, 5, 29, 17];


const NOT_A_NAME_LIST: [u8; 3] = [0x04, 0x01, 0x00];


fn generate_certificate(common_name: &str, names: &[&str]) -> Result<Generated, Box<dyn Error>> {
    let mut params = CertificateParams::new(names.iter().map(|name| (*name).to_string()).collect::<Vec<_>>())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, common_name);
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok(Generated {
        pem: certificate.pem(),
        der: certificate.der().to_vec(),
        key_pem: key.serialize_pem(),
    })
}


#[test]
fn pem_certificate_gives_a_full_record() -> TestResult {
    let generated = generate_certificate("leaf.example.test", &["leaf.example.test", "*.example.test"])?;
    let outcome = parse_input(generated.pem.as_bytes())?;
    let record = outcome.records.first().ok_or("no record")?;
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.private_keys_refused, 0);
    assert_eq!(record.fingerprint_sha256, HEXLOWER.encode(&Sha256::digest(&generated.der)));
    assert_eq!(record.subject, "CN=leaf.example.test");
    assert_eq!(record.issuer, record.subject);
    assert!(record.self_signed);
    assert_eq!(record.dns_names, ["leaf.example.test", "*.example.test"]);
    assert_eq!(record.key_type, KeyType::Ec);
    assert_eq!(record.key_bits, Some(EC_BITS));
    assert!(record.not_before < record.not_after);
    Ok(())
}


#[test]
fn der_certificate_gives_the_same_record_as_pem() -> TestResult {
    let generated = generate_certificate("leaf.example.test", &["leaf.example.test"])?;
    assert_eq!(parse_input(&generated.der)?, parse_input(generated.pem.as_bytes())?);
    Ok(())
}


#[test]
fn rsa_certificate_reports_type_and_size() -> TestResult {
    let outcome = parse_input(RSA_PEM)?;
    let record = outcome.records.first().ok_or("no record")?;
    assert_eq!(record.key_type, KeyType::Rsa);
    assert_eq!(record.key_bits, Some(RSA_BITS));
    assert!(record.dns_names.is_empty());
    Ok(())
}


#[test]
fn ed25519_certificate_is_other_without_size() -> TestResult {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certificate = CertificateParams::new(vec!["ed.example.test".to_string()])?.self_signed(&key)?;
    let outcome = parse_input(certificate.der())?;
    let record = outcome.records.first().ok_or("no record")?;
    assert_eq!(record.key_type, KeyType::Other);
    assert_eq!(record.key_bits, None);
    Ok(())
}


#[test]
fn certificate_signed_by_another_is_not_self_signed() -> TestResult {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "ca.test");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec!["leaf.test".to_string()])?;
    leaf_params.distinguished_name.push(rcgen::DnType::CommonName, "leaf.test");
    let leaf = leaf_params.signed_by(&leaf_key, &Issuer::new(ca_params, ca_key))?;
    let outcome = parse_input(leaf.pem().as_bytes())?;
    let record = outcome.records.first().ok_or("no record")?;
    assert!(!record.self_signed);
    assert_eq!(record.issuer, "CN=ca.test");
    Ok(())
}


#[test]
fn bundle_gives_one_record_per_certificate_and_ignores_other_blocks() -> TestResult {
    let first = generate_certificate("one.test", &["one.test"])?;
    let second = generate_certificate("two.test", &["two.test"])?;
    let bundle = format!("{}\n{}\n-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", first.pem, second.pem);
    let outcome = parse_input(bundle.as_bytes())?;
    assert_eq!(outcome.records.len(), BUNDLE_CERTIFICATES);
    assert_eq!(outcome.private_keys_refused, 0);
    Ok(())
}


#[test]
fn private_key_blocks_are_refused_and_counted() -> TestResult {
    let generated = generate_certificate("leaf.test", &["leaf.test"])?;
    let other = generate_certificate("other.test", &["other.test"])?;
    let input = format!("{}{}{}", generated.pem, generated.key_pem, other.key_pem);
    let outcome = parse_input(input.as_bytes())?;
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.private_keys_refused, KEY_BLOCKS);
    assert!(!format!("{outcome:?}").contains(generated.key_pem.lines().nth(1).ok_or("no key line")?));
    Ok(())
}


#[test]
fn only_a_private_key_gives_no_record() -> TestResult {
    let generated = generate_certificate("leaf.test", &["leaf.test"])?;
    let outcome = parse_input(generated.key_pem.as_bytes())?;
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.private_keys_refused, 1);
    Ok(())
}


#[test]
fn garbage_and_truncated_input_are_errors() -> TestResult {
    let generated = generate_certificate("leaf.test", &["leaf.test"])?;
    assert!(matches!(parse_input(b"hello"), Err(CertError::Certificate(_))));
    assert!(matches!(parse_input(b""), Err(CertError::Certificate(_))));
    assert!(matches!(
        parse_input(generated.der.get(..TRUNCATED_DER_BYTES).ok_or("short")?),
        Err(CertError::Certificate(_))
    ));
    assert!(matches!(
        parse_input(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
        Err(CertError::Pem(_))
    ));
    assert!(matches!(
        parse_input(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
        Err(CertError::Certificate(_))
    ));
    let truncated = generated.pem.get(..generated.pem.len() / HALF).ok_or("short")?;
    assert!(matches!(parse_input(truncated.as_bytes()), Err(CertError::Pem(_))));
    Ok(())
}


#[test]
fn input_size_is_bounded() -> TestResult {
    let generated = generate_certificate("leaf.test", &["leaf.test"])?;
    let mut at_limit = generated.pem.into_bytes();
    at_limit.resize(MAX_INPUT_BYTES, b'\n');
    assert_eq!(parse_input(&at_limit)?.records.len(), 1);
    let over = vec![b' '; MAX_INPUT_BYTES + 1];
    assert!(matches!(parse_input(&over), Err(CertError::InputTooLarge { size, max }) if size == MAX_INPUT_BYTES + 1 && max == MAX_INPUT_BYTES));
    Ok(())
}


#[test]
fn block_and_certificate_counts_are_bounded() -> TestResult {
    let generated = generate_certificate("leaf.test", &["leaf.test"])?;
    let at_limit = generated.pem.repeat(MAX_CERTIFICATES);
    assert_eq!(parse_input(at_limit.as_bytes())?.records.len(), MAX_CERTIFICATES);
    let too_many_certificates = generated.pem.repeat(MAX_CERTIFICATES + 1);
    assert!(matches!(
        parse_input(too_many_certificates.as_bytes()),
        Err(CertError::TooManyCertificates { .. })
    ));
    let keys_at_limit = generated.key_pem.repeat(MAX_PEM_BLOCKS);
    assert_eq!(parse_input(keys_at_limit.as_bytes())?.private_keys_refused, MAX_PEM_BLOCKS);
    let too_many_blocks = generated.key_pem.repeat(MAX_PEM_BLOCKS + 1);
    assert!(matches!(parse_input(too_many_blocks.as_bytes()), Err(CertError::TooManyBlocks { .. })));
    Ok(())
}


#[test]
fn dns_names_are_bounded() -> TestResult {
    let names = (0..=MAX_DNS_NAMES).map(|i| format!("host{i}.example.test")).collect::<Vec<_>>();
    let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    let generated = generate_certificate("many.test", &name_refs)?;
    let outcome = parse_input(generated.pem.as_bytes())?;
    let record = outcome.records.first().ok_or("no record")?;
    assert_eq!(record.dns_names.len(), MAX_DNS_NAMES);
    Ok(())
}


#[test]
fn a_malformed_alternative_name_extension_is_an_error() -> TestResult {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(&SAN_OID, NOT_A_NAME_LIST.to_vec()));
    let certificate = params.self_signed(&KeyPair::generate()?)?;
    assert!(matches!(parse_input(certificate.der()), Err(CertError::Extension(_))));
    Ok(())
}


#[test]
fn only_dns_names_are_kept() -> TestResult {
    let mut params = CertificateParams::new(vec!["web.example.test".to_string()])?;
    params.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let certificate = params.self_signed(&KeyPair::generate()?)?;
    let outcome = parse_input(certificate.der())?;
    let record = outcome.records.first().ok_or("no record")?;
    assert_eq!(record.dns_names, ["web.example.test"]);
    Ok(())
}


#[test]
fn errors_keep_their_cause() -> TestResult {
    let error = parse_input(b"hello").err().ok_or("no error")?;
    assert!(std::error::Error::source(&error).is_some());
    assert!(!error.to_string().is_empty());
    Ok(())
}

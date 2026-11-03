#[path = "support/failing_reader.rs"]
mod failing_reader;
#[path = "support/types.rs"]
mod types;


use core_auth::error::{AuthError, PolicyViolation};
use core_auth::password::{build_hasher, hash_password, verify_password, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM};
use core_auth::policy::{check_password, load_compromised, MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS};
use core_auth::random::{os_random, random_array};
use core_auth::types::CompromisedSet;
use failing_reader::FailingReader;
use std::io::BufReader;
use types::TestResult;


const GOOD_PASSWORD: &str = "correct horse battery";


const OTHER_SALT_LENGTH: usize = 4;


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn compromised() -> CompromisedSet {
    ["password1234", "qwertyuiop12"].iter().map(|word| (*word).to_owned()).collect()
}


#[test]
fn hash_has_owasp_parameters_and_verifies() -> TestResult {
    let stored = hash_password(GOOD_PASSWORD, os_random)?;
    let expected_prefix = format!("$argon2id$v=19$m={ARGON2_MEMORY_KIB},t={ARGON2_ITERATIONS},p={ARGON2_PARALLELISM}$");
    assert!(stored.starts_with(&expected_prefix));
    assert!(verify_password(GOOD_PASSWORD, &stored)?);
    assert!(!stored.contains(GOOD_PASSWORD));
    Ok(())
}


#[test]
fn wrong_password_is_rejected() -> TestResult {
    let stored = hash_password(GOOD_PASSWORD, os_random)?;
    assert!(!verify_password("correct horse batterz", &stored)?);
    assert!(!verify_password("", &stored)?);
    Ok(())
}


#[test]
fn salts_differ_between_hashes() -> TestResult {
    let first = hash_password(GOOD_PASSWORD, os_random)?;
    let second = hash_password(GOOD_PASSWORD, os_random)?;
    assert_ne!(first, second);
    Ok(())
}


#[test]
fn malformed_hash_is_an_error() -> TestResult {
    assert!(matches!(verify_password(GOOD_PASSWORD, "not a hash"), Err(AuthError::Hash(_))));
    Ok(())
}


#[test]
fn foreign_algorithm_is_an_error() -> TestResult {
    let foreign = "$scrypt$ln=4,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    assert!(matches!(verify_password(GOOD_PASSWORD, foreign), Err(AuthError::Hash(_))));
    Ok(())
}


#[test]
fn random_failure_is_reported() -> TestResult {
    assert!(matches!(hash_password(GOOD_PASSWORD, failing_random), Err(AuthError::Random(_))));
    assert!(matches!(random_array::<OTHER_SALT_LENGTH>(failing_random), Err(AuthError::Random(_))));
    Ok(())
}


#[test]
fn invalid_parameters_are_reported() -> TestResult {
    assert!(matches!(build_hasher(0, 0, 0), Err(AuthError::Params(_))));
    Ok(())
}


#[test]
fn policy_length_boundaries() -> TestResult {
    let empty = CompromisedSet::new();
    let short = "a".repeat(MIN_PASSWORD_CHARS - 1);
    let exact = "a".repeat(MIN_PASSWORD_CHARS);
    let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
    let longest = "a".repeat(MAX_PASSWORD_BYTES);
    assert_eq!(check_password(&short, &empty), Err(PolicyViolation::TooShort));
    assert_eq!(check_password(&exact, &empty), Ok(()));
    assert_eq!(check_password(&longest, &empty), Ok(()));
    assert_eq!(check_password(&long, &empty), Err(PolicyViolation::TooLong));
    Ok(())
}


#[test]
fn policy_counts_characters_not_bytes() -> TestResult {
    let wide = "é".repeat(MIN_PASSWORD_CHARS);
    let narrow = "é".repeat(MIN_PASSWORD_CHARS - 1);
    assert_eq!(check_password(&wide, &CompromisedSet::new()), Ok(()));
    assert_eq!(check_password(&narrow, &CompromisedSet::new()), Err(PolicyViolation::TooShort));
    Ok(())
}


#[test]
fn policy_has_no_composition_rules() -> TestResult {
    assert_eq!(check_password("alllowercaseletters", &CompromisedSet::new()), Ok(()));
    Ok(())
}


#[test]
fn policy_rejects_compromised_passwords_case_insensitively() -> TestResult {
    assert_eq!(check_password("password1234", &compromised()), Err(PolicyViolation::Compromised));
    assert_eq!(check_password("PassWord1234", &compromised()), Err(PolicyViolation::Compromised));
    assert_eq!(check_password("password1235", &compromised()), Ok(()));
    Ok(())
}


#[test]
fn compromised_list_is_trimmed_and_skips_blank_lines() -> TestResult {
    let list = load_compromised("  Password1234  \n\n\nQwertyuiop12\n".as_bytes())?;
    assert_eq!(list, compromised());
    Ok(())
}


#[test]
fn compromised_list_read_failure_is_reported() -> TestResult {
    assert!(load_compromised(BufReader::new(FailingReader)).is_err());
    Ok(())
}

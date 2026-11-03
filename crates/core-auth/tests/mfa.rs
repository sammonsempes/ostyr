#[path = "support/types.rs"]
mod types;


use core_auth::error::AuthError;
use core_auth::model::TotpEnrolment;
use core_auth::random::os_random;
use core_auth::secretbox::{open_secret, seal_secret, KEY_BYTES};
use core_auth::totp::{
    code_for_step, consume_backup_code, hash_backup_code, new_backup_codes, new_secret, secret_text, texts_match, unix_seconds, verify_code,
    BACKUP_CODE_COUNT, TOTP_SECRET_BYTES, TOTP_STEP_SECONDS,
};
use core_auth::types::StoreKey;
use secrecy::SecretSlice;
use time::OffsetDateTime;
use types::TestResult;


const RFC_SECRET: &[u8] = b"12345678901234567890";


const RFC_TIME_59: i64 = 59;


const RFC_STEP_59: u64 = 1;


const RFC_TIME_LATER: i64 = 1_111_111_109;


const THREE_HASHES: usize = 3;


const KEY_FILL: u8 = 7;


const OTHER_KEY_FILL: u8 = 8;


const BASE_TIME: i64 = 1_700_000_010;


const STEP_SECONDS: i64 = 30;


const TWO_STEPS: u64 = 2;


const BOUNDARY_RESIDUE: i64 = 29;


const ENCRYPTED_PREFIX_LENGTH: usize = 8;


fn at(seconds: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(seconds)
}


fn base_step() -> u64 {
    u64::try_from(BASE_TIME).map_or(0, |seconds| seconds / TOTP_STEP_SECONDS)
}


fn key_of(length: usize) -> StoreKey {
    SecretSlice::from(vec![KEY_FILL; length])
}


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn enrolment_with(hashes: Vec<String>) -> TotpEnrolment {
    TotpEnrolment {
        encrypted_secret: String::new(),
        last_step: 0,
        backup_code_hashes: hashes,
    }
}


#[test]
fn rfc_6238_vectors() {
    assert_eq!(code_for_step(RFC_SECRET, RFC_STEP_59), "287082");
    assert_eq!(
        code_for_step(RFC_SECRET, u64::try_from(RFC_TIME_LATER).map_or(0, |time| time / TOTP_STEP_SECONDS)),
        "081804"
    );
}


#[test]
fn window_accepts_one_step_each_side_and_rejects_two() -> TestResult {
    let now = at(BASE_TIME)?;
    let current = base_step();
    assert_eq!(verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, current), now, 0)?, Some(current));
    assert_eq!(
        verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, current - 1), now, 0)?,
        Some(current - 1)
    );
    assert_eq!(
        verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, current + 1), now, 0)?,
        Some(current + 1)
    );
    assert_eq!(verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, current - TWO_STEPS), now, 0)?, None);
    assert_eq!(verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, current + TWO_STEPS), now, 0)?, None);
    Ok(())
}


#[test]
fn window_edge_moves_with_the_step_boundary() -> TestResult {
    let current = base_step();
    let old_code = code_for_step(RFC_SECRET, current - 1);
    let last_second = at(BASE_TIME + BOUNDARY_RESIDUE - (BASE_TIME % STEP_SECONDS))?;
    let next_second = at(BASE_TIME + STEP_SECONDS - (BASE_TIME % STEP_SECONDS))?;
    assert_eq!(verify_code(RFC_SECRET, &old_code, last_second, 0)?, Some(current - 1));
    assert_eq!(verify_code(RFC_SECRET, &old_code, next_second, 0)?, None);
    Ok(())
}


#[test]
fn a_code_cannot_be_replayed() -> TestResult {
    let now = at(BASE_TIME)?;
    let current = base_step();
    let code = code_for_step(RFC_SECRET, current);
    assert_eq!(verify_code(RFC_SECRET, &code, now, current)?, None);
    assert_eq!(verify_code(RFC_SECRET, &code, now, current - 1)?, Some(current));
    Ok(())
}


#[test]
fn wrong_and_malformed_codes_are_rejected() -> TestResult {
    let now = at(BASE_TIME)?;
    assert_eq!(verify_code(RFC_SECRET, "000000x", now, 0)?, None);
    assert_eq!(verify_code(RFC_SECRET, "", now, 0)?, None);
    assert!(!texts_match("abc", "abd"));
    assert!(texts_match("abc", "abc"));
    Ok(())
}


#[test]
fn time_before_the_epoch_is_refused() -> TestResult {
    assert!(matches!(unix_seconds(at(-1)?), Err(AuthError::ClockBeforeEpoch)));
    assert!(matches!(verify_code(RFC_SECRET, "123456", at(-1)?, 0), Err(AuthError::ClockBeforeEpoch)));
    assert_eq!(unix_seconds(at(RFC_TIME_59)?)?, u64::try_from(RFC_TIME_59)?);
    Ok(())
}


#[test]
fn window_at_time_zero_does_not_underflow() -> TestResult {
    assert_eq!(verify_code(RFC_SECRET, &code_for_step(RFC_SECRET, 1), at(0)?, 0)?, Some(1));
    Ok(())
}


#[test]
fn secrets_and_backup_codes_are_generated() -> TestResult {
    let secret = new_secret(os_random)?;
    assert_eq!(secret.len(), TOTP_SECRET_BYTES);
    assert!(!secret_text(&secret).is_empty());
    let codes = new_backup_codes(os_random)?;
    assert_eq!(codes.len(), BACKUP_CODE_COUNT);
    assert_ne!(codes.first(), codes.get(1));
    assert!(matches!(new_secret(failing_random), Err(AuthError::Random(_))));
    assert!(matches!(new_backup_codes(failing_random), Err(AuthError::Random(_))));
    Ok(())
}


#[test]
fn backup_codes_work_once() {
    let hashes = vec![hash_backup_code("AAAA"), hash_backup_code("BBBB"), hash_backup_code("CCCC")];
    let mut enrolment = enrolment_with(hashes);
    assert!(!consume_backup_code(&mut enrolment, "ZZZZ"));
    assert_eq!(enrolment.backup_code_hashes.len(), THREE_HASHES);
    assert!(consume_backup_code(&mut enrolment, "BBBB"));
    assert_eq!(enrolment.backup_code_hashes, vec![hash_backup_code("AAAA"), hash_backup_code("CCCC")]);
    assert!(!consume_backup_code(&mut enrolment, "BBBB"));
}


#[test]
fn backup_code_hash_hides_the_code() {
    let hash = hash_backup_code("AAAA");
    assert!(!hash.contains("AAAA"));
    assert_eq!(hash, hash_backup_code("AAAA"));
}


#[test]
fn sealed_secret_round_trips_and_hides_plaintext() -> TestResult {
    let key = key_of(KEY_BYTES);
    let sealed = seal_secret(&key, "alice", RFC_SECRET, os_random)?;
    assert!(!sealed.contains(&secret_text(RFC_SECRET)));
    assert!(sealed.len() > ENCRYPTED_PREFIX_LENGTH);
    assert_eq!(open_secret(&key, "alice", &sealed)?, RFC_SECRET);
    Ok(())
}


#[test]
fn sealed_secret_is_bound_to_key_and_account() -> TestResult {
    let key = key_of(KEY_BYTES);
    let sealed = seal_secret(&key, "alice", RFC_SECRET, os_random)?;
    assert!(matches!(open_secret(&key, "bob", &sealed), Err(AuthError::Decrypt)));
    let other = SecretSlice::from(vec![OTHER_KEY_FILL; KEY_BYTES]);
    assert!(matches!(open_secret(&other, "alice", &sealed), Err(AuthError::Decrypt)));
    Ok(())
}


#[test]
fn sealed_secret_rejects_garbage() {
    let key = key_of(KEY_BYTES);
    assert!(matches!(open_secret(&key, "alice", "!!!"), Err(AuthError::Decrypt)));
    assert!(matches!(open_secret(&key, "alice", "AAAA"), Err(AuthError::Decrypt)));
}


#[test]
fn key_length_and_random_failures_are_reported() {
    let short = key_of(KEY_BYTES - 1);
    assert!(matches!(seal_secret(&short, "alice", RFC_SECRET, os_random), Err(AuthError::InvalidKey)));
    assert!(matches!(open_secret(&short, "alice", "AAAA"), Err(AuthError::InvalidKey)));
    assert!(matches!(
        seal_secret(&key_of(KEY_BYTES), "alice", RFC_SECRET, failing_random),
        Err(AuthError::Random(_))
    ));
}

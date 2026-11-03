use crate::error::AuthError;
use crate::model::TotpEnrolment;
use crate::random::random_array;
use crate::types::RandomFn;
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use totp_lite::{totp_custom, Sha1};


pub const TOTP_STEP_SECONDS: u64 = 30;


pub const TOTP_DIGITS: u32 = 6;


pub const TOTP_SKEW_STEPS: u64 = 1;


pub const TOTP_SECRET_BYTES: usize = 20;


pub const BACKUP_CODE_COUNT: usize = 10;


pub const BACKUP_CODE_BYTES: usize = 10;


pub fn unix_seconds(now: OffsetDateTime) -> Result<u64, AuthError> {
    u64::try_from(now.unix_timestamp()).map_err(|_| AuthError::ClockBeforeEpoch)
}


pub fn code_for_step(secret: &[u8], step: u64) -> String {
    totp_custom::<Sha1>(TOTP_STEP_SECONDS, TOTP_DIGITS, secret, step.saturating_mul(TOTP_STEP_SECONDS))
}


pub fn texts_match(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}


/// Returns the accepted step, which must be newer than `last_step` so a code works once.
pub fn verify_code(secret: &[u8], code: &str, now: OffsetDateTime, last_step: u64) -> Result<Option<u64>, AuthError> {
    let current = unix_seconds(now)? / TOTP_STEP_SECONDS;
    let first = current.saturating_sub(TOTP_SKEW_STEPS);
    let last = current.saturating_add(TOTP_SKEW_STEPS);
    Ok((first..=last)
        .filter(|step| *step > last_step)
        .find(|step| texts_match(&code_for_step(secret, *step), code)))
}


pub fn secret_text(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}


pub fn hash_backup_code(code: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(code.as_bytes()))
}


pub fn new_secret(random: RandomFn) -> Result<[u8; TOTP_SECRET_BYTES], AuthError> {
    random_array::<TOTP_SECRET_BYTES>(random)
}


pub fn new_backup_codes(random: RandomFn) -> Result<Vec<String>, AuthError> {
    (0..BACKUP_CODE_COUNT)
        .map(|_| random_array::<BACKUP_CODE_BYTES>(random).map(|bytes| BASE32_NOPAD.encode(&bytes)))
        .collect()
}


/// Removes and reports the matching hash; every hash is compared so timing does not reveal the position.
pub fn consume_backup_code(enrolment: &mut TotpEnrolment, code: &str) -> bool {
    let wanted = hash_backup_code(code);
    let matches: Vec<bool> = enrolment.backup_code_hashes.iter().map(|stored| texts_match(stored, &wanted)).collect();
    let found = matches.contains(&true);
    let mut flags = matches.into_iter();
    enrolment.backup_code_hashes.retain(|_| !flags.next().unwrap_or(false));
    found
}

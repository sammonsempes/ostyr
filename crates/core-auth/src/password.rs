use crate::error::AuthError;
use crate::random::random_array;
use crate::types::RandomFn;
use argon2::password_hash::{Error as HashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};


pub const ARGON2_MEMORY_KIB: u32 = 19_456;


pub const ARGON2_ITERATIONS: u32 = 2;


pub const ARGON2_PARALLELISM: u32 = 1;


pub const SALT_BYTES: usize = 16;


pub fn build_hasher(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(memory_kib, iterations, parallelism, None)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}


pub fn owasp_hasher() -> Result<Argon2<'static>, AuthError> {
    build_hasher(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM)
}


pub fn hash_password(password: &str, random: RandomFn) -> Result<String, AuthError> {
    let salt_bytes = random_array::<SALT_BYTES>(random)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let hash = owasp_hasher()?.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}


pub fn verify_password(password: &str, stored: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(stored)?;
    match owasp_hasher()?.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(HashError::Password) => Ok(false),
        Err(other) => Err(AuthError::Hash(other)),
    }
}

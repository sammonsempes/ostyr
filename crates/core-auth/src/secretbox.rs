use crate::error::AuthError;
use crate::random::random_array;
use crate::types::{RandomFn, StoreKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use data_encoding::BASE64;
use secrecy::ExposeSecret;


pub const KEY_BYTES: usize = 32;


pub const NONCE_BYTES: usize = 12;


pub fn cipher_for(key: &StoreKey) -> Result<ChaCha20Poly1305, AuthError> {
    ChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| AuthError::InvalidKey)
}


pub fn seal_secret(key: &StoreKey, context: &str, plaintext: &[u8], random: RandomFn) -> Result<String, AuthError> {
    let cipher = cipher_for(key)?;
    let nonce_bytes = random_array::<NONCE_BYTES>(random)?;
    let payload = Payload {
        msg: plaintext,
        aad: context.as_bytes(),
    };
    let ciphertext = cipher.encrypt(&Nonce::from(nonce_bytes), payload).map_err(|_| AuthError::Encrypt)?;
    Ok(BASE64.encode(&[nonce_bytes.as_slice(), ciphertext.as_slice()].concat()))
}


pub fn open_secret(key: &StoreKey, context: &str, sealed: &str) -> Result<Vec<u8>, AuthError> {
    let cipher = cipher_for(key)?;
    let raw = BASE64.decode(sealed.as_bytes()).map_err(|_| AuthError::Decrypt)?;
    let (nonce_bytes, ciphertext) = raw.split_at_checked(NONCE_BYTES).ok_or(AuthError::Decrypt)?;
    let payload = Payload {
        msg: ciphertext,
        aad: context.as_bytes(),
    };
    cipher.decrypt(Nonce::from_slice(nonce_bytes), payload).map_err(|_| AuthError::Decrypt)
}

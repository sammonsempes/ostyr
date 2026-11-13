use crate::model::{IDENTIFIER_COUNT, NONCE_LENGTH, SESSION_ID_LENGTH};
use crate::types::{FillFn, SignerFn};
use ed25519_dalek::{Signer, SigningKey};


/// A signer over an in-memory key, for tests and examples; the platform injects a vault or HSM signer.
pub fn memory_signer(key: SigningKey) -> Box<SignerFn> {
    Box::new(move |message| Ok(key.sign(message).to_bytes().to_vec()))
}


pub fn os_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buffer)
}


/// A fresh session id and nonce from one draw.
pub fn new_identifiers(fill: FillFn) -> Result<([u8; SESSION_ID_LENGTH], [u8; NONCE_LENGTH]), getrandom::Error> {
    let mut random = [[0; SESSION_ID_LENGTH]; IDENTIFIER_COUNT];
    fill(random.as_flattened_mut())?;
    let [session_id, nonce] = random;
    Ok((session_id, nonce))
}

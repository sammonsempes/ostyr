use crate::action::validate_action;
use crate::codec::signing_message;
use crate::error::SignError;
use crate::model::{Command, Envelope, NONCE_LENGTH};
use crate::types::{FillFn, SignerFn};
use ed25519_dalek::{Signer, SigningKey};


/// The signer is injected: the private key never has to live in this crate (vault, HSM).
pub fn sign_command(command: &Command, key_id: &str, signer: &SignerFn) -> Result<Vec<u8>, SignError> {
    validate_action(&command.action)?;
    let command_bytes = postcard::to_stdvec(command)?;
    let signature = signer(&signing_message(&command_bytes)).map_err(SignError::Signer)?;
    Ok(postcard::to_stdvec(&Envelope {
        key_id: key_id.to_owned(),
        command: command_bytes,
        signature,
    })?)
}


/// A signer over an in-memory key, for tests and examples.
pub fn memory_signer(key: SigningKey) -> Box<SignerFn> {
    Box::new(move |message| Ok(key.sign(message).to_bytes().to_vec()))
}


pub fn os_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buffer)
}


pub fn new_nonce(fill: FillFn) -> Result<[u8; NONCE_LENGTH], getrandom::Error> {
    let mut nonce = [0; NONCE_LENGTH];
    fill(&mut nonce)?;
    Ok(nonce)
}

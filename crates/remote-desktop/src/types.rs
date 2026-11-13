use crate::model::NONCE_LENGTH;
use std::error::Error;


pub type BoxError = Box<dyn Error + Send + Sync>;


pub type SignerFn = dyn Fn(&[u8]) -> Result<Vec<u8>, BoxError> + Send + Sync;


pub type FillFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;


pub type Nonce = [u8; NONCE_LENGTH];

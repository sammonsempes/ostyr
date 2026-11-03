use crate::error::CodecError;
use crate::model::SIGNING_CONTEXT;
use serde::de::DeserializeOwned;


/// Refuses trailing bytes so one value has exactly one encoding.
pub fn decode_exact<Value: DeserializeOwned>(bytes: &[u8]) -> Result<Value, CodecError> {
    let (value, rest) = postcard::take_from_bytes(bytes)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(CodecError::TrailingBytes)
    }
}


/// The bytes the signature covers: a domain separator followed by the serialised command.
pub fn signing_message(command: &[u8]) -> Vec<u8> {
    [SIGNING_CONTEXT, command].concat()
}

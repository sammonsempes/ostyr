use crate::error::{AiError, SecretClass};
use crate::limits::{DELIMITER_NOTICE, MAX_DATA_DEPTH, MAX_DATA_NODES, MAX_KEY_BYTES, NONCE_BYTES, NONCE_PLACEHOLDER, TEMPERATURE};
use crate::settings::AiSettings;
use crate::types::RandomFn;
use core_config::secret_file::{open_secret, SecretFileError};
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;


pub const BEARER_PREFIX: &str = "Bearer ";


/// Walks the document with an explicit stack and stops as soon as a bound is passed: no recursion, no work past the cap.
pub fn check_data_shape(data: &Value) -> Result<(), AiError> {
    let mut stack: Vec<(&Value, usize)> = vec![(data, 1)];
    let mut seen: usize = 0;
    let mut deepest: usize = 0;
    while seen <= MAX_DATA_NODES && deepest <= MAX_DATA_DEPTH && !stack.is_empty() {
        stack.pop().into_iter().for_each(|(value, depth)| {
            seen += 1;
            deepest = deepest.max(depth);
            match value {
                Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
                Value::Object(entries) => stack.extend(entries.values().map(|item| (item, depth + 1))),
                _ => (),
            }
        });
    }
    if seen > MAX_DATA_NODES || deepest > MAX_DATA_DEPTH {
        Err(AiError::DataTooComplex)
    } else {
        Ok(())
    }
}


/// 32 lowercase hex characters, fresh per call.
pub fn new_nonce(random: RandomFn) -> Result<String, AiError> {
    let mut bytes = [0; NONCE_BYTES];
    random(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}


pub fn opening_tag(nonce: &str) -> String {
    format!("<data-{nonce}>")
}


pub fn closing_tag(nonce: &str) -> String {
    format!("</data-{nonce}>")
}


/// Two messages: the platform's instructions and the fixed notice, then the telemetry as one JSON document between the nonce tags.
pub fn build_request(settings: &AiSettings, instructions: &str, data: &Value, nonce: &str) -> Result<Vec<u8>, AiError> {
    check_data_shape(data)?;
    let document = data.to_string();
    let closing = closing_tag(nonce);
    if document.contains(&closing) {
        Err(AiError::DataHoldsDelimiter)
    } else {
        let system = format!("{instructions}\n\n{}", DELIMITER_NOTICE.replace(NONCE_PLACEHOLDER, nonce));
        let user = format!("{}{document}{closing}", opening_tag(nonce));
        let body = json!({
            "model": settings.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": settings.max_tokens,
            "temperature": TEMPERATURE,
        })
        .to_string()
        .into_bytes();
        if body.len() > settings.max_request_bytes {
            Err(AiError::RequestTooLarge {
                bytes: body.len(),
                cap: settings.max_request_bytes,
            })
        } else {
            Ok(body)
        }
    }
}


pub fn secret_class(error: SecretFileError) -> AiError {
    match error {
        SecretFileError::Io { .. } => AiError::Secret {
            class: SecretClass::Unreadable,
        },
        _ => AiError::Secret { class: SecretClass::Refused },
    }
}


/// Printable ASCII without spaces, so it can sit in a header; the error never carries the bytes.
pub fn key_text(bytes: &[u8]) -> Result<Zeroizing<String>, AiError> {
    if bytes.len() > MAX_KEY_BYTES {
        Err(AiError::Secret {
            class: SecretClass::TooLarge,
        })
    } else {
        let text = std::str::from_utf8(bytes)
            .map_err(|_error| AiError::Secret { class: SecretClass::Format })?
            .trim();
        if text.is_empty() || !text.chars().all(|character| character.is_ascii_graphic()) {
            Err(AiError::Secret { class: SecretClass::Format })
        } else {
            Ok(Zeroizing::new(format!("{BEARER_PREFIX}{text}")))
        }
    }
}


/// At most `MAX_KEY_BYTES + 1` bytes are read, into a buffer zeroed on drop.
pub fn read_key(reader: &mut dyn Read) -> Result<Zeroizing<String>, AiError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_KEY_BYTES + 1));
    reader
        .take(MAX_KEY_BYTES as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|_error| AiError::Secret {
            class: SecretClass::Unreadable,
        })?;
    key_text(&buffer)
}


/// The `Authorization` value from the key file, opened with the shared secret-file checks (regular file, owner, no group or other bit, no symlink).
pub fn read_authorization(path: &Path) -> Result<Zeroizing<String>, AiError> {
    let mut handle = open_secret(path).map_err(secret_class)?;
    read_key(&mut handle)
}

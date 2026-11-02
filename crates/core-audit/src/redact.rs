use crate::types::ParameterMap;


pub const REDACTED: &str = "[REDACTED]";


pub const SENSITIVE_KEY_PARTS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "authorization",
    "credential",
    "passphrase",
    "cookie",
];


pub const SENSITIVE_VALUE_PREFIXES: [&str; 3] = ["Bearer ", "Basic ", "-----BEGIN"];


pub fn is_sensitive(key: &str, value: &str) -> bool {
    let lowered = key.to_lowercase();
    SENSITIVE_KEY_PARTS.iter().any(|part| lowered.contains(part)) || SENSITIVE_VALUE_PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}


/// Values of sensitive keys, and values that look like credentials, are replaced by `[REDACTED]`; keys are kept.
pub fn redact_parameters(parameters: &ParameterMap) -> ParameterMap {
    parameters
        .iter()
        .map(|(key, value)| {
            let kept = if is_sensitive(key, value) { REDACTED.to_owned() } else { value.clone() };
            (key.clone(), kept)
        })
        .collect()
}

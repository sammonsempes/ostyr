use crate::types::ParameterMap;


pub const REDACTED: &str = "[REDACTED]";


pub const SENSITIVE_KEY_PARTS: [&str; 10] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "auth",
    "credential",
    "passphrase",
    "cookie",
];


pub const SENSITIVE_VALUE_PREFIXES: [&str; 3] = ["bearer ", "basic ", "-----begin"];


pub const JWT_PREFIX: &str = "eyJ";


pub const JWT_SEGMENTS: usize = 3;


pub fn is_sensitive_key(key: &str) -> bool {
    let lowered = key.to_lowercase();
    SENSITIVE_KEY_PARTS.iter().any(|part| lowered.contains(part))
}


pub fn has_sensitive_prefix(value: &str) -> bool {
    let lowered = value.trim_start().to_lowercase();
    SENSITIVE_VALUE_PREFIXES.iter().any(|prefix| lowered.starts_with(prefix))
}


pub fn is_base64url_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
}


pub fn is_jwt(value: &str) -> bool {
    value.starts_with(JWT_PREFIX) && value.split('.').count() == JWT_SEGMENTS && value.split('.').all(is_base64url_segment)
}


pub fn is_sensitive(key: &str, value: &str) -> bool {
    is_sensitive_key(key) || has_sensitive_prefix(value) || is_jwt(value)
}


/// Replaces the password of `scheme://user:pass@host/...` by `[REDACTED]`; any other value is returned unchanged.
pub fn redact_url_password(value: &str) -> String {
    match value.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
            match authority
                .rsplit_once('@')
                .and_then(|(userinfo, host)| userinfo.split_once(':').map(|(user, _)| (user, host)))
            {
                Some((user, host)) => format!("{scheme}://{user}:{REDACTED}@{host}{tail}"),
                None => value.to_owned(),
            }
        }
        None => value.to_owned(),
    }
}


pub fn redact_value(key: &str, value: &str) -> String {
    if is_sensitive(key, value) {
        REDACTED.to_owned()
    } else {
        redact_url_password(value)
    }
}


/// Values of sensitive keys, and values that look like credentials, are replaced by `[REDACTED]`; keys are kept.
pub fn redact_parameters(parameters: &ParameterMap) -> ParameterMap {
    parameters.iter().map(|(key, value)| (key.clone(), redact_value(key, value))).collect()
}

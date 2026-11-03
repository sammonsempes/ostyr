//! Secret redaction shared by the audit log, the structured logs and the ECS export (spec section 12).

pub mod key;
pub mod types;
pub mod value;


use crate::key::is_sensitive_key;
use crate::types::ParameterMap;
use crate::value::{redact_text, REDACTED};


/// Replaces the whole value of a sensitive key, otherwise every credential found inside the value.
pub fn redact_value(key: &str, value: &str) -> String {
    if is_sensitive_key(key) {
        REDACTED.to_owned()
    } else {
        redact_text(value)
    }
}


/// Redacts every value of `parameters` through `redact_value`; keys are kept.
pub fn redact_parameters(parameters: &ParameterMap) -> ParameterMap {
    parameters.iter().map(|(key, value)| (key.clone(), redact_value(key, value))).collect()
}

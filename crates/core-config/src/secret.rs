use schemars::JsonSchema;
use serde::Deserialize;
use thiserror::Error;


pub const SECRET_PREFIXES: [&str; 3] = ["vault://", "openbao://", "sops:"];


/// A reference to a secret held elsewhere, never the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(try_from = "String")]
#[schemars(with = "String", extend("pattern" = "^(vault://|openbao://|sops:).+"))]
pub struct SecretRef(pub String);


/// The message never echoes the rejected value, which may be a real secret.
#[derive(Debug, Error)]
#[error("a secret field takes a reference (vault://, openbao:// or sops:), never a value")]
pub struct PlaintextSecret;


impl TryFrom<String> for SecretRef {
    type Error = PlaintextSecret;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let is_reference = SECRET_PREFIXES
            .iter()
            .any(|prefix| value.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty()));
        if is_reference {
            Ok(Self(value))
        } else {
            Err(PlaintextSecret)
        }
    }
}

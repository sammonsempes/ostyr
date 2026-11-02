use crate::secret::SecretRef;
use crate::types::{SecretMap, SettingsMap};
use schemars::JsonSchema;
use serde::Deserialize;


/// Platform file: which modules coexist (spec section 4). Optional: a module runs alone without it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformConfig {
    pub modules: Vec<ModuleEntry>,
    pub authentication: Option<AuthenticationRef>,
    pub event_bus: Option<ServiceRef>,
    pub storage: Option<ServiceRef>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    pub name: String,
    pub version: String,
    pub endpoint: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationRef {
    pub provider: String,
    pub issuer: String,
    pub client_secret: SecretRef,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRef {
    pub endpoint: String,
    pub credentials: Option<SecretRef>,
}


/// Configuration of one module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfig {
    pub name: String,
    pub version: String,
    pub tenant: Option<String>,
    pub listen: Option<String>,
    #[serde(default)]
    pub secrets: SecretMap,
    #[serde(default)]
    pub settings: SettingsMap,
}

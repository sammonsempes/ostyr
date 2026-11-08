use crate::error::ExportError;
use core_config::parse::{parse_document, read_file};
use core_config::secret::SecretRef;
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::Path;


pub const DEFAULT_APP_NAME: &str = "ostyr";


pub const DEFAULT_BATCH_SIZE: usize = 500;


pub const DEFAULT_BUFFER_MAX_BYTES: u64 = 256 * 1024 * 1024;


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    #[default]
    Tls,
    Udp,
}


/// `transport: udp` is the explicit opt-in for legacy receivers; TLS over TCP is the default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    pub address: String,
    #[serde(default)]
    pub transport: SyslogTransport,
    pub hostname: String,
    #[serde(default = "default_app_name")]
    pub app_name: String,
    pub ca_file: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    pub token: Option<SecretRef>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    pub buffer_dir: String,
    #[serde(default = "default_buffer_max_bytes")]
    pub buffer_max_bytes: u64,
    pub ca_file: Option<String>,
}


/// OTLP/HTTP logs: `endpoint` is the full URL (`https://host:4318/v1/logs`); the bearer token is read from `token_file`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub token_file: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    pub buffer_dir: String,
    #[serde(default = "default_buffer_max_bytes")]
    pub buffer_max_bytes: u64,
    pub ca_file: Option<String>,
    #[serde(default = "default_app_name")]
    pub service_name: String,
    pub tenant: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub syslog: Option<SyslogConfig>,
    pub webhook: Option<WebhookConfig>,
    pub otlp: Option<OtlpConfig>,
}


pub fn default_app_name() -> String {
    DEFAULT_APP_NAME.to_string()
}


pub fn default_batch_size() -> usize {
    DEFAULT_BATCH_SIZE
}


pub fn default_buffer_max_bytes() -> u64 {
    DEFAULT_BUFFER_MAX_BYTES
}


pub fn parse_export(text: &str, file: &str) -> Result<ExportConfig, ExportError> {
    parse_document(text, file).map_err(ExportError::from)
}


pub fn load_export(path: &Path) -> Result<ExportConfig, ExportError> {
    let text = read_file(path)?;
    parse_export(&text, &path.display().to_string())
}

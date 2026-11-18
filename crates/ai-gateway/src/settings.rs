use crate::error::AiError;
use crate::limits::{
    DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES, ENDPOINT_PATH, MAX_MODEL_CHARS, MAX_REQUEST_BYTES_CEILING, MAX_RESPONSE_BYTES_CEILING,
    MAX_TIMEOUT_SECONDS, MAX_TOKENS_CEILING, MIN_RESPONSE_BYTES, MIN_TIMEOUT_SECONDS, MODEL_EXTRA_CHARACTERS,
};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;
use url::{Host, Url};


pub const AI_SECTION: &str = "ai";


pub fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}


pub fn default_max_request_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BYTES
}


/// `ai.yaml`. The key file is a path only: the key itself is read per call and never held here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiSettings {
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    pub timeout_seconds: u64,
    pub max_tokens: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] AiError),
}


/// `https://` to any host, `http://` only to a literal loopback address (`127.0.0.0/8` or `::1`), never to a name.
pub fn host_allowed(url: &Url) -> bool {
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(Host::Ipv4(address))) => address.is_loopback(),
        ("http", Some(Host::Ipv6(address))) => address.is_loopback(),
        _ => false,
    }
}


/// A plain address and path: no credentials, query or fragment.
pub fn base_url_ok(text: &str) -> bool {
    Url::parse(text).is_ok_and(|url| {
        host_allowed(&url) && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none()
    })
}


/// An ASCII allowlist, so no blank-looking or direction-changing character passes.
pub fn model_ok(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= MAX_MODEL_CHARS
        && !model.starts_with('-')
        && model
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || MODEL_EXTRA_CHARACTERS.contains(character))
}


/// The first refused field is named.
pub fn validate_ai(settings: &AiSettings) -> Result<(), AiError> {
    if !base_url_ok(&settings.base_url) {
        Err(AiError::Settings { field: "base_url" })
    } else if !model_ok(&settings.model) {
        Err(AiError::Settings { field: "model" })
    } else if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&settings.timeout_seconds) {
        Err(AiError::Settings { field: "timeout_seconds" })
    } else if !(1..=MAX_TOKENS_CEILING).contains(&settings.max_tokens) {
        Err(AiError::Settings { field: "max_tokens" })
    } else if !(MIN_RESPONSE_BYTES..=MAX_RESPONSE_BYTES_CEILING).contains(&settings.max_response_bytes) {
        Err(AiError::Settings { field: "max_response_bytes" })
    } else if !(1..=MAX_REQUEST_BYTES_CEILING).contains(&settings.max_request_bytes) {
        Err(AiError::Settings { field: "max_request_bytes" })
    } else {
        Ok(())
    }
}


pub fn endpoint_url(settings: &AiSettings) -> String {
    format!("{}{ENDPOINT_PATH}", settings.base_url.trim_end_matches('/'))
}


pub fn ai_state(settings: &AiSettings) -> ConfigState {
    [
        ("base_url", settings.base_url.clone()),
        ("model", settings.model.clone()),
        ("api_key_file", format!("{:?}", settings.api_key_file)),
        ("ca_file", format!("{:?}", settings.ca_file)),
        ("timeout_seconds", settings.timeout_seconds.to_string()),
        ("max_tokens", settings.max_tokens.to_string()),
        ("max_response_bytes", settings.max_response_bytes.to_string()),
        ("max_request_bytes", settings.max_request_bytes.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// A reload that breaks a bound is refused (and audited `denied`); the old settings stay.
pub fn ai_subscriber() -> Subscriber<AiSettings> {
    Subscriber {
        section: AI_SECTION.to_owned(),
        validate: Box::new(|config| validate_ai(config).map_err(Into::into)),
        apply: Box::new(|_config| ()),
    }
}


/// Loads and validates the first settings; the caller takes one `current_config` snapshot per call.
pub fn open_ai(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<AiSettings>, OpenError> {
    let mut engine = open_engine(Box::new(move || load_file::<AiSettings>(&path)), ai_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_ai(&first)?;
    engine.subscribers.push(ai_subscriber());
    Ok(engine)
}

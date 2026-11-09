use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_file};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use std::path::{Path, PathBuf};


pub const DEFAULT_PORT: u16 = 5432;


pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;


pub const DEFAULT_STATEMENT_TIMEOUT_SECS: u64 = 30;


pub const MAX_DEADLINE_SECS: u64 = 3600;


pub const MAX_TEXT_BYTES: usize = 255;


/// Connection settings; the password itself is never here, only the path of the file holding it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgSettings {
    #[serde(deserialize_with = "host_field")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(deserialize_with = "name_field")]
    pub database: String,
    #[serde(deserialize_with = "name_field")]
    pub user: String,
    #[serde(deserialize_with = "path_field")]
    pub password_file: String,
    #[serde(deserialize_with = "path_field")]
    pub ca_file: String,
    #[serde(default = "default_connect_timeout", deserialize_with = "deadline_field")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_statement_timeout", deserialize_with = "deadline_field")]
    pub statement_timeout_secs: u64,
}


pub fn default_port() -> u16 {
    DEFAULT_PORT
}


pub fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}


pub fn default_statement_timeout() -> u64 {
    DEFAULT_STATEMENT_TIMEOUT_SECS
}


/// A host is a name or an address: a leading `/` would select a Unix socket, which has no TLS, and a leading `-` is refused everywhere.
pub fn check_host(text: &str) -> Result<(), &'static str> {
    let valid = !text.is_empty()
        && text.len() <= MAX_TEXT_BYTES
        && !text.starts_with('-')
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ':'));
    if valid {
        Ok(())
    } else {
        Err("invalid host: a name or an address of at most 255 characters")
    }
}


pub fn check_name(text: &str) -> Result<(), &'static str> {
    let valid = !text.is_empty() && text.len() <= MAX_TEXT_BYTES && !text.starts_with('-') && !text.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err("invalid name: 1 to 255 characters, no control character, no leading `-`")
    }
}


pub fn check_path(text: &str) -> Result<(), &'static str> {
    if text.is_empty() || text.chars().any(char::is_control) {
        Err("invalid path: empty or holding a control character")
    } else {
        Ok(())
    }
}


pub fn checked_text<'de, Decoder: Deserializer<'de>>(
    deserializer: Decoder,
    check: fn(&str) -> Result<(), &'static str>,
) -> Result<String, Decoder::Error> {
    let text = String::deserialize(deserializer)?;
    check(&text).map_err(Decoder::Error::custom)?;
    Ok(text)
}


pub fn host_field<'de, Decoder: Deserializer<'de>>(deserializer: Decoder) -> Result<String, Decoder::Error> {
    checked_text(deserializer, check_host)
}


pub fn name_field<'de, Decoder: Deserializer<'de>>(deserializer: Decoder) -> Result<String, Decoder::Error> {
    checked_text(deserializer, check_name)
}


pub fn path_field<'de, Decoder: Deserializer<'de>>(deserializer: Decoder) -> Result<String, Decoder::Error> {
    checked_text(deserializer, check_path)
}


pub fn deadline_field<'de, Decoder: Deserializer<'de>>(deserializer: Decoder) -> Result<u64, Decoder::Error> {
    let seconds = u64::deserialize(deserializer)?;
    if (1..=MAX_DEADLINE_SECS).contains(&seconds) {
        Ok(seconds)
    } else {
        Err(Decoder::Error::custom("a deadline is between 1 and 3600 seconds"))
    }
}


pub fn parse_settings(text: &str, file: &str) -> Result<PgSettings, ConfigError> {
    parse_document(text, file)
}


pub fn load_settings(path: &Path) -> Result<PgSettings, ConfigError> {
    let text = read_file(path)?;
    parse_settings(&text, &path.display().to_string())
}


pub fn settings_state(settings: &PgSettings) -> ConfigState {
    [
        ("host", settings.host.clone()),
        ("port", settings.port.to_string()),
        ("database", settings.database.clone()),
        ("user", settings.user.clone()),
        ("password_file", settings.password_file.clone()),
        ("ca_file", settings.ca_file.clone()),
        ("connect_timeout_secs", settings.connect_timeout_secs.to_string()),
        ("statement_timeout_secs", settings.statement_timeout_secs.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<PgSettings>> {
    Box::new(move || load_settings(&path))
}


/// A connection takes one snapshot with `core_config::reload::current_config` and keeps it; a reload only changes what the next connect sees.
pub fn open_settings(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<PgSettings>, ConfigError> {
    open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)
}

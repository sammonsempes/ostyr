use crate::limits::{
    Limits, DEFAULT_MAX_BYTES, DEFAULT_MAX_CAPABILITIES, DEFAULT_MAX_HOST_READ_BYTES, DEFAULT_MAX_HOST_SECONDS, DEFAULT_MAX_INTERFACES,
    DEFAULT_MAX_LINKS_PER_HOST, DEFAULT_MAX_LINKS_PER_PORT, DEFAULT_MAX_NEIGHBOURS_PER_INTERFACE, DEFAULT_MAX_PORT_BYTES, DEFAULT_MAX_TEXT_BYTES,
    DEFAULT_PORT_TIMEOUT_SECONDS, MAX_HOST_READ_BYTES_CEILING, MAX_HOST_SECONDS_CEILING, MAX_PORT_TIMEOUT_SECONDS, MIN_PORT_TIMEOUT_SECONDS,
};
use crate::links::MAX_STALE_AFTER_SECONDS;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_file};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;


pub const TOPOLOGY_SECTION: &str = "net-topology";


pub const DEFAULT_STALE_AFTER_SECONDS: i64 = 600;


pub const MAX_INTERFACES_CEILING: usize = 65_536;


pub const MAX_NEIGHBOURS_CEILING: usize = 1_024;


pub const MAX_CAPABILITIES_CEILING: usize = 256;


pub const MAX_TEXT_BYTES_CEILING: usize = 1_024;


pub const MAX_LINKS_PER_HOST_CEILING: usize = 1_048_576;


/// The settings file of the crate: every key optional, each defaulting to the value the caller used to pass.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub stale_after_seconds: i64,
    pub max_bytes: u64,
    pub max_port_bytes: u64,
    pub max_host_read_bytes: u64,
    pub max_host_seconds: u64,
    pub port_timeout_seconds: u64,
    pub max_interfaces: usize,
    pub max_neighbours_per_interface: usize,
    pub max_capabilities: usize,
    pub max_text_bytes: usize,
    pub max_links_per_host: usize,
    pub max_links_per_port: usize,
}


impl Default for Settings {
    fn default() -> Self {
        Self {
            stale_after_seconds: DEFAULT_STALE_AFTER_SECONDS,
            max_bytes: DEFAULT_MAX_BYTES,
            max_port_bytes: DEFAULT_MAX_PORT_BYTES,
            max_host_read_bytes: DEFAULT_MAX_HOST_READ_BYTES,
            max_host_seconds: DEFAULT_MAX_HOST_SECONDS,
            port_timeout_seconds: DEFAULT_PORT_TIMEOUT_SECONDS,
            max_interfaces: DEFAULT_MAX_INTERFACES,
            max_neighbours_per_interface: DEFAULT_MAX_NEIGHBOURS_PER_INTERFACE,
            max_capabilities: DEFAULT_MAX_CAPABILITIES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_links_per_host: DEFAULT_MAX_LINKS_PER_HOST,
            max_links_per_port: DEFAULT_MAX_LINKS_PER_PORT,
        }
    }
}


#[derive(Debug, Error)]
#[error("setting `{field}` is out of range")]
pub struct SettingsError {
    pub field: &'static str,
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] SettingsError),
}


pub fn limits_of(settings: &Settings) -> Limits {
    Limits {
        max_bytes: settings.max_bytes,
        max_port_bytes: settings.max_port_bytes,
        max_host_read_bytes: settings.max_host_read_bytes,
        max_host_seconds: settings.max_host_seconds,
        port_timeout_seconds: settings.port_timeout_seconds,
        max_interfaces: settings.max_interfaces,
        max_neighbours_per_interface: settings.max_neighbours_per_interface,
        max_capabilities: settings.max_capabilities,
        max_text_bytes: settings.max_text_bytes,
        max_links_per_host: settings.max_links_per_host,
        max_links_per_port: settings.max_links_per_port,
    }
}


/// Strict parse (unknown keys refused, input text never echoed); range checks are `validate_settings`.
pub fn parse_settings(text: &str, file: &str) -> Result<Settings, ConfigError> {
    parse_document(text, file)
}


/// The first refused field is named, never clamped.
pub fn validate_settings(settings: &Settings) -> Result<(), SettingsError> {
    let checks = [
        (
            "stale_after_seconds",
            (1..=MAX_STALE_AFTER_SECONDS).contains(&settings.stale_after_seconds),
        ),
        ("max_bytes", (1..=MAX_HOST_READ_BYTES_CEILING).contains(&settings.max_bytes)),
        ("max_port_bytes", (1..=settings.max_bytes).contains(&settings.max_port_bytes)),
        (
            "max_host_read_bytes",
            (settings.max_port_bytes..=MAX_HOST_READ_BYTES_CEILING).contains(&settings.max_host_read_bytes),
        ),
        (
            "port_timeout_seconds",
            (MIN_PORT_TIMEOUT_SECONDS..=MAX_PORT_TIMEOUT_SECONDS).contains(&settings.port_timeout_seconds),
        ),
        (
            "max_host_seconds",
            (settings.port_timeout_seconds..=MAX_HOST_SECONDS_CEILING).contains(&settings.max_host_seconds),
        ),
        ("max_interfaces", (1..=MAX_INTERFACES_CEILING).contains(&settings.max_interfaces)),
        (
            "max_neighbours_per_interface",
            (1..=MAX_NEIGHBOURS_CEILING).contains(&settings.max_neighbours_per_interface),
        ),
        ("max_capabilities", (1..=MAX_CAPABILITIES_CEILING).contains(&settings.max_capabilities)),
        ("max_text_bytes", (1..=MAX_TEXT_BYTES_CEILING).contains(&settings.max_text_bytes)),
        (
            "max_links_per_host",
            (1..=MAX_LINKS_PER_HOST_CEILING).contains(&settings.max_links_per_host),
        ),
        (
            "max_links_per_port",
            (1..=settings.max_links_per_host).contains(&settings.max_links_per_port),
        ),
    ];
    checks
        .into_iter()
        .find(|(_, within)| !within)
        .map_or(Ok(()), |(field, _)| Err(SettingsError { field }))
}


pub fn settings_state(settings: &Settings) -> ConfigState {
    [
        ("stale_after_seconds", settings.stale_after_seconds.to_string()),
        ("max_bytes", settings.max_bytes.to_string()),
        ("max_port_bytes", settings.max_port_bytes.to_string()),
        ("max_host_read_bytes", settings.max_host_read_bytes.to_string()),
        ("max_host_seconds", settings.max_host_seconds.to_string()),
        ("port_timeout_seconds", settings.port_timeout_seconds.to_string()),
        ("max_interfaces", settings.max_interfaces.to_string()),
        ("max_neighbours_per_interface", settings.max_neighbours_per_interface.to_string()),
        ("max_capabilities", settings.max_capabilities.to_string()),
        ("max_text_bytes", settings.max_text_bytes.to_string()),
        ("max_links_per_host", settings.max_links_per_host.to_string()),
        ("max_links_per_port", settings.max_links_per_port.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// A reload that breaks a bound is refused (audited `denied`, logged) and the old settings stay.
pub fn topology_subscriber() -> Subscriber<Settings> {
    Subscriber {
        section: TOPOLOGY_SECTION.to_owned(),
        validate: Box::new(|settings| validate_settings(settings).map_err(Into::into)),
        apply: Box::new(|_settings| ()),
    }
}


/// Reads the whole file once per load, parses strictly, validates the first snapshot; the caller takes one `current_config` per use.
pub fn open_topology(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<Settings>, OpenError> {
    let mut engine = open_engine(
        Box::new(move || parse_settings(&read_file(&path)?, &path.display().to_string())),
        settings_state,
        Vec::new(),
        audit,
        context,
    )?;
    validate_settings(&current_config(&engine))?;
    engine.subscribers.push(topology_subscriber());
    Ok(engine)
}

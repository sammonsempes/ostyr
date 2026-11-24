use crate::error::SettingsError;
use crate::model::{
    RelaySettings, AGENT_CONNECT_TIMEOUT_SECONDS, ALLOWED_PUNCTUATION, DESCRIPTORS_PER_CONNECTION, MAX_CONNECTIONS_LIMIT, MAX_SECONDS_LIMIT,
    MAX_SETTINGS_BYTES, MIN_IDLE_SECONDS, MIN_LIFETIME_SECONDS, RESERVED_FDS, SETTINGS_FILE_CLASS, SETTINGS_SECTION,
};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_bytes_capped};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};


/// A socket address, folded so an IPv4-mapped IPv6 address compares as IPv4; the error never repeats the text.
pub fn deserialize_address<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<SocketAddr, Source::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse::<SocketAddr>()
        .map(|parsed| SocketAddr::new(parsed.ip().to_canonical(), parsed.port()))
        .map_err(|_error| Source::Error::custom("not a socket address"))
}


/// The soft `RLIMIT_NOFILE`, `u64::MAX` when unlimited.
pub fn nofile_soft_limit() -> u64 {
    rustix::process::getrlimit(rustix::process::Resource::Nofile).current.unwrap_or(u64::MAX)
}


pub fn is_broadcast(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(v4) if v4.is_broadcast())
}


/// A zero port, a multicast or broadcast address, and (unless `allow_unspecified`) the unspecified address.
pub fn unusable(address: SocketAddr, allow_unspecified: bool) -> bool {
    address.port() == 0 || address.ip().is_multicast() || is_broadcast(address.ip()) || (!allow_unspecified && address.ip().is_unspecified())
}


/// The relay would connect to itself: the same address, or a wildcard listener with a loopback upstream on its port.
pub fn self_loop(listen: SocketAddr, upstream: SocketAddr) -> bool {
    listen == upstream || (listen.ip().is_unspecified() && upstream.ip().is_loopback() && upstream.port() == listen.port())
}


/// Names of the settings that are out of bounds or inconsistent.
pub fn invalid_settings(settings: &RelaySettings) -> Vec<&'static str> {
    [
        ("listen", unusable(settings.listen, true)),
        ("upstream", unusable(settings.upstream, false)),
        ("upstream is the relay itself", self_loop(settings.listen, settings.upstream)),
        ("max_connections", !(1..=MAX_CONNECTIONS_LIMIT).contains(&settings.max_connections)),
        (
            "max_connections_per_source",
            !(1..=settings.max_connections).contains(&settings.max_connections_per_source),
        ),
        (
            "connect_timeout_seconds",
            !(1..AGENT_CONNECT_TIMEOUT_SECONDS).contains(&settings.connect_timeout_seconds),
        ),
        ("idle_seconds", !(MIN_IDLE_SECONDS..=MAX_SECONDS_LIMIT).contains(&settings.idle_seconds)),
        (
            "max_lifetime_seconds",
            !(MIN_LIFETIME_SECONDS..=MAX_SECONDS_LIMIT).contains(&settings.max_lifetime_seconds),
        ),
        (
            "connect_timeout_seconds must be below idle_seconds",
            settings.connect_timeout_seconds >= settings.idle_seconds,
        ),
        (
            "idle_seconds must not exceed max_lifetime_seconds",
            settings.idle_seconds > settings.max_lifetime_seconds,
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


/// Two descriptors per connection plus a reserve must fit the soft limit.
pub fn check_descriptors(max_connections: usize, soft: u64) -> Result<(), SettingsError> {
    let needed = u64::try_from(max_connections)
        .unwrap_or(u64::MAX)
        .saturating_mul(DESCRIPTORS_PER_CONNECTION)
        .saturating_add(RESERVED_FDS);
    if needed > soft {
        Err(SettingsError::Descriptors {
            max: max_connections,
            needed,
            soft,
        })
    } else {
        Ok(())
    }
}


pub fn validate_settings(settings: &RelaySettings, soft: u64) -> Result<(), SettingsError> {
    let invalid = invalid_settings(settings);
    if invalid.is_empty() {
        check_descriptors(settings.max_connections, soft)
    } else {
        Err(SettingsError::Invalid(invalid.join(", ")))
    }
}


/// A reload may not change `listen`; everything else is validated like the first load.
pub fn validate_reload(candidate: &RelaySettings, started: SocketAddr, soft: u64) -> Result<(), SettingsError> {
    if candidate.listen == started {
        validate_settings(candidate, soft)
    } else {
        Err(SettingsError::ListenChanged)
    }
}


/// One line per field, so a reload's diff and audit entry show which bound changed.
pub fn settings_state(settings: &RelaySettings) -> ConfigState {
    format!("{settings:#?}")
        .lines()
        .filter_map(|line| line.trim().trim_end_matches(',').split_once(": "))
        .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_owned()))
        .collect()
}


/// The position and value of the first byte off the ASCII allowlist: letters, digits and a few punctuation marks, so no tag, anchor, alias, merge key, escape, comment or block scalar.
pub fn check_allowlist(bytes: &[u8], file: &str) -> Result<(), ConfigError> {
    match bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || ALLOWED_PUNCTUATION.contains(byte)))
    {
        Some(offset) => Err(ConfigError::WatchedFile {
            file: file.to_owned(),
            reason: format!("a byte at offset {offset} is outside the {SETTINGS_FILE_CLASS} ASCII allowlist"),
        }),
        None => Ok(()),
    }
}


/// Reads the file once, checks those bytes against the allowlist, then parses the same bytes.
pub fn read_settings(path: &Path) -> Result<RelaySettings, ConfigError> {
    let file = path.display().to_string();
    let bytes = read_bytes_capped(path, MAX_SETTINGS_BYTES)?;
    check_allowlist(&bytes, &file)?;
    let text: String = bytes.iter().map(|byte| char::from(*byte)).collect();
    parse_document(&text, &file)
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<RelaySettings>> {
    Box::new(move || read_settings(&path))
}


pub fn settings_subscriber(started: SocketAddr) -> Subscriber<RelaySettings> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(move |candidate| validate_reload(candidate, started, nofile_soft_limit()).map_err(BoxError::from)),
        apply: Box::new(|_applied| ()),
    }
}


/// The first load must be valid; later reloads are validated (and `listen` pinned), audited and swapped atomically.
pub fn open_settings_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
    soft: u64,
) -> Result<ReloadEngine<RelaySettings>, SettingsError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_settings(&first, soft)?;
    Ok(ReloadEngine {
        subscribers: vec![settings_subscriber(first.listen)],
        ..engine
    })
}

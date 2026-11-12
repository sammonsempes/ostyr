use crate::error::StatusPageError;
use crate::model::{
    PageSettings, MAX_CONNECTIONS_LIMIT, MAX_CONNECTIONS_PER_SOURCE_LIMIT, MAX_CONNECTION_TIMEOUT_SECONDS, MAX_HEADERS_LIMIT, MAX_HEADER_BYTES_LIMIT,
    MAX_HEADER_READ_TIMEOUT_SECONDS, MAX_PROXY_HEADER_BYTES_LIMIT, MAX_PUBLISH_INTERVAL_SECONDS, MAX_SOURCES_LIMIT, MAX_TRUSTED_PROXIES,
    MAX_WIDE_MULTIPLIER, MAX_WIDE_PREFIX_BITS, MIN_HEADER_BYTES, MIN_PROXY_HEADER_BYTES, MIN_PUBLISH_INTERVAL_SECONDS, SETTINGS_SECTION,
};
use crate::types::{BoxError, SharedSettings};
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use std::path::PathBuf;
use std::sync::Arc;


pub fn shared_settings(settings: PageSettings) -> SharedSettings {
    Arc::new(ArcSwap::from_pointee(settings))
}


/// Names of the settings that are zero or out of range in `settings`.
pub fn invalid_settings(settings: &PageSettings) -> Vec<&'static str> {
    [
        ("rate_per_second", settings.rate_per_second == 0),
        ("burst", settings.burst == 0),
        ("max_sources", settings.max_sources == 0 || settings.max_sources > MAX_SOURCES_LIMIT),
        (
            "max_connections",
            settings.max_connections == 0 || settings.max_connections > MAX_CONNECTIONS_LIMIT,
        ),
        (
            "max_connections_per_source",
            settings.max_connections_per_source == 0 || settings.max_connections_per_source > MAX_CONNECTIONS_PER_SOURCE_LIMIT,
        ),
        (
            "header_read_timeout_seconds",
            settings.header_read_timeout_seconds == 0 || settings.header_read_timeout_seconds > MAX_HEADER_READ_TIMEOUT_SECONDS,
        ),
        (
            "connection_timeout_seconds",
            settings.connection_timeout_seconds == 0 || settings.connection_timeout_seconds > MAX_CONNECTION_TIMEOUT_SECONDS,
        ),
        ("max_headers", settings.max_headers == 0 || settings.max_headers > MAX_HEADERS_LIMIT),
        (
            "max_header_bytes",
            settings.max_header_bytes < MIN_HEADER_BYTES || settings.max_header_bytes > MAX_HEADER_BYTES_LIMIT,
        ),
        ("cache_max_age_seconds", settings.cache_max_age_seconds == 0),
        ("trusted_proxies", settings.trusted_proxies.len() > MAX_TRUSTED_PROXIES),
        (
            "max_proxy_header_bytes",
            settings.max_proxy_header_bytes < MIN_PROXY_HEADER_BYTES || settings.max_proxy_header_bytes > MAX_PROXY_HEADER_BYTES_LIMIT,
        ),
        (
            "wide_prefix_bits",
            settings.wide_prefix_bits == 0 || settings.wide_prefix_bits > MAX_WIDE_PREFIX_BITS,
        ),
        (
            "wide_multiplier",
            settings.wide_multiplier == 0 || settings.wide_multiplier > MAX_WIDE_MULTIPLIER,
        ),
        (
            "publish_interval_seconds",
            !(MIN_PUBLISH_INTERVAL_SECONDS..=MAX_PUBLISH_INTERVAL_SECONDS).contains(&settings.publish_interval_seconds),
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


pub fn validate_settings(settings: &PageSettings) -> Result<(), StatusPageError> {
    let invalid = invalid_settings(settings);
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(StatusPageError::InvalidSettings(invalid.join(", ")))
    }
}


/// One line per field, so a reload's diff and audit entry show which bound changed.
pub fn settings_state(settings: &PageSettings) -> ConfigState {
    let proxies = settings.trusted_proxies.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
    let mut state: ConfigState = format!("{settings:#?}")
        .lines()
        .filter_map(|line| line.trim().trim_end_matches(',').split_once(": "))
        .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_owned()))
        .collect();
    state.insert(format!("{SETTINGS_SECTION}.trusted_proxies"), proxies);
    state
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<PageSettings>> {
    Box::new(move || load_file::<PageSettings>(&path))
}


/// Refuses an invalid candidate before the swap, then publishes each applied one to `shared`.
pub fn settings_subscriber(shared: SharedSettings) -> Subscriber<PageSettings> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(|candidate| validate_settings(candidate).map_err(BoxError::from)),
        apply: Box::new(move |applied| shared.store(Arc::new(applied.clone()))),
    }
}


/// The first load must be valid; later reloads are validated, audited and swapped atomically, an invalid file keeps the old settings.
pub fn open_settings_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<PageSettings>, SharedSettings), StatusPageError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_settings(&first)?;
    let shared = shared_settings(first.as_ref().clone());
    let subscribed = ReloadEngine {
        subscribers: vec![settings_subscriber(Arc::clone(&shared))],
        ..engine
    };
    Ok((subscribed, shared))
}

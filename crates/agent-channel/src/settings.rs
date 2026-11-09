use crate::error::SettingsError;
use crate::model::{ChannelSettings, ServerState, MAX_MESSAGE_BYTES_LIMIT, MAX_TOTAL_CONNECTIONS_LIMIT, SETTINGS_SECTION};
use crate::types::{BoxError, SharedSettings};
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub fn shared_settings(settings: ChannelSettings) -> SharedSettings {
    Arc::new(ArcSwap::from_pointee(settings))
}


/// The settings in force now: a whole snapshot, old or new, never a mix.
pub fn settings_of(state: &ServerState) -> Arc<ChannelSettings> {
    state.settings.load_full()
}


/// Names of the settings that are zero, or too large to be a bound, in `settings`.
pub fn invalid_settings(settings: &ChannelSettings) -> Vec<&'static str> {
    [
        ("heartbeat_interval_seconds", settings.heartbeat_interval_seconds == 0),
        (
            "max_message_bytes",
            settings.max_message_bytes == 0 || settings.max_message_bytes > MAX_MESSAGE_BYTES_LIMIT,
        ),
        ("rate_window_seconds", settings.rate_window_seconds == 0),
        ("max_streams_per_agent", settings.max_streams_per_agent == 0),
        ("max_connections_per_agent", settings.max_connections_per_agent == 0),
        ("max_inflight_per_agent", settings.max_inflight_per_agent == 0),
        ("max_requests_per_window", settings.max_requests_per_window == 0),
        ("silence_threshold_seconds", settings.silence_threshold_seconds == 0),
        ("silence_check_interval_seconds", settings.silence_check_interval_seconds == 0),
        ("max_streams_per_connection", settings.max_streams_per_connection == 0),
        ("request_timeout_seconds", settings.request_timeout_seconds == 0),
        ("first_request_timeout_seconds", settings.first_request_timeout_seconds == 0),
        (
            "max_total_connections",
            settings.max_total_connections == 0 || settings.max_total_connections > MAX_TOTAL_CONNECTIONS_LIMIT,
        ),
        ("max_pending_handshakes", settings.max_pending_handshakes == 0),
        ("max_pending_handshakes_per_source", settings.max_pending_handshakes_per_source == 0),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


pub fn validate_settings(settings: &ChannelSettings) -> Result<(), SettingsError> {
    let invalid = invalid_settings(settings);
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(SettingsError::Invalid(invalid.join(", ")))
    }
}


/// One line per field, so a reload's diff and audit entry show which bound changed.
pub fn settings_state(settings: &ChannelSettings) -> ConfigState {
    format!("{settings:#?}")
        .lines()
        .filter_map(|line| line.trim().trim_end_matches(',').split_once(": "))
        .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_owned()))
        .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<ChannelSettings>> {
    Box::new(move || load_file::<ChannelSettings>(&path))
}


/// Refuses an invalid candidate before the swap, then publishes each applied one to `shared`.
pub fn settings_subscriber(shared: SharedSettings) -> Subscriber<ChannelSettings> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(|candidate| validate_settings(candidate).map_err(BoxError::from)),
        apply: Box::new(move |applied| shared.store(Arc::new(applied.clone()))),
    }
}


/// The first load must be valid. Later reloads are validated, audited and swapped atomically; an invalid file keeps the old settings.
pub fn open_settings_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<ChannelSettings>, SharedSettings), SettingsError> {
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


/// Grows or shrinks the permits of the total connection cap towards `wanted`; returns the capacity now in force.
pub fn resize_total(connections: &Semaphore, capacity: usize, wanted: usize) -> usize {
    if wanted > capacity {
        connections.add_permits(wanted - capacity);
        wanted
    } else {
        capacity - connections.forget_permits(capacity - wanted)
    }
}

use crate::error::SourceError;
use crate::model::{
    LinuxFile, OsquerySettings, SensorSettings, SourceSettings, UpdateSettings, MAX_DNS_RESOLVERS, MAX_ENDPOINTS, MAX_LINES_PER_POLL_CEILING,
    MAX_LINE_BYTES_CEILING, MAX_OSQUERY_DEADLINE_SECONDS, MAX_OSQUERY_MEMORY_BYTES, MAX_POLL_MILLIS, MAX_RESTARTS_PER_HOUR_CEILING,
    MAX_SENSOR_INTERVAL_SECONDS, MAX_SENSOR_WINDOW_SECONDS, MAX_SPOOL_BYTES_CEILING, MAX_UPDATE_DEADLINE_SECONDS, MAX_UPDATE_INTERVAL_SECONDS,
    MIN_OSQUERY_MEMORY_BYTES, MIN_UPDATE_INTERVAL_SECONDS, SETTINGS_SECTION,
};
use crate::types::{SettingsEngine, SharedOsquery, SharedSensor, SharedSource, SharedUpdates};
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;


/// Names of the settings that are zero or above their ceiling.
pub fn invalid_settings(settings: &SourceSettings) -> Vec<&'static str> {
    [
        ("poll_millis", settings.poll_millis == 0 || settings.poll_millis > MAX_POLL_MILLIS),
        (
            "max_line_bytes",
            settings.max_line_bytes == 0 || settings.max_line_bytes > MAX_LINE_BYTES_CEILING,
        ),
        (
            "max_spool_bytes",
            settings.max_spool_bytes == 0 || settings.max_spool_bytes > MAX_SPOOL_BYTES_CEILING,
        ),
        (
            "max_lines_per_poll",
            settings.max_lines_per_poll == 0 || settings.max_lines_per_poll > MAX_LINES_PER_POLL_CEILING,
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


/// Names of the sensor settings that are zero (the restart cap may be zero) or above their ceiling.
pub fn invalid_sensor_settings(settings: &SensorSettings) -> Vec<&'static str> {
    [
        (
            "window_seconds",
            settings.window_seconds == 0 || settings.window_seconds > MAX_SENSOR_WINDOW_SECONDS,
        ),
        (
            "interval_seconds",
            settings.interval_seconds == 0 || settings.interval_seconds > MAX_SENSOR_INTERVAL_SECONDS,
        ),
        ("max_restarts_per_hour", settings.max_restarts_per_hour > MAX_RESTARTS_PER_HOUR_CEILING),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


/// Names of the update settings out of range: an interval under its minimum or above its ceiling, a zero deadline or one above its ceiling.
pub fn invalid_update_settings(settings: &UpdateSettings) -> Vec<&'static str> {
    [
        (
            "updates.interval_seconds",
            !(MIN_UPDATE_INTERVAL_SECONDS..=MAX_UPDATE_INTERVAL_SECONDS).contains(&settings.interval_seconds),
        ),
        (
            "updates.deadline_seconds",
            settings.deadline_seconds == 0 || settings.deadline_seconds > MAX_UPDATE_DEADLINE_SECONDS,
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


/// Names of the osquery settings out of range: a relative path, a zero deadline or one above its ceiling, a memory limit outside its range.
pub fn invalid_osquery_settings(settings: &OsquerySettings) -> Vec<&'static str> {
    [
        ("osquery.path", !settings.path.is_absolute()),
        ("osquery.prlimit_path", !settings.prlimit_path.is_absolute()),
        (
            "osquery.max_memory_bytes",
            !(MIN_OSQUERY_MEMORY_BYTES..=MAX_OSQUERY_MEMORY_BYTES).contains(&settings.max_memory_bytes),
        ),
        (
            "osquery.deadline_seconds",
            settings.deadline_seconds == 0 || settings.deadline_seconds > MAX_OSQUERY_DEADLINE_SECONDS,
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


/// An address no peer can have: unspecified, loopback, multicast or the IPv4 broadcast, an IPv4-mapped IPv6 form judged as the IPv4 address.
pub fn unusable_address(address: &IpAddr) -> bool {
    let canonical = address.to_canonical();
    canonical.is_unspecified() || canonical.is_loopback() || canonical.is_multicast() || matches!(canonical, IpAddr::V4(v4) if v4.is_broadcast())
}


/// Names of the isolation settings that are out of range: too many endpoints or resolvers, a zero port, a relative `nft_path`.
pub fn invalid_isolation_settings(file: &LinuxFile) -> Vec<&'static str> {
    [
        ("isolation.endpoints", file.isolation.endpoints.len() > MAX_ENDPOINTS),
        ("isolation.ports", file.isolation.endpoints.iter().any(|endpoint| endpoint.port == 0)),
        ("isolation.dns", file.isolation.dns.len() > MAX_DNS_RESOLVERS),
        (
            "isolation.endpoints.address",
            file.isolation.endpoints.iter().any(|endpoint| unusable_address(&endpoint.address)),
        ),
        ("isolation.dns.address", file.isolation.dns.iter().any(unusable_address)),
        ("nft_path", !file.nft_path.is_absolute()),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


pub fn validate_settings(settings: &SourceSettings) -> Result<(), SourceError> {
    let invalid = invalid_settings(settings);
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(SourceError::Settings(invalid.join(", ")))
    }
}


pub fn validate_file(file: &LinuxFile) -> Result<(), SourceError> {
    validate_settings(&file.settings)?;
    let invalid: Vec<&str> = invalid_sensor_settings(&file.sensor)
        .into_iter()
        .chain(invalid_isolation_settings(file))
        .chain(invalid_update_settings(&file.updates))
        .chain(invalid_osquery_settings(&file.osquery))
        .collect();
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(SourceError::Settings(invalid.join(", ")))
    }
}


/// One entry per setting, so a reload's diff and audit entry show which bound changed; the paths of the file are not part of it.
pub fn settings_state(file: &LinuxFile) -> ConfigState {
    let settings = &file.settings;
    [
        ("poll_millis", settings.poll_millis),
        ("max_line_bytes", settings.max_line_bytes),
        ("max_spool_bytes", settings.max_spool_bytes),
        ("max_lines_per_poll", settings.max_lines_per_poll),
    ]
    .into_iter()
    .chain([
        ("sensor_window_seconds", file.sensor.window_seconds),
        ("sensor_interval_seconds", file.sensor.interval_seconds),
        ("sensor_max_restarts_per_hour", file.sensor.max_restarts_per_hour),
        ("updates_interval_seconds", file.updates.interval_seconds),
        ("updates_deadline_seconds", file.updates.deadline_seconds),
        ("osquery_deadline_seconds", file.osquery.deadline_seconds),
        ("osquery_max_memory_bytes", file.osquery.max_memory_bytes),
    ])
    .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_string()))
    .chain([
        (format!("{SETTINGS_SECTION}.updates_manager"), format!("{:?}", file.updates.manager)),
        (format!("{SETTINGS_SECTION}.osquery_path"), file.osquery.path.display().to_string()),
        (
            format!("{SETTINGS_SECTION}.osquery_prlimit_path"),
            file.osquery.prlimit_path.display().to_string(),
        ),
    ])
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<LinuxFile>> {
    Box::new(move || load_file::<LinuxFile>(&path))
}


pub fn settings_subscriber(shared: SharedSource, sensor: SharedSensor, updates: SharedUpdates, osquery: SharedOsquery) -> Subscriber<LinuxFile> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(|candidate| validate_file(candidate).map_err(BoxError::from)),
        apply: Box::new(move |applied| {
            shared.store(Arc::new(applied.settings.clone()));
            sensor.store(Arc::new(applied.sensor.clone()));
            updates.store(Arc::new(applied.updates.clone()));
            osquery.store(Arc::new(applied.osquery.clone()));
        }),
    }
}


/// The first load must be valid; later reloads are validated, audited and swapped atomically, an invalid file keeps the old settings.
pub fn open_settings_engine(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<SettingsEngine, SourceError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_file(&first)?;
    let shared: SharedSource = Arc::new(ArcSwap::from_pointee(first.settings.clone()));
    let sensor: SharedSensor = Arc::new(ArcSwap::from_pointee(first.sensor.clone()));
    let updates: SharedUpdates = Arc::new(ArcSwap::from_pointee(first.updates.clone()));
    let osquery: SharedOsquery = Arc::new(ArcSwap::from_pointee(first.osquery.clone()));
    let subscribed = ReloadEngine {
        subscribers: vec![settings_subscriber(
            Arc::clone(&shared),
            Arc::clone(&sensor),
            Arc::clone(&updates),
            Arc::clone(&osquery),
        )],
        ..engine
    };
    Ok((subscribed, shared, sensor, updates, osquery))
}

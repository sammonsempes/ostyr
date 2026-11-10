use crate::error::SourceError;
use crate::model::{
    LinuxFile, SensorSettings, SourceSettings, MAX_LINES_PER_POLL_CEILING, MAX_LINE_BYTES_CEILING, MAX_POLL_MILLIS, MAX_RESTARTS_PER_HOUR_CEILING,
    MAX_SENSOR_INTERVAL_SECONDS, MAX_SENSOR_WINDOW_SECONDS, MAX_SPOOL_BYTES_CEILING, SETTINGS_SECTION,
};
use crate::types::{SharedSensor, SharedSource};
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
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
    let invalid = invalid_sensor_settings(&file.sensor);
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
    ])
    .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_string()))
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<LinuxFile>> {
    Box::new(move || load_file::<LinuxFile>(&path))
}


pub fn settings_subscriber(shared: SharedSource, sensor: SharedSensor) -> Subscriber<LinuxFile> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(|candidate| validate_file(candidate).map_err(BoxError::from)),
        apply: Box::new(move |applied| {
            shared.store(Arc::new(applied.settings.clone()));
            sensor.store(Arc::new(applied.sensor.clone()));
        }),
    }
}


/// The first load must be valid; later reloads are validated, audited and swapped atomically, an invalid file keeps the old settings.
pub fn open_settings_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<LinuxFile>, SharedSource, SharedSensor), SourceError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_file(&first)?;
    let shared: SharedSource = Arc::new(ArcSwap::from_pointee(first.settings.clone()));
    let sensor: SharedSensor = Arc::new(ArcSwap::from_pointee(first.sensor.clone()));
    let subscribed = ReloadEngine {
        subscribers: vec![settings_subscriber(Arc::clone(&shared), Arc::clone(&sensor))],
        ..engine
    };
    Ok((subscribed, shared, sensor))
}

use crate::error::SourceError;
use crate::model::{LinuxFile, SourceSettings, SETTINGS_SECTION};
use crate::types::SharedSource;
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::path::PathBuf;
use std::sync::Arc;


/// Names of the settings that are zero.
pub fn invalid_settings(settings: &SourceSettings) -> Vec<&'static str> {
    [
        ("poll_millis", settings.poll_millis == 0),
        ("max_line_bytes", settings.max_line_bytes == 0),
        ("max_spool_bytes", settings.max_spool_bytes == 0),
        ("max_lines_per_poll", settings.max_lines_per_poll == 0),
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
    .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value.to_string()))
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<LinuxFile>> {
    Box::new(move || load_file::<LinuxFile>(&path))
}


pub fn settings_subscriber(shared: SharedSource) -> Subscriber<LinuxFile> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(|candidate| validate_settings(&candidate.settings).map_err(BoxError::from)),
        apply: Box::new(move |applied| shared.store(Arc::new(applied.settings.clone()))),
    }
}


/// The first load must be valid; later reloads are validated, audited and swapped atomically, an invalid file keeps the old settings.
pub fn open_settings_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<LinuxFile>, SharedSource), SourceError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    validate_settings(&first.settings)?;
    let shared: SharedSource = Arc::new(ArcSwap::from_pointee(first.settings.clone()));
    let subscribed = ReloadEngine {
        subscribers: vec![settings_subscriber(Arc::clone(&shared))],
        ..engine
    };
    Ok((subscribed, shared))
}

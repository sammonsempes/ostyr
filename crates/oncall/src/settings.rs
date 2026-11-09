use crate::error::OncallError;
use crate::limits::{MAX_PATH_LEN, MAX_SECRET_DIRS, MAX_TIMEOUT_MILLIS};
use crate::validate::{check_between, check_name};
use core_config::parse::{parse_document, read_file};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};


pub const SETTINGS_SECTION: &str = "oncall-transport";


/// `secret_dirs` maps a tenant to its secrets directory; `ca_file` is the only CA trusted when set, else the Mozilla roots.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSettings {
    pub timeout_millis: u64,
    pub ca_file: Option<String>,
    pub secret_dirs: BTreeMap<String, String>,
}


pub fn validate_settings(settings: &TransportSettings) -> Result<(), OncallError> {
    check_between("timeout_millis", settings.timeout_millis, 1, MAX_TIMEOUT_MILLIS)?;
    check_between("secret_dirs", settings.secret_dirs.len() as u64, 0, MAX_SECRET_DIRS)?;
    settings
        .ca_file
        .iter()
        .try_for_each(|path| check_between("ca_file", path.chars().count() as u64, 1, MAX_PATH_LEN))?;
    settings.secret_dirs.iter().try_for_each(|(tenant, path)| {
        check_name("secret_dirs tenant", tenant)?;
        check_between("secret_dirs path", path.chars().count() as u64, 1, MAX_PATH_LEN)
    })
}


pub fn parse_settings(text: &str, file: &str) -> Result<TransportSettings, OncallError> {
    let settings: TransportSettings = parse_document(text, file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


pub fn settings_state(settings: &TransportSettings) -> ConfigState {
    ConfigState::from([
        ("timeout_millis".to_owned(), settings.timeout_millis.to_string()),
        ("ca_file".to_owned(), format!("{:?}", settings.ca_file)),
        ("secret_dirs".to_owned(), format!("{:?}", settings.secret_dirs)),
    ])
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<TransportSettings>> {
    Box::new(move || read_file(&path).and_then(|text| parse_document(&text, &path.display().to_string())))
}


pub fn check_settings(settings: &TransportSettings) -> Result<(), BoxError> {
    validate_settings(settings).map_err(BoxError::from)
}


/// The hook that refuses an invalid settings file before a swap, so a reload keeps the old settings.
pub fn settings_subscriber() -> Subscriber<TransportSettings> {
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(check_settings),
        apply: Box::new(|_settings| tracing::info!("on-call transport settings swapped")),
    }
}


/// Loads and validates the first settings; later changes go through `core_config::reload::reload`.
pub fn open_settings_engine(path: &Path, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<TransportSettings>, OncallError> {
    let engine = open_engine(
        settings_loader(path.to_path_buf()),
        settings_state,
        vec![settings_subscriber()],
        audit,
        context,
    )?;
    validate_settings(&current_config(&engine))?;
    Ok(engine)
}

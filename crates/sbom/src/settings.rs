//! Syft settings (a file applied live through core-config) and the typed scan target.

use crate::error::{SettingsError, TargetError};
use crate::limits::{DIRECTORY_SCHEME, DOCKER_SCHEME, OCI_SCHEME, SYFT_SECTION, SYFT_STATE_KEY};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyftSettings {
    pub binary: PathBuf,
    pub work_dir: PathBuf,
    pub deadline_millis: u64,
    pub max_stdout_bytes: usize,
    pub max_components: usize,
    pub max_stderr_bytes: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Directory(PathBuf),
    OciArchive(PathBuf),
    DockerArchive(PathBuf),
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] SettingsError),
}


pub fn ensure<Failure>(condition: bool, failure: Failure) -> Result<(), Failure> {
    condition.then_some(()).ok_or(failure)
}


/// Absolute binary and work directory, and every deadline and cap above zero.
pub fn validate_settings(settings: &SyftSettings) -> Result<(), SettingsError> {
    ensure(settings.binary.is_absolute(), SettingsError::Invalid("binary"))?;
    ensure(settings.work_dir.is_absolute(), SettingsError::Invalid("work_dir"))?;
    ensure(settings.deadline_millis > 0, SettingsError::Invalid("deadline_millis"))?;
    ensure(settings.max_stdout_bytes > 0, SettingsError::Invalid("max_stdout_bytes"))?;
    ensure(settings.max_components > 0, SettingsError::Invalid("max_components"))?;
    ensure(settings.max_stderr_bytes > 0, SettingsError::Invalid("max_stderr_bytes"))
}


pub fn settings_state(settings: &SyftSettings) -> ConfigState {
    std::iter::once((SYFT_STATE_KEY.to_owned(), format!("{settings:?}"))).collect()
}


pub fn settings_subscriber() -> Subscriber<SyftSettings> {
    Subscriber {
        section: SYFT_SECTION.to_owned(),
        validate: Box::new(|settings| validate_settings(settings).map_err(Into::into)),
        apply: Box::new(|_settings| ()),
    }
}


/// Loads and validates the first settings; later reloads are validated by the subscriber and refused when invalid.
pub fn open_settings(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<SyftSettings>, OpenError> {
    let engine = open_engine(
        Box::new(move || load_file::<SyftSettings>(&path)),
        settings_state,
        vec![settings_subscriber()],
        audit,
        context,
    )?;
    validate_settings(&current_config(&engine))?;
    Ok(engine)
}


fn target_path(target: &Target) -> &Path {
    match target {
        Target::Directory(path) | Target::OciArchive(path) | Target::DockerArchive(path) => path,
    }
}


fn target_scheme(target: &Target) -> &'static str {
    match target {
        Target::Directory(_) => DIRECTORY_SCHEME,
        Target::OciArchive(_) => OCI_SCHEME,
        Target::DockerArchive(_) => DOCKER_SCHEME,
    }
}


/// The syft source argument, refused before any spawn when the path is not UTF-8, absolute, free of control characters and of a leading `-`.
pub fn source_argument(target: &Target) -> Result<String, TargetError> {
    let text = target_path(target).to_str().ok_or(TargetError::NotUtf8)?;
    ensure(!text.chars().any(char::is_control), TargetError::Control)?;
    ensure(!text.starts_with('-'), TargetError::LeadingDash)?;
    ensure(target_path(target).is_absolute(), TargetError::Relative)?;
    Ok(format!("{}{text}", target_scheme(target)))
}

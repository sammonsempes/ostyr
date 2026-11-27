use crate::cli::MAX_SAMPLING_FILE_BYTES;
use crate::sampling::{parse_sampling, Sampling, SamplingError};
use crate::settings::{load_traces_settings, TracesSettings};
use core_config::error::ConfigError;
use core_config::parse::{open_regular, read_text_capped};
use core_config::types::{ConfigState, LoaderFn};
use metrics_ingest::settings::LoadError;
use std::path::{Path, PathBuf};


/// A configuration error for the reload engine: parse errors keep their fixed text, a refused value its fixed `Display`.
pub fn settings_refusal(path: &Path, error: LoadError) -> ConfigError {
    match error {
        LoadError::Config(config) => config,
        LoadError::Invalid(invalid) => ConfigError::WatchedFile {
            file: path.display().to_string(),
            reason: invalid.to_string(),
        },
    }
}


/// The loader of a `ReloadEngine<TracesSettings>`: the same checks as `load_traces_settings`, a refusal keeps the old settings in force.
pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<TracesSettings>> {
    Box::new(move || load_traces_settings(&path).map_err(|error| settings_refusal(&path, error)))
}


/// The audited state of the settings: paths and numbers, never the password.
pub fn settings_state(settings: &TracesSettings) -> ConfigState {
    [
        ("url", settings.url.clone()),
        ("user", settings.user.clone()),
        ("password_file", settings.password_file.display().to_string()),
        (
            "ca_file",
            settings.ca_file.as_ref().map_or_else(String::new, |file| file.display().to_string()),
        ),
        ("database", settings.database.clone()),
        ("table", settings.table.clone()),
        ("timeout_ms", settings.timeout_ms.to_string()),
        ("limits", format!("{:?}", settings.limits)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn sampling_refusal(path: &Path, error: SamplingError) -> ConfigError {
    match error {
        SamplingError::Parse(config) => config,
        other => ConfigError::WatchedFile {
            file: path.display().to_string(),
            reason: other.to_string(),
        },
    }
}


/// Reads the sampling file once from the opened handle, capped, and validates exactly those bytes.
pub fn load_sampling(path: &Path) -> Result<Sampling, ConfigError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path, &file)?;
    let text = read_text_capped(&mut handle, &file, MAX_SAMPLING_FILE_BYTES)?;
    parse_sampling(&text, &file).map_err(|error| sampling_refusal(path, error))
}


pub fn sampling_loader(path: PathBuf) -> Box<LoaderFn<Sampling>> {
    Box::new(move || load_sampling(&path))
}


/// The audited state of the sampling ratios.
pub fn sampling_state(sampling: &Sampling) -> ConfigState {
    let fixed = [
        ("default_ratio".to_owned(), sampling.default_ratio.to_string()),
        (
            "error_ratio".to_owned(),
            sampling.error_ratio.map_or_else(String::new, |ratio| ratio.to_string()),
        ),
    ];
    fixed
        .into_iter()
        .chain(
            sampling
                .services
                .iter()
                .map(|(service, ratio)| (format!("services.{service}"), ratio.to_string())),
        )
        .collect()
}

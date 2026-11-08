use crate::config::ExportConfig;
use crate::error::ExportError;
use crate::otlp::prepare_otlp;
use core_config::parse::{parse_document, read_file};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::path::{Path, PathBuf};


pub const OTLP_SECTION: &str = "otlp";


/// One line per output section; secrets are never in the settings, only the path of the token file.
pub fn export_state(config: &ExportConfig) -> ConfigState {
    [
        ("syslog", format!("{:?}", config.syslog)),
        ("webhook", format!("{:?}", config.webhook)),
        (OTLP_SECTION, format!("{:?}", config.otlp)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// Refuses a configuration whose OTLP section cannot work: cleartext endpoint, empty batch, unreadable or malformed token.
pub fn check_otlp(config: &ExportConfig) -> Result<(), ExportError> {
    config.otlp.iter().try_for_each(|otlp| prepare_otlp(otlp).map(|_token| ()))
}


pub fn validate_otlp(config: &ExportConfig) -> Result<(), BoxError> {
    check_otlp(config).map_err(BoxError::from)
}


pub fn export_loader(path: PathBuf) -> Box<LoaderFn<ExportConfig>> {
    Box::new(move || read_file(&path).and_then(|text| parse_document(&text, &path.display().to_string())))
}


/// The hook that validates the OTLP section before a swap; readers take the settings from `current_config` on every run.
pub fn otlp_subscriber() -> Subscriber<ExportConfig> {
    Subscriber {
        section: OTLP_SECTION.to_owned(),
        validate: Box::new(validate_otlp),
        apply: Box::new(|_config| tracing::info!("export settings swapped")),
    }
}


/// Loads the first configuration and validates it like a reload would; later changes go through `core_config::reload::reload`.
pub fn open_export_engine(path: &Path, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<ExportConfig>, ExportError> {
    let engine = open_engine(export_loader(path.to_path_buf()), export_state, vec![otlp_subscriber()], audit, context)?;
    check_otlp(&current_config(&engine))?;
    Ok(engine)
}

use crate::config::ExportConfig;
use crate::error::ExportError;
use crate::otlp::read_token;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_file};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine, Subscriber};
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


/// Refuses a new configuration whose OTLP section cannot work: bad endpoint scheme, empty batch, unreadable token file.
pub fn validate_otlp(config: &ExportConfig) -> Result<(), BoxError> {
    config.otlp.iter().try_for_each(|otlp| {
        if !(otlp.endpoint.starts_with("https://") || otlp.endpoint.starts_with("http://")) {
            Err(ExportError::Invalid("endpoint must start with http:// or https://"))
        } else if otlp.batch_size == 0 {
            Err(ExportError::Invalid("batch_size must be at least 1"))
        } else {
            otlp.token_file.iter().try_for_each(|path| read_token(Path::new(path)).map(|_token| ()))
        }
        .map_err(BoxError::from)
    })
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


/// Loads the first configuration; later changes go through `core_config::reload::reload` (watch, signal or call).
pub fn open_export_engine(path: &Path, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<ExportConfig>, ConfigError> {
    open_engine(export_loader(path.to_path_buf()), export_state, vec![otlp_subscriber()], audit, context)
}

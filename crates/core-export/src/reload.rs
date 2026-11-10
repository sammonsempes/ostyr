use crate::config::ExportConfig;
use crate::error::ExportError;
use crate::otlp::{check_transport, prepare_otlp};
use core_config::parse::{parse_document, read_file};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::path::{Path, PathBuf};
use ureq::http::Uri;


pub const OTLP_SECTION: &str = "otlp";


pub const WEBHOOK_SECTION: &str = "webhook";


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


/// Refuses a webhook URL with userinfo, a query string or cleartext http to a remote host (a token in a path segment cannot be detected): the token goes through `SecretRef`, and the URL reaches the audit and the logs.
pub fn check_webhook(config: &ExportConfig) -> Result<(), ExportError> {
    config.webhook.iter().try_for_each(|webhook| {
        let uri = webhook
            .url
            .parse::<Uri>()
            .map_err(|_invalid| ExportError::Invalid("webhook url is not a valid URL"))?;
        if uri.query().is_some() || uri.authority().is_some_and(|authority| authority.as_str().contains('@')) || webhook.url.contains('#') {
            Err(ExportError::Invalid(
                "webhook url must not contain credentials, a query string or a fragment",
            ))
        } else {
            check_transport(&uri)
        }
    })
}


pub fn validate_webhook(config: &ExportConfig) -> Result<(), BoxError> {
    check_webhook(config).map_err(BoxError::from)
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


pub fn webhook_subscriber() -> Subscriber<ExportConfig> {
    Subscriber {
        section: WEBHOOK_SECTION.to_owned(),
        validate: Box::new(validate_webhook),
        apply: Box::new(|_config| tracing::info!("webhook settings swapped")),
    }
}


/// Loads the first configuration and validates it like a reload would; later changes go through `core_config::reload::reload`.
pub fn open_export_engine(path: &Path, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<ExportConfig>, ExportError> {
    let engine = open_engine(
        export_loader(path.to_path_buf()),
        export_state,
        vec![otlp_subscriber(), webhook_subscriber()],
        audit,
        context,
    )?;
    check_otlp(&current_config(&engine))?;
    check_webhook(&current_config(&engine))?;
    Ok(engine)
}

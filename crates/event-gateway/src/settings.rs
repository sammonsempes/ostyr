use crate::error::GatewayError;
use crate::model::{GatewaySettings, LIMIT_COUNT, LIMIT_MS, SECTION};
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, SharedAuditFn};
use siem_ingest::error::SettingsError;
use siem_ingest::nats_settings::{check_nats_url, check_optional_path};
use siem_ingest::settings::{check_order, check_present, check_range};
use std::path::PathBuf;


/// A user and its password file go together, and neither combines with a credentials file.
pub fn check_auth(settings: &GatewaySettings) -> Result<(), SettingsError> {
    let user = settings.nats_user.as_deref();
    let paired = user.is_some() == settings.nats_password_file.is_some();
    let single = user.is_none() || settings.nats_credentials_file.is_none();
    if paired && single {
        user.map_or(Ok(()), |name| check_present("nats_user", name))
    } else {
        Err(SettingsError::Invalid {
            field: "nats_user",
            reason: "needs nats_password_file, and excludes nats_credentials_file",
        })
    }
}


/// Every bound is nonzero and capped; the backoff starts below its ceiling.
pub fn validate_settings(settings: &GatewaySettings) -> Result<(), SettingsError> {
    check_nats_url(&settings.nats_url, settings.nats_tls_first)?;
    check_range("connect_timeout_ms", settings.connect_timeout_ms, LIMIT_MS)?;
    check_range("publish_timeout_ms", settings.publish_timeout_ms, LIMIT_MS)?;
    check_range("ping_interval_ms", settings.ping_interval_ms, LIMIT_MS)?;
    check_range("max_in_flight_batches", settings.max_in_flight_batches as u64, LIMIT_COUNT as u64)?;
    check_range("max_events_per_batch", settings.max_events_per_batch as u64, LIMIT_COUNT as u64)?;
    check_range("backoff_initial_ms", settings.backoff_initial_ms, LIMIT_MS)?;
    check_range("backoff_max_ms", settings.backoff_max_ms, LIMIT_MS)?;
    check_order(
        ("backoff_initial_ms", settings.backoff_initial_ms),
        ("backoff_max_ms", settings.backoff_max_ms),
    )?;
    check_optional_path("nats_ca_file", settings.nats_ca_file.as_ref())?;
    check_optional_path("nats_password_file", settings.nats_password_file.as_ref())?;
    check_optional_path("nats_credentials_file", settings.nats_credentials_file.as_ref())?;
    check_auth(settings)
}


pub fn path_text(path: Option<&PathBuf>) -> String {
    path.map_or_else(String::new, |present| present.display().to_string())
}


/// The reload diff and audit: paths and numbers only, a secret is never a setting value.
pub fn settings_state(settings: &GatewaySettings) -> ConfigState {
    [
        ("nats_url", settings.nats_url.clone()),
        ("nats_tls_first", settings.nats_tls_first.to_string()),
        ("nats_ca_file", path_text(settings.nats_ca_file.as_ref())),
        ("nats_credentials_file", path_text(settings.nats_credentials_file.as_ref())),
        ("nats_user", settings.nats_user.as_ref().map_or_else(String::new, Clone::clone)),
        ("nats_password_file", path_text(settings.nats_password_file.as_ref())),
        ("connect_timeout_ms", settings.connect_timeout_ms.to_string()),
        ("publish_timeout_ms", settings.publish_timeout_ms.to_string()),
        ("ping_interval_ms", settings.ping_interval_ms.to_string()),
        ("max_in_flight_batches", settings.max_in_flight_batches.to_string()),
        ("max_events_per_batch", settings.max_events_per_batch.to_string()),
        ("backoff_initial_ms", settings.backoff_initial_ms.to_string()),
        ("backoff_max_ms", settings.backoff_max_ms.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn validate_subscriber() -> Subscriber<GatewaySettings> {
    Subscriber {
        section: SECTION.to_owned(),
        validate: Box::new(|settings| validate_settings(settings).map_err(BoxError::from)),
        apply: Box::new(|_| ()),
    }
}


/// Fails when the file is unreadable or its first settings are invalid; a later invalid file is refused by `reload` and the old settings stay.
pub fn open_settings(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<GatewaySettings>, GatewayError> {
    let engine = open_engine(
        Box::new(move || load_file(&path)),
        settings_state,
        vec![validate_subscriber()],
        audit,
        context,
    )?;
    validate_settings(&current_config(&engine))?;
    Ok(engine)
}

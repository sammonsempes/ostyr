use crate::error::OncallError;
use crate::limits::{MAX_HOST_LEN, MAX_PATH_LEN, MAX_SECRET_DIRS, MAX_TIMEOUT_MILLIS, MAX_USERNAME_LEN};
use crate::smtp::parse_address;
use crate::validate::{check_between, check_name};
use core_config::parse::{parse_document, read_file};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};


pub const SETTINGS_SECTION: &str = "oncall-transport";


/// How the SMTP connection is secured: `starttls` upgrades a plain connection (refused when the server does not offer it), `implicit` is TLS from the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    Starttls,
    Implicit,
}


/// The mail relay: `from` is the envelope and header sender, `username` goes with the channel's `secret_file` as the password.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    pub from: String,
    pub username: Option<String>,
}


/// `secret_dirs` maps a tenant to its secrets directory; `ca_file` is the only CA trusted when set, else the Mozilla roots.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSettings {
    pub timeout_millis: u64,
    pub ca_file: Option<String>,
    pub secret_dirs: BTreeMap<String, String>,
    #[serde(default)]
    pub smtp: Option<SmtpSettings>,
}


pub fn validate_smtp(smtp: &SmtpSettings) -> Result<(), OncallError> {
    check_between("smtp host", smtp.host.chars().count() as u64, 1, MAX_HOST_LEN)?;
    check_between("smtp port", u64::from(smtp.port), 1, u64::from(u16::MAX))?;
    if smtp.host.chars().any(|character| character.is_control() || character.is_whitespace()) {
        Err(OncallError::InvalidSetting { field: "smtp host" })
    } else {
        parse_address(&smtp.from).map_err(|_error| OncallError::InvalidSetting { field: "smtp from" })?;
        smtp.username.iter().try_for_each(|name| {
            check_between("smtp username", name.chars().count() as u64, 1, MAX_USERNAME_LEN)?;
            if name.chars().any(char::is_control) {
                Err(OncallError::InvalidSetting { field: "smtp username" })
            } else {
                Ok(())
            }
        })
    }
}


pub fn validate_settings(settings: &TransportSettings) -> Result<(), OncallError> {
    check_between("timeout_millis", settings.timeout_millis, 1, MAX_TIMEOUT_MILLIS)?;
    check_between("secret_dirs", settings.secret_dirs.len() as u64, 0, MAX_SECRET_DIRS)?;
    settings
        .ca_file
        .iter()
        .try_for_each(|path| check_between("ca_file", path.chars().count() as u64, 1, MAX_PATH_LEN))?;
    settings.smtp.iter().try_for_each(validate_smtp)?;
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
        ("smtp".to_owned(), format!("{:?}", settings.smtp)),
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

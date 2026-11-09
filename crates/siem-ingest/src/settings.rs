use crate::error::{IngestError, SettingsError};
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, SharedAuditFn};
use serde::{Deserialize, Serialize};
use siem_schema::identifier::validate_identifier;
use std::path::PathBuf;
use ureq::http::Uri;


pub const MODULE: &str = "siem-ingest";


pub const RELOAD_REQUEST_ID: &str = "siem-ingest-reload";


pub const SECTION: &str = "ingest";


pub const MIB: usize = 1_048_576;


pub const DEFAULT_MAX_BATCH_MESSAGES: usize = 1000;


pub const LIMIT_MAX_BATCH_MESSAGES: usize = 100_000;


pub const DEFAULT_MAX_BATCH_BYTES: usize = 4 * MIB;


pub const LIMIT_MAX_BATCH_BYTES: usize = 64 * MIB;


pub const DEFAULT_MAX_BATCH_AGE_SECONDS: u32 = 5;


pub const LIMIT_MAX_BATCH_AGE_SECONDS: u32 = 3600;


pub const DEFAULT_MAX_MESSAGE_BYTES: usize = MIB;


pub const LIMIT_MAX_MESSAGE_BYTES: usize = 16 * MIB;


pub const DEFAULT_MAX_BUFFERED_BYTES: usize = 64 * MIB;


pub const LIMIT_MAX_BUFFERED_BYTES: usize = 1024 * MIB;


pub const DEFAULT_RETRY_ATTEMPTS: u32 = 5;


pub const LIMIT_RETRY_ATTEMPTS: u32 = 20;


pub const DEFAULT_BACKOFF_INITIAL_MS: u64 = 100;


pub const DEFAULT_BACKOFF_MAX_MS: u64 = 10_000;


pub const LIMIT_BACKOFF_MS: u64 = 600_000;


pub const DEFAULT_INSERT_TIMEOUT_MS: u64 = 10_000;


pub const LIMIT_INSERT_TIMEOUT_MS: u64 = 300_000;


pub const DEFAULT_MAX_TENANT_BYTES: usize = 64;


pub const LIMIT_MAX_TENANT_BYTES: usize = 256;


pub const DEFAULT_CLICKHOUSE_URL: &str = "https://127.0.0.1:8443";


pub const DEFAULT_CLICKHOUSE_DATABASE: &str = "ostyr";


pub const DEFAULT_CLICKHOUSE_TABLE: &str = "events";


pub const DEFAULT_CLICKHOUSE_USER: &str = "ostyr_ingest";


pub const DEFAULT_CLICKHOUSE_PASSWORD_FILE: &str = "/etc/ostyr/clickhouse-ingest.password";


pub const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];


/// Every setting is bounded by `validate_settings`; the defaults pass it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IngestSettings {
    pub max_batch_messages: usize,
    pub max_batch_bytes: usize,
    pub max_batch_age_seconds: u32,
    pub max_message_bytes: usize,
    pub max_buffered_bytes: usize,
    pub retry_attempts: u32,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    pub insert_timeout_ms: u64,
    pub max_tenant_bytes: usize,
    pub clickhouse_url: String,
    pub clickhouse_database: String,
    pub clickhouse_table: String,
    pub clickhouse_user: String,
    pub clickhouse_password_file: PathBuf,
    pub clickhouse_ca_file: Option<PathBuf>,
}


impl Default for IngestSettings {
    fn default() -> Self {
        Self {
            max_batch_messages: DEFAULT_MAX_BATCH_MESSAGES,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_batch_age_seconds: DEFAULT_MAX_BATCH_AGE_SECONDS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            backoff_initial_ms: DEFAULT_BACKOFF_INITIAL_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
            insert_timeout_ms: DEFAULT_INSERT_TIMEOUT_MS,
            max_tenant_bytes: DEFAULT_MAX_TENANT_BYTES,
            clickhouse_url: DEFAULT_CLICKHOUSE_URL.to_owned(),
            clickhouse_database: DEFAULT_CLICKHOUSE_DATABASE.to_owned(),
            clickhouse_table: DEFAULT_CLICKHOUSE_TABLE.to_owned(),
            clickhouse_user: DEFAULT_CLICKHOUSE_USER.to_owned(),
            clickhouse_password_file: PathBuf::from(DEFAULT_CLICKHOUSE_PASSWORD_FILE),
            clickhouse_ca_file: None,
        }
    }
}


pub fn check_range(field: &'static str, value: u64, max: u64) -> Result<(), SettingsError> {
    if (1..=max).contains(&value) {
        Ok(())
    } else {
        Err(SettingsError::OutOfRange { field, value, min: 1, max })
    }
}


pub fn check_order(smaller: (&'static str, u64), larger: (&'static str, u64)) -> Result<(), SettingsError> {
    if smaller.1 <= larger.1 {
        Ok(())
    } else {
        Err(SettingsError::Inconsistent {
            smaller: smaller.0,
            smaller_value: smaller.1,
            larger: larger.0,
            larger_value: larger.1,
        })
    }
}


pub fn check_identifier(field: &'static str, value: &str) -> Result<(), SettingsError> {
    validate_identifier(value).map(|_| ()).map_err(|_| SettingsError::Invalid {
        field,
        reason: "not a valid identifier",
    })
}


pub fn check_present(field: &'static str, value: &str) -> Result<(), SettingsError> {
    if value.is_empty() {
        Err(SettingsError::Invalid { field, reason: "empty" })
    } else {
        Ok(())
    }
}


/// Plain HTTP to a loopback host: the only case where the scheme may not be https.
pub fn is_loopback_http(value: &str) -> bool {
    value
        .parse::<Uri>()
        .is_ok_and(|uri| uri.scheme_str() == Some("http") && uri.host().is_some_and(|host| LOOPBACK_HOSTS.contains(&host)))
}


/// Credentials travel in headers: plain HTTP is accepted for loopback only, and the URL carries no userinfo, query or fragment.
pub fn check_url(value: &str) -> Result<(), SettingsError> {
    let parsed = value.parse::<Uri>();
    let scheme_ok = parsed.as_ref().is_ok_and(|uri| uri.scheme_str() == Some("https")) || is_loopback_http(value);
    let bare = !value.contains(['?', '#', '@']);
    if scheme_ok && bare {
        Ok(())
    } else {
        Err(SettingsError::Invalid {
            field: "clickhouse_url",
            reason: "must be https, or http on loopback, without userinfo, query or fragment",
        })
    }
}


/// Every value in `1..=limit`, and a message that can never fit in a batch or in the buffer is refused.
pub fn validate_settings(settings: &IngestSettings) -> Result<(), SettingsError> {
    check_range("max_batch_messages", settings.max_batch_messages as u64, LIMIT_MAX_BATCH_MESSAGES as u64)?;
    check_range("max_batch_bytes", settings.max_batch_bytes as u64, LIMIT_MAX_BATCH_BYTES as u64)?;
    check_range(
        "max_batch_age_seconds",
        u64::from(settings.max_batch_age_seconds),
        u64::from(LIMIT_MAX_BATCH_AGE_SECONDS),
    )?;
    check_range("max_message_bytes", settings.max_message_bytes as u64, LIMIT_MAX_MESSAGE_BYTES as u64)?;
    check_range("max_buffered_bytes", settings.max_buffered_bytes as u64, LIMIT_MAX_BUFFERED_BYTES as u64)?;
    check_range("retry_attempts", u64::from(settings.retry_attempts), u64::from(LIMIT_RETRY_ATTEMPTS))?;
    check_range("backoff_initial_ms", settings.backoff_initial_ms, LIMIT_BACKOFF_MS)?;
    check_range("backoff_max_ms", settings.backoff_max_ms, LIMIT_BACKOFF_MS)?;
    check_order(
        ("max_message_bytes", settings.max_message_bytes as u64),
        ("max_batch_bytes", settings.max_batch_bytes as u64),
    )?;
    check_order(
        ("max_message_bytes", settings.max_message_bytes as u64),
        ("max_buffered_bytes", settings.max_buffered_bytes as u64),
    )?;
    check_order(
        ("max_batch_bytes", settings.max_batch_bytes as u64),
        ("max_buffered_bytes", settings.max_buffered_bytes as u64),
    )?;
    check_range("insert_timeout_ms", settings.insert_timeout_ms, LIMIT_INSERT_TIMEOUT_MS)?;
    check_range("max_tenant_bytes", settings.max_tenant_bytes as u64, LIMIT_MAX_TENANT_BYTES as u64)?;
    check_url(&settings.clickhouse_url)?;
    check_identifier("clickhouse_database", &settings.clickhouse_database)?;
    check_identifier("clickhouse_table", &settings.clickhouse_table)?;
    check_present("clickhouse_user", &settings.clickhouse_user)?;
    check_present("clickhouse_password_file", &settings.clickhouse_password_file.to_string_lossy())?;
    settings
        .clickhouse_ca_file
        .as_ref()
        .map_or(Ok(()), |path| check_present("clickhouse_ca_file", &path.to_string_lossy()))?;
    check_order(
        ("backoff_initial_ms", settings.backoff_initial_ms),
        ("backoff_max_ms", settings.backoff_max_ms),
    )
}


/// One entry per field, so the diff of a reload names what changed.
pub fn settings_state(settings: &IngestSettings) -> ConfigState {
    [
        ("max_batch_messages", settings.max_batch_messages.to_string()),
        ("max_batch_bytes", settings.max_batch_bytes.to_string()),
        ("max_batch_age_seconds", settings.max_batch_age_seconds.to_string()),
        ("max_message_bytes", settings.max_message_bytes.to_string()),
        ("max_buffered_bytes", settings.max_buffered_bytes.to_string()),
        ("retry_attempts", settings.retry_attempts.to_string()),
        ("backoff_initial_ms", settings.backoff_initial_ms.to_string()),
        ("backoff_max_ms", settings.backoff_max_ms.to_string()),
        ("insert_timeout_ms", settings.insert_timeout_ms.to_string()),
        ("max_tenant_bytes", settings.max_tenant_bytes.to_string()),
        ("clickhouse_url", settings.clickhouse_url.clone()),
        ("clickhouse_database", settings.clickhouse_database.clone()),
        ("clickhouse_table", settings.clickhouse_table.clone()),
        ("clickhouse_user", settings.clickhouse_user.clone()),
        ("clickhouse_password_file", settings.clickhouse_password_file.display().to_string()),
        (
            "clickhouse_ca_file",
            settings
                .clickhouse_ca_file
                .as_ref()
                .map_or_else(String::new, |path| path.display().to_string()),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn validate_subscriber() -> Subscriber<IngestSettings> {
    Subscriber {
        section: SECTION.to_owned(),
        validate: Box::new(|settings| validate_settings(settings).map_err(BoxError::from)),
        apply: Box::new(|_| ()),
    }
}


/// Fails when the file is unreadable or its first settings are invalid; a later invalid file is refused by `reload` and the old settings stay.
pub fn open_settings(path: PathBuf, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<IngestSettings>, IngestError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: "all".to_owned(),
        module: MODULE.to_owned(),
        target: path.display().to_string(),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    };
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

use crate::error::{IngestError, SettingsError};
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, SharedAuditFn};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;


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

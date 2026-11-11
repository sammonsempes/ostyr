use crate::limits::{
    DEFAULT_CONFIDENCE, DEFAULT_DICTIONARY_PORT, DEFAULT_DICTIONARY_USER, DEFAULT_TIMEOUT_MS, MAX_CONFIDENCE, MAX_TIMEOUT_MS, MAX_USER_BYTES,
};
use crate::model::{IocType, Tlp};
use crate::store::{quote_identifier, StoreError};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use siem_ingest::error::SettingsError;
use siem_ingest::settings::check_url;
use std::collections::BTreeSet;
use std::path::PathBuf;
use thiserror::Error;


pub const FEEDS_SECTION: &str = "feeds";


pub const EXPORT_KEY: &str = "export.policy";


pub const CLICKHOUSE_KEY: &str = "clickhouse";


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    Stix,
    AbuseChUrlhaus,
    AbuseChThreatfox,
    AbuseChFeodo,
    Crowdsec,
    Csv,
    Json,
}


/// Column names (CSV header) or field names (JSON object) of the generic formats; only `value` is required.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub value: Option<String>,
    pub ioc_type: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub confidence: Option<String>,
    pub malware: Option<String>,
    pub actor: Option<String>,
    pub campaign: Option<String>,
}


pub fn default_confidence() -> u8 {
    DEFAULT_CONFIDENCE
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    pub name: String,
    pub format: FeedFormat,
    pub path: PathBuf,
    pub version: Option<String>,
    #[serde(default)]
    pub mapping: Mapping,
    #[serde(default = "default_confidence")]
    pub default_confidence: u8,
    #[serde(default)]
    pub tlp: Tlp,
    pub ttl_seconds: Option<u32>,
}


/// STIX export policy: nothing above `max_tlp` or below `min_confidence`, and only the listed types (`None` means every type).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPolicy {
    #[serde(default)]
    pub max_tlp: Tlp,
    #[serde(default)]
    pub min_confidence: u8,
    #[serde(default)]
    pub types: Option<Vec<IocType>>,
}


pub fn default_dictionary_port() -> u16 {
    DEFAULT_DICTIONARY_PORT
}


pub fn default_dictionary_user() -> String {
    DEFAULT_DICTIONARY_USER.to_owned()
}


pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}


/// Where the IOCs are loaded: every row carries `tenant`; the password is read from `password_file` at each load and never held here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickhouseConfig {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub table: String,
    pub dictionary: String,
    #[serde(default = "default_dictionary_user")]
    pub dictionary_user: String,
    #[serde(default = "default_dictionary_port")]
    pub dictionary_port: u16,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    pub tenant: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedsFile {
    pub feeds: Vec<FeedConfig>,
    #[serde(default)]
    pub export: ExportPolicy,
    #[serde(default)]
    pub clickhouse: Option<ClickhouseConfig>,
}


#[derive(Debug, Error)]
pub enum ClickhouseError {
    #[error("clickhouse.tenant is not a valid tenant name")]
    Tenant(#[source] PgError),
    #[error("clickhouse identifier refused")]
    Identifier(#[from] StoreError),
    #[error("clickhouse.url refused")]
    Url(#[from] SettingsError),
    #[error("clickhouse.user must be 1 to {MAX_USER_BYTES} printable ASCII characters")]
    User,
    #[error("clickhouse.dictionary_port must not be 0")]
    Port,
    #[error("clickhouse.timeout_ms must be within 1..={MAX_TIMEOUT_MS}")]
    Timeout,
}


#[derive(Debug, Error)]
pub enum FeedsError {
    #[error("feed name `{0}` is empty or used twice")]
    Name(String),
    #[error("feed `{0}`: default confidence above {MAX_CONFIDENCE}")]
    Confidence(String),
    #[error("feed `{0}`: the csv and json formats need `mapping.value`")]
    MappingValue(String),
    #[error("export policy: minimum confidence above {MAX_CONFIDENCE}")]
    ExportConfidence,
    #[error("clickhouse settings invalid")]
    Clickhouse(#[from] ClickhouseError),
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] FeedsError),
}


pub fn needs_mapping(format: FeedFormat) -> bool {
    matches!(format, FeedFormat::Csv | FeedFormat::Json)
}


/// Tenant by core-pg's grammar, URL by siem-ingest's rule, identifiers quoted by the store, user and timeout bounded; nothing is sent here.
pub fn validate_clickhouse(config: &ClickhouseConfig) -> Result<(), ClickhouseError> {
    tenant_scope(&config.tenant).map_err(ClickhouseError::Tenant)?;
    check_url(&config.url)?;
    [&config.database, &config.table, &config.dictionary, &config.dictionary_user]
        .into_iter()
        .try_for_each(|name| quote_identifier(name).map(drop))?;
    let user_ok = !config.user.is_empty() && config.user.len() <= MAX_USER_BYTES && config.user.chars().all(|character| character.is_ascii_graphic());
    if !user_ok {
        Err(ClickhouseError::User)
    } else if config.dictionary_port == 0 {
        Err(ClickhouseError::Port)
    } else if config.timeout_ms == 0 || config.timeout_ms > MAX_TIMEOUT_MS {
        Err(ClickhouseError::Timeout)
    } else {
        Ok(())
    }
}


/// Names are unique and non-empty, confidences (feeds and export minimum) within 0 to 100, generic formats carry a value mapping.
pub fn validate_feeds(config: &FeedsFile) -> Result<(), FeedsError> {
    let mut names = BTreeSet::new();
    let feeds = config.feeds.iter().try_for_each(|feed| {
        if feed.name.is_empty() || !names.insert(feed.name.as_str()) {
            Err(FeedsError::Name(feed.name.clone()))
        } else if feed.default_confidence > MAX_CONFIDENCE {
            Err(FeedsError::Confidence(feed.name.clone()))
        } else if needs_mapping(feed.format) && feed.mapping.value.is_none() {
            Err(FeedsError::MappingValue(feed.name.clone()))
        } else {
            Ok(())
        }
    });
    feeds?;
    if config.export.min_confidence > MAX_CONFIDENCE {
        Err(FeedsError::ExportConfidence)
    } else {
        config
            .clickhouse
            .as_ref()
            .map_or(Ok(()), |clickhouse| validate_clickhouse(clickhouse).map_err(FeedsError::from))
    }
}


pub fn feeds_state(config: &FeedsFile) -> ConfigState {
    config
        .feeds
        .iter()
        .map(|feed| (format!("{FEEDS_SECTION}.{}", feed.name), format!("{feed:?}")))
        .chain([
            (EXPORT_KEY.to_owned(), format!("{:?}", config.export)),
            (CLICKHOUSE_KEY.to_owned(), format!("{:?}", config.clickhouse)),
        ])
        .collect()
}


pub fn feeds_subscriber() -> Subscriber<FeedsFile> {
    Subscriber {
        section: FEEDS_SECTION.to_owned(),
        validate: Box::new(|config| validate_feeds(config).map_err(Into::into)),
        apply: Box::new(|_config| ()),
    }
}


/// Loads and validates the first configuration; later reloads are validated by the subscriber and refused when invalid.
pub fn open_feeds(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<FeedsFile>, OpenError> {
    let engine = open_engine(
        Box::new(move || load_file::<FeedsFile>(&path)),
        feeds_state,
        vec![feeds_subscriber()],
        audit,
        context,
    )?;
    validate_feeds(&current_config(&engine))?;
    Ok(engine)
}

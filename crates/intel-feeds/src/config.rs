use crate::limits::{
    DEFAULT_CONFIDENCE, DEFAULT_DICTIONARY_PORT, DEFAULT_DICTIONARY_USER, DEFAULT_RETRO_MARGIN_SECONDS, DEFAULT_TAXII_MAX_PAGES,
    DEFAULT_TAXII_PAGE_LIMIT, DEFAULT_TIMEOUT_MS, LIMIT_TAXII_MAX_PAGES, LIMIT_TAXII_PAGE_LIMIT, MAX_CONFIDENCE, MAX_RETRO_INTERVAL_SECONDS,
    MAX_RETRO_MARGIN_SECONDS, MAX_RETRO_MATCHES, MAX_RETRO_ROWS_TO_GROUP, MAX_RETRO_ROWS_TO_READ, MAX_RETRO_SECONDS, MAX_RETRO_WINDOW_SECONDS,
    MAX_TAXII_COLLECTION_BYTES, MAX_TIMEOUT_MS, MAX_USER_BYTES, MIN_RETRO_INTERVAL_SECONDS,
};
use crate::model::{IocType, Tlp};
use crate::retro::{validate_retro, RetroError, RetroSettings};
use crate::store::{quote_identifier, StoreError};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use siem_ingest::error::SettingsError;
use siem_ingest::settings::check_url;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use thiserror::Error;


pub const FEEDS_SECTION: &str = "feeds";


pub const EXPORT_KEY: &str = "export.policy";


pub const CLICKHOUSE_KEY: &str = "clickhouse";


pub const RETRO_KEY: &str = "retro";


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
    Misp,
    Taxii21,
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
    #[serde(default)]
    pub path: PathBuf,
    pub version: Option<String>,
    #[serde(default)]
    pub mapping: Mapping,
    #[serde(default = "default_confidence")]
    pub default_confidence: u8,
    #[serde(default)]
    pub tlp: Tlp,
    pub ttl_seconds: Option<u32>,
    #[serde(default)]
    pub taxii: Option<TaxiiConfig>,
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


pub fn default_taxii_max_pages() -> u32 {
    DEFAULT_TAXII_MAX_PAGES
}


pub fn default_taxii_page_limit() -> u32 {
    DEFAULT_TAXII_PAGE_LIMIT
}


/// One TAXII 2.1 collection: the password is read from `password_file` at each poll and never held here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxiiConfig {
    pub api_root: String,
    pub collection: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_taxii_max_pages")]
    pub max_pages: u32,
    #[serde(default = "default_taxii_page_limit")]
    pub page_limit: u32,
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


pub fn default_retro_max_matches() -> usize {
    MAX_RETRO_MATCHES
}


pub fn default_retro_seconds() -> u32 {
    MAX_RETRO_SECONDS
}


pub fn default_retro_rows_to_read() -> u64 {
    MAX_RETRO_ROWS_TO_READ
}


pub fn default_retro_rows_to_group() -> u64 {
    MAX_RETRO_ROWS_TO_GROUP
}


pub fn default_retro_margin() -> u64 {
    DEFAULT_RETRO_MARGIN_SECONDS
}


/// The scheduled retro match: `reader` is its own ClickHouse identity (never the loader's), the window ends now and starts `window_seconds` before.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetroSection {
    pub reader: ClickhouseConfig,
    pub events_database: String,
    pub events_table: String,
    #[serde(default = "default_retro_max_matches")]
    pub max_matches: usize,
    #[serde(default = "default_retro_seconds")]
    pub max_execution_seconds: u32,
    #[serde(default = "default_retro_rows_to_read")]
    pub max_rows_to_read: u64,
    #[serde(default = "default_retro_rows_to_group")]
    pub max_rows_to_group_by: u64,
    pub interval_seconds: u64,
    pub window_seconds: u64,
    #[serde(default = "default_retro_margin")]
    pub margin_seconds: u64,
    pub pg_settings: PathBuf,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedsFile {
    pub feeds: Vec<FeedConfig>,
    #[serde(default)]
    pub export: ExportPolicy,
    #[serde(default)]
    pub clickhouse: Option<ClickhouseConfig>,
    #[serde(default)]
    pub retro: Option<RetroSection>,
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
pub enum RetroSectionError {
    #[error("retro reader or budget refused")]
    Settings(#[from] RetroError),
    #[error("retro.interval_seconds must be within {MIN_RETRO_INTERVAL_SECONDS}..={MAX_RETRO_INTERVAL_SECONDS}")]
    Interval,
    #[error("retro.margin_seconds must be within 1..={MAX_RETRO_MARGIN_SECONDS}")]
    Margin,
    #[error("retro.window_seconds must cover interval_seconds plus margin_seconds and stay within {MAX_RETRO_WINDOW_SECONDS}")]
    Window,
    #[error("retro.pg_settings must name a file")]
    PgSettings,
}


#[derive(Debug, Error)]
pub enum TaxiiConfigError {
    #[error("a taxii21 feed needs a `taxii` section, and no other format takes one")]
    Section,
    #[error("taxii.api_root refused")]
    ApiRoot(#[from] SettingsError),
    #[error("taxii.collection must be 1 to {MAX_TAXII_COLLECTION_BYTES} characters of [A-Za-z0-9-]")]
    Collection,
    #[error("taxii.user must be 1 to {MAX_USER_BYTES} printable ASCII characters without `:`")]
    User,
    #[error("taxii.timeout_ms must be within 1..={MAX_TIMEOUT_MS}")]
    Timeout,
    #[error("taxii.max_pages must be within 1..={LIMIT_TAXII_MAX_PAGES}")]
    Pages,
    #[error("taxii.page_limit must be within 1..={LIMIT_TAXII_PAGE_LIMIT}")]
    PageLimit,
}


#[derive(Debug, Error)]
pub enum FeedsError {
    #[error("feed `{0}`: {1}")]
    Taxii(String, #[source] TaxiiConfigError),
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
    #[error("retro section invalid")]
    Retro(#[from] RetroSectionError),
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] FeedsError),
}


pub fn collection_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TAXII_COLLECTION_BYTES
        && name.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
}


/// URL by siem-ingest's rule, collection an ASCII allowlist, user printable without `:` (Basic auth), counts and timeout within their limits.
pub fn validate_taxii(config: &TaxiiConfig) -> Result<(), TaxiiConfigError> {
    check_url(&config.api_root)?;
    let user_ok = !config.user.is_empty()
        && config.user.len() <= MAX_USER_BYTES
        && config.user.chars().all(|character| character.is_ascii_graphic() && character != ':');
    if !collection_ok(&config.collection) {
        Err(TaxiiConfigError::Collection)
    } else if !user_ok {
        Err(TaxiiConfigError::User)
    } else if config.timeout_ms == 0 || config.timeout_ms > MAX_TIMEOUT_MS {
        Err(TaxiiConfigError::Timeout)
    } else if config.max_pages == 0 || config.max_pages > LIMIT_TAXII_MAX_PAGES {
        Err(TaxiiConfigError::Pages)
    } else if config.page_limit == 0 || config.page_limit > LIMIT_TAXII_PAGE_LIMIT {
        Err(TaxiiConfigError::PageLimit)
    } else {
        Ok(())
    }
}


/// A taxii21 feed carries a valid `taxii` section; any other feed carries none.
pub fn validate_feed_taxii(feed: &FeedConfig) -> Result<(), TaxiiConfigError> {
    match (feed.format == FeedFormat::Taxii21, feed.taxii.as_ref()) {
        (true, Some(taxii)) => validate_taxii(taxii),
        (false, None) => Ok(()),
        (true, None) | (false, Some(_)) => Err(TaxiiConfigError::Section),
    }
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


pub fn retro_settings(section: &RetroSection) -> RetroSettings {
    RetroSettings {
        reader: section.reader.clone(),
        events_database: section.events_database.clone(),
        events_table: section.events_table.clone(),
        max_matches: section.max_matches,
        max_execution_seconds: section.max_execution_seconds,
        max_rows_to_read: section.max_rows_to_read,
        max_rows_to_group_by: section.max_rows_to_group_by,
    }
}


/// The reader and budget by `validate_retro`; the interval and margin bounded; the window covers the interval plus the ingest-lag margin; nothing is sent here.
pub fn validate_retro_section(section: &RetroSection) -> Result<(), RetroSectionError> {
    validate_retro(&retro_settings(section))?;
    let covered = section.interval_seconds.saturating_add(section.margin_seconds);
    if !(MIN_RETRO_INTERVAL_SECONDS..=MAX_RETRO_INTERVAL_SECONDS).contains(&section.interval_seconds) {
        Err(RetroSectionError::Interval)
    } else if section.margin_seconds == 0 || section.margin_seconds > MAX_RETRO_MARGIN_SECONDS {
        Err(RetroSectionError::Margin)
    } else if section.window_seconds < covered || section.window_seconds > MAX_RETRO_WINDOW_SECONDS {
        Err(RetroSectionError::Window)
    } else if section.pg_settings.as_os_str().is_empty() {
        Err(RetroSectionError::PgSettings)
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
            validate_feed_taxii(feed).map_err(|error| FeedsError::Taxii(feed.name.clone(), error))
        }
    });
    feeds?;
    if config.export.min_confidence > MAX_CONFIDENCE {
        Err(FeedsError::ExportConfidence)
    } else {
        config
            .clickhouse
            .as_ref()
            .map_or(Ok(()), |clickhouse| validate_clickhouse(clickhouse).map_err(FeedsError::from))?;
        config
            .retro
            .as_ref()
            .map_or(Ok(()), |section| validate_retro_section(section).map_err(FeedsError::from))
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
            (RETRO_KEY.to_owned(), format!("{:?}", config.retro)),
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


/// `retro.pg_settings` is read at start only: the first load fixes it (absent included) and a later load that differs is refused with the old file kept.
pub fn check_pg_baseline(baseline: &OnceLock<Option<PathBuf>>, config: &FeedsFile) -> Result<(), ConfigError> {
    let current = config.retro.as_ref().map(|section| section.pg_settings.clone());
    if *baseline.get_or_init(|| current.clone()) == current {
        Ok(())
    } else {
        Err(ConfigError::WatchedFile {
            file: format!("{RETRO_KEY}.pg_settings"),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
    }
}


/// The loader of the engine: the file is parsed once per load and that one parse is checked against the start-only baseline.
pub fn feeds_loader(path: PathBuf) -> Box<LoaderFn<FeedsFile>> {
    let baseline = OnceLock::new();
    Box::new(move || {
        let config = load_file::<FeedsFile>(&path)?;
        check_pg_baseline(&baseline, &config)?;
        Ok(config)
    })
}


/// Loads and validates the first configuration; later reloads are validated by the subscriber and refused when invalid.
pub fn open_feeds(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<FeedsFile>, OpenError> {
    let engine = open_engine(feeds_loader(path), feeds_state, vec![feeds_subscriber()], audit, context)?;
    validate_feeds(&current_config(&engine))?;
    Ok(engine)
}

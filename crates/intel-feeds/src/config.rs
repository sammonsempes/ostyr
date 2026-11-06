use crate::limits::{DEFAULT_CONFIDENCE, MAX_CONFIDENCE};
use crate::model::{IocType, Tlp};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use thiserror::Error;


pub const FEEDS_SECTION: &str = "feeds";


pub const EXPORT_KEY: &str = "export.policy";


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


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedsFile {
    pub feeds: Vec<FeedConfig>,
    #[serde(default)]
    pub export: ExportPolicy,
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
        Ok(())
    }
}


pub fn feeds_state(config: &FeedsFile) -> ConfigState {
    config
        .feeds
        .iter()
        .map(|feed| (format!("{FEEDS_SECTION}.{}", feed.name), format!("{feed:?}")))
        .chain(std::iter::once((EXPORT_KEY.to_owned(), format!("{:?}", config.export))))
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

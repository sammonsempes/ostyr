use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Cidr,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
}


/// Declared from the least to the most restrictive: merging keeps the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    Clear,
    Green,
    #[default]
    Amber,
    AmberStrict,
    Red,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Canonical {
    pub ioc_type: IocType,
    pub value: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub feed: String,
    pub version: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tags {
    pub malware: Vec<String>,
    pub actor: Vec<String>,
    pub campaign: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub sources: Vec<Source>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
    pub confidence: u8,
    pub tlp: Tlp,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub tags: Tags,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawEntry {
    pub value: String,
    pub type_name: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub confidence: Option<String>,
    pub malware: Option<String>,
    pub actor: Option<String>,
    pub campaign: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkipSample {
    pub line: u64,
    pub reason: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct FeedSummary {
    pub feed: String,
    pub parsed: u64,
    pub skipped: BTreeMap<&'static str, u64>,
    pub unsupported: u64,
    pub expired: u64,
    pub duplicates: u64,
    pub samples: Vec<SkipSample>,
    pub failed: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Collector {
    pub iocs: Vec<Ioc>,
    pub summary: FeedSummary,
}

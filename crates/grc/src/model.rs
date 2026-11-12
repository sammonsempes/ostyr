use serde::Deserialize;
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Technical,
    Organisational,
}


#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Threshold {
    AtLeast(f64),
    AtMost(f64),
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub kind: ControlKind,
    pub indicator: Option<String>,
    pub max_age_hours: Option<u32>,
    pub compliant: Option<Threshold>,
    pub partial: Option<Threshold>,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Framework {
    pub framework: String,
    pub version: u32,
    pub controls: Vec<Control>,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndicatorValue {
    pub tenant: String,
    pub name: String,
    pub value: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEvidence {
    pub tenant: String,
    pub control: String,
    pub owner: String,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub review_until: OffsetDateTime,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotAssessable,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub indicator: String,
    pub value: f64,
    pub observed_at: i64,
    pub source: String,
    pub sha256: String,
}


#[derive(Debug, Clone, PartialEq)]
pub struct ControlResult {
    pub control: String,
    pub status: ControlStatus,
    pub evidence: Option<Evidence>,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub tenant: String,
    pub framework: String,
    pub version: u32,
    pub results: Vec<ControlResult>,
}

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use chrono_tz::Tz;
use serde::Deserialize;
use std::collections::BTreeMap;


/// A rotation: `participants` take turns every `period_days`, the first hand-off is `start` in the schedule's local time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub name: String,
    pub participants: Vec<String>,
    pub start: NaiveDateTime,
    pub period_days: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub person: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolidayRule {
    Nobody,
    Cover(Vec<String>),
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holiday {
    pub date: NaiveDate,
    pub rule: HolidayRule,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub name: String,
    pub time_zone: Tz,
    pub layers: Vec<Layer>,
    #[serde(default)]
    pub overrides: Vec<Override>,
    #[serde(default)]
    pub holidays: Vec<Holiday>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Person(String),
    Schedule(String),
}


/// `delay_seconds` is counted from the previous level (from the opening for the first one).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Level {
    pub delay_seconds: u32,
    pub targets: Vec<Target>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub levels: Vec<Level>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationState {
    Acknowledged,
    Waiting,
    Level(usize),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Equal,
    Regex,
}


/// A regex matcher is anchored: it must match the whole label value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    pub label: String,
    pub kind: MatchKind,
    pub value: String,
}


/// `expires_at` is required: a silence without an expiry is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Silence {
    pub name: String,
    pub matchers: Vec<Matcher>,
    pub author: String,
    pub reason: String,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SilenceFile {
    pub silences: Vec<Silence>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub name: String,
    pub assets: Vec<String>,
    pub author: String,
    pub reason: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowFile {
    pub windows: Vec<Window>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub fingerprint: String,
    pub labels: BTreeMap<String, String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertGroup {
    pub labels: BTreeMap<String, String>,
    pub alerts: Vec<Alert>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Smtp,
    Webhook,
    Ntfy,
    Teams,
    Slack,
    Sms,
}


/// `secret_file` is the path of a file holding the secret; the secret itself is never a field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub name: String,
    pub tenant: String,
    pub kind: ChannelKind,
    pub target: String,
    pub secret_file: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertNotice {
    pub tenant: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub subject: String,
    pub body: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyFailure {
    pub channel: String,
    pub reason: String,
}

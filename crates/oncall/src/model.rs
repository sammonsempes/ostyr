use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use chrono_tz::Tz;
use serde::Deserialize;


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

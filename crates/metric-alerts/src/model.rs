use crate::types::Labels;
use serde::Deserialize;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Above,
    Below,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


/// `clear` is the level a firing alert must cross back over to resolve; absent, it equals `threshold`. Durations are in seconds.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Threshold {
        direction: Direction,
        threshold: f64,
        clear: Option<f64>,
    },
    Rate {
        direction: Direction,
        threshold: f64,
        clear: Option<f64>,
    },
    Absence {
        interval: u64,
    },
    Forecast {
        window: u64,
        capacity: Capacity,
        horizon: u64,
        min_confidence: f64,
        min_points: usize,
    },
}


/// Where the capacity a forecast projects towards comes from: a constant, or the latest value of another metric.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capacity {
    Fixed { value: f64 },
    Metric { name: String },
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub metric: String,
    #[serde(default)]
    pub selector: Labels,
    pub condition: Condition,
    #[serde(rename = "for", default)]
    pub hold_for: u64,
    pub close_after: u64,
    pub severity: Severity,
    #[serde(default)]
    pub labels: Labels,
    pub runbook: String,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub rules: Vec<Rule>,
}

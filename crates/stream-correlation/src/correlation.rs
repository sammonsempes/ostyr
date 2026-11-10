use crate::error::CorrelationError;
use crate::field::MILLIS_PER_SECOND;
use crate::level::Level;
use serde::Deserialize;
use serde_json::Value;
use sigma_sql::rule::METADATA_KEYS;
use std::collections::BTreeMap;


pub const SECONDS_PER_MINUTE: i64 = 60;


pub const MINUTES_PER_HOUR: i64 = 60;


pub const HOURS_PER_DAY: i64 = 24;


pub const DAYS_PER_WEEK: i64 = 7;


pub const FIELD_KEY: &str = "field";


pub const EXTRA_KEYS: &[&str] = &["status", "tags"];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}


pub const COMPARISONS: &[(&str, Comparison)] = &[
    ("gt", Comparison::Gt),
    ("gte", Comparison::Gte),
    ("lt", Comparison::Lt),
    ("lte", Comparison::Lte),
    ("eq", Comparison::Eq),
];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub comparison: Comparison,
    pub value: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    EventCount(Threshold),
    ValueCount { threshold: Threshold, field: String },
    Temporal,
    TemporalOrdered,
}


/// A parsed correlation rule; `rules` holds indices into the rule set's base rules, in the order the rule lists them.
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub title: String,
    pub level: Level,
    pub kind: Kind,
    pub rules: Vec<usize>,
    pub group_by: Vec<String>,
    pub timespan_ms: i64,
    pub generate: bool,
    pub source: String,
    pub fingerprint: String,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCorrelation {
    #[serde(rename = "type")]
    pub kind: String,
    pub rules: Vec<String>,
    #[serde(rename = "group-by", default)]
    pub group_by: Vec<String>,
    pub timespan: String,
    pub condition: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub generate: bool,
}


#[derive(Debug, Deserialize)]
pub struct RawDocument {
    pub title: Option<String>,
    pub level: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub correlation: RawCorrelation,
    #[serde(flatten)]
    pub rest: BTreeMap<String, Value>,
}


pub fn unsupported(rule: &str, construct: String) -> CorrelationError {
    CorrelationError::Unsupported {
        rule: rule.to_string(),
        construct,
    }
}


pub fn invalid(rule: &str, field: &str, reason: String) -> CorrelationError {
    CorrelationError::Invalid {
        rule: rule.to_string(),
        field: field.to_string(),
        reason,
    }
}


const UNITS: &[(&str, i64)] = &[
    ("s", MILLIS_PER_SECOND),
    ("m", MILLIS_PER_SECOND * SECONDS_PER_MINUTE),
    ("h", MILLIS_PER_SECOND * SECONDS_PER_MINUTE * MINUTES_PER_HOUR),
    ("d", MILLIS_PER_SECOND * SECONDS_PER_MINUTE * MINUTES_PER_HOUR * HOURS_PER_DAY),
    (
        "w",
        MILLIS_PER_SECOND * SECONDS_PER_MINUTE * MINUTES_PER_HOUR * HOURS_PER_DAY * DAYS_PER_WEEK,
    ),
];


/// Parses `<positive integer><s|m|h|d|w>` into milliseconds.
pub fn parse_timespan(rule: &str, text: &str) -> Result<i64, CorrelationError> {
    let (digits, unit) = UNITS
        .iter()
        .find_map(|(suffix, millis)| text.strip_suffix(suffix).map(|digits| (digits, *millis)))
        .ok_or_else(|| invalid(rule, "timespan", "does not end in s, m, h, d or w".to_string()))?;
    let count: i64 = digits
        .parse()
        .map_err(|_| invalid(rule, "timespan", "the count is not an integer".to_string()))?;
    count
        .checked_mul(unit)
        .filter(|millis| *millis > 0)
        .ok_or_else(|| invalid(rule, "timespan", "is not a positive duration".to_string()))
}


fn comparison_for(rule: &str, key: &str, value: &Value) -> Result<Threshold, CorrelationError> {
    let comparison = COMPARISONS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, comparison)| *comparison)
        .ok_or_else(|| unsupported(rule, "condition key".to_string()))?;
    let count = value
        .as_u64()
        .ok_or_else(|| invalid(rule, "condition", "a threshold needs a non-negative integer".to_string()))?;
    Ok(Threshold { comparison, value: count })
}


fn parse_threshold(rule: &str, condition: &BTreeMap<String, Value>) -> Result<Threshold, CorrelationError> {
    let thresholds = condition
        .iter()
        .filter(|(key, _)| key.as_str() != FIELD_KEY)
        .map(|(key, value)| comparison_for(rule, key, value))
        .collect::<Result<Vec<_>, _>>()?;
    match thresholds.as_slice() {
        [only] => Ok(*only),
        _ => Err(invalid(
            rule,
            "condition",
            "exactly one of gt, gte, lt, lte or eq is required".to_string(),
        )),
    }
}


fn count_kind(rule: &str, correlation: &RawCorrelation, value_count: bool) -> Result<Kind, CorrelationError> {
    let condition = correlation
        .condition
        .as_ref()
        .ok_or_else(|| invalid(rule, "condition", "a count rule needs a condition".to_string()))?;
    let threshold = parse_threshold(rule, condition)?;
    match (value_count, condition.get(FIELD_KEY)) {
        (true, Some(Value::String(field))) => Ok(Kind::ValueCount {
            threshold,
            field: field.clone(),
        }),
        (true, _) => Err(invalid(rule, "condition", "value_count needs a string field".to_string())),
        (false, Some(_)) => Err(unsupported(rule, "field in an event_count condition".to_string())),
        (false, None) => Ok(Kind::EventCount(threshold)),
    }
}


fn temporal_kind(rule: &str, correlation: &RawCorrelation, kind: Kind) -> Result<Kind, CorrelationError> {
    match correlation.condition {
        Some(_) => Err(unsupported(rule, "condition on a temporal rule".to_string())),
        None => Ok(kind),
    }
}


pub fn parse_kind(rule: &str, correlation: &RawCorrelation) -> Result<Kind, CorrelationError> {
    match correlation.kind.as_str() {
        "event_count" => count_kind(rule, correlation, false),
        "value_count" => count_kind(rule, correlation, true),
        "temporal" => temporal_kind(rule, correlation, Kind::Temporal),
        "temporal_ordered" => temporal_kind(rule, correlation, Kind::TemporalOrdered),
        _ => Err(unsupported(rule, "correlation type".to_string())),
    }
}


/// Refuses any top-level key that is neither a rule field nor a metadata key.
pub fn check_keys(rule: &str, document: &RawDocument) -> Result<(), CorrelationError> {
    document
        .rest
        .keys()
        .filter(|key| !METADATA_KEYS.contains(&key.as_str()) && !EXTRA_KEYS.contains(&key.as_str()))
        .try_for_each(|_| Err(unsupported(rule, "top-level key".to_string())))
}

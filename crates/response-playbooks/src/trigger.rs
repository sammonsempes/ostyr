use crate::types::ParamMap;
use serde_json::Value;


pub const ALERT_PREFIX: &str = "alert.";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    AtLeast,
    AtMost,
    Above,
    Below,
}


pub const COMPARATORS: [(&str, Comparison); 4] = [
    (">=", Comparison::AtLeast),
    ("<=", Comparison::AtMost),
    (">", Comparison::Above),
    ("<", Comparison::Below),
];


pub fn lookup<'a>(alert: &'a Value, key: &str) -> Option<&'a Value> {
    key.strip_prefix(ALERT_PREFIX)
        .and_then(|path| alert.pointer(&format!("/{}", path.replace('.', "/"))))
}


pub fn parse_comparison(text: &str) -> Option<(Comparison, f64)> {
    COMPARATORS
        .iter()
        .find_map(|(symbol, comparison)| text.trim().strip_prefix(symbol).map(|rest| (*comparison, rest)))
        .and_then(|(comparison, rest)| rest.trim().parse().ok().map(|threshold| (comparison, threshold)))
}


pub fn compare(comparison: Comparison, actual: f64, threshold: f64) -> bool {
    match comparison {
        Comparison::AtLeast => actual >= threshold,
        Comparison::AtMost => actual <= threshold,
        Comparison::Above => actual > threshold,
        Comparison::Below => actual < threshold,
    }
}


/// A string such as `">= 0.8"` is a numeric comparison, any other expected value must be equal.
pub fn satisfied(expected: &Value, actual: &Value) -> bool {
    expected.as_str().and_then(parse_comparison).map_or_else(
        || expected == actual,
        |(comparison, threshold)| actual.as_f64().is_some_and(|number| compare(comparison, number, threshold)),
    )
}


/// One line per trigger key whose alert field is missing or does not satisfy the expected value.
pub fn mismatches(trigger: &ParamMap, alert: &Value) -> Vec<String> {
    trigger
        .iter()
        .filter(|(key, expected)| !lookup(alert, key).is_some_and(|actual| satisfied(expected, actual)))
        .map(|(key, expected)| format!("{key} expected {expected}"))
        .collect()
}

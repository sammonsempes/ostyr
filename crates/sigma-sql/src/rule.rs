use crate::error::SigmaError;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}


#[derive(Debug, Deserialize)]
struct RawRule {
    title: String,
    id: Option<String>,
    status: Option<String>,
    level: Option<String>,
    logsource: LogSource,
    detection: Map<String, Value>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}


#[derive(Debug)]
pub struct Rule {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub selections: BTreeMap<String, Value>,
    pub condition: String,
}


pub const CONDITION_KEY: &str = "condition";


pub const METADATA_KEYS: &[&str] = &[
    "description",
    "author",
    "date",
    "modified",
    "references",
    "falsepositives",
    "fields",
    "related",
    "license",
    "taxonomy",
    "scope",
    "name",
];


fn unsupported(rule: &str, construct: &str) -> SigmaError {
    SigmaError::Unsupported {
        rule: rule.to_string(),
        construct: construct.to_string(),
    }
}


fn condition_text(title: &str, detection: &mut Map<String, Value>) -> Result<String, SigmaError> {
    match detection.remove(CONDITION_KEY) {
        Some(Value::String(text)) if text.contains('|') => Err(unsupported(title, "aggregation in condition")),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(unsupported(title, "condition that is not a single string")),
        None => Err(SigmaError::BadCondition {
            rule: title.to_string(),
            reason: "detection has no condition".to_string(),
        }),
    }
}


/// Parses one single-document Sigma rule; any key or construct outside the supported set is a typed error.
pub fn parse_rule(text: &str) -> Result<Rule, SigmaError> {
    let raw: RawRule = serde_saphyr::from_str(text)?;
    let title = raw.title;
    raw.rest
        .keys()
        .filter(|key| !METADATA_KEYS.contains(&key.as_str()))
        .try_for_each(|key| Err(unsupported(&title, &format!("top-level key {key}"))))?;
    let mut detection = raw.detection;
    let condition = condition_text(&title, &mut detection)?;
    if detection.contains_key("timeframe") {
        Err(unsupported(&title, "timeframe"))
    } else {
        Ok(Rule {
            title,
            id: raw.id,
            status: raw.status,
            level: raw.level,
            tags: raw.tags,
            logsource: raw.logsource,
            selections: detection.into_iter().collect(),
            condition,
        })
    }
}

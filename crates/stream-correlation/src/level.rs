use crate::correlation::invalid;
use crate::error::CorrelationError;
use serde::{Deserialize, Serialize};


pub const MAX_TITLE_CHARS: usize = 200;


pub const DEFAULT_LEVEL: Level = Level::Medium;


/// Sigma severity, ordered from the least to the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}


pub const LEVELS: &[(&str, Level)] = &[
    ("informational", Level::Informational),
    ("low", Level::Low),
    ("medium", Level::Medium),
    ("high", Level::High),
    ("critical", Level::Critical),
];


/// Parses a Sigma `level`; a missing one is `None`, an unknown one is refused without echoing it.
pub fn parse_level(rule: &str, text: Option<&str>) -> Result<Option<Level>, CorrelationError> {
    text.map(|word| {
        LEVELS
            .iter()
            .find(|(name, _)| *name == word)
            .map(|(_, level)| *level)
            .ok_or_else(|| invalid(rule, "level", "not one of informational, low, medium, high or critical".to_string()))
    })
    .transpose()
}


/// Refuses a title that is empty, too long or holds a control character; the refusal names the rule by `rule`, never by the title.
pub fn check_title(rule: &str, title: &str) -> Result<(), CorrelationError> {
    if title.trim().is_empty() {
        Err(invalid(rule, "title", "empty".to_string()))
    } else if title.chars().count() > MAX_TITLE_CHARS {
        Err(invalid(rule, "title", "too long".to_string()))
    } else if title.chars().any(char::is_control) {
        Err(invalid(rule, "title", "holds a control character".to_string()))
    } else {
        Ok(())
    }
}


/// The most severe of the levels, `DEFAULT_LEVEL` when there are none.
pub fn highest(levels: impl Iterator<Item = Level>) -> Level {
    levels.max().unwrap_or(DEFAULT_LEVEL)
}

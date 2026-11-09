use crate::error::RuleError;
use crate::model::{Capacity, Condition, Direction, Rule, RuleFile};
use crate::types::Labels;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_RULES: usize = 1000;


pub const MAX_ID_LEN: usize = 128;


pub const MAX_METRIC_LEN: usize = 256;


pub const MAX_LABELS: usize = 16;


pub const MAX_LABEL_LEN: usize = 128;


pub const MAX_RUNBOOK_LEN: usize = 512;


pub const MIN_CONFIDENCE: f64 = 0.0;


pub const MAX_CONFIDENCE: f64 = 1.0;


pub const MIN_FIT_POINTS: usize = 2;


pub const MAX_FIT_POINTS: usize = 100_000;


pub const MAX_DURATION_SECONDS: u64 = 2_592_000;


/// Reads at most `MAX_FILE_BYTES` from `reader`, parses strictly and validates bounds; `file` only labels errors.
pub fn parse_rules(reader: &mut dyn Read, file: &str) -> Result<RuleFile, RuleError> {
    let text = read_text(&mut Read::take(reader, MAX_FILE_BYTES + 1), file)?;
    (text.len() as u64 <= MAX_FILE_BYTES)
        .then_some(())
        .ok_or_else(|| RuleError::FileTooLarge { file: file.to_string() })?;
    let rule_file = parse_document::<RuleFile>(&text, file)?;
    validate_rule_file(&rule_file, file)?;
    Ok(rule_file)
}


pub fn load_rules(path: &Path) -> Result<RuleFile, RuleError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_rules(&mut handle, &file)
}


pub fn validate_rule_file(rule_file: &RuleFile, file: &str) -> Result<(), RuleError> {
    (rule_file.rules.len() <= MAX_RULES)
        .then_some(())
        .ok_or_else(|| RuleError::TooManyRules {
            file: file.to_string(),
            count: rule_file.rules.len(),
        })?;
    rule_file
        .rules
        .iter()
        .try_fold(BTreeSet::new(), |mut seen, rule| {
            validate_rule(file, rule)?;
            seen.insert(rule.id.as_str()).then_some(seen).ok_or_else(|| RuleError::DuplicateId {
                file: file.to_string(),
                rule: rule.id.clone(),
            })
        })
        .map(|_| ())
}


pub fn validate_rule(file: &str, rule: &Rule) -> Result<(), RuleError> {
    let checks = [
        ("id", bounded(&rule.id, MAX_ID_LEN)),
        ("metric", bounded(&rule.metric, MAX_METRIC_LEN)),
        ("selector", labels_ok(&rule.selector)),
        ("labels", labels_ok(&rule.labels)),
        ("runbook", rule.runbook.len() <= MAX_RUNBOOK_LEN),
        ("for", rule.hold_for <= MAX_DURATION_SECONDS),
        ("close_after", rule.close_after <= MAX_DURATION_SECONDS),
        ("condition", condition_ok(&rule.condition)),
    ];
    checks.iter().find(|check| !check.1).map_or(Ok(()), |check| {
        Err(RuleError::Invalid {
            file: file.to_string(),
            rule: rule.id.clone(),
            field: check.0,
        })
    })
}


pub fn bounded(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
}


pub fn labels_ok(labels: &Labels) -> bool {
    labels.len() <= MAX_LABELS
        && labels
            .iter()
            .all(|(key, value)| bounded(key, MAX_LABEL_LEN) && bounded(value, MAX_LABEL_LEN))
}


pub fn condition_ok(condition: &Condition) -> bool {
    match condition {
        Condition::Threshold { direction, threshold, clear } | Condition::Rate { direction, threshold, clear } => {
            threshold.is_finite() && clear.is_none_or(|level| level.is_finite() && clear_side_ok(*direction, level, *threshold))
        }
        Condition::Absence { interval } => (1..=MAX_DURATION_SECONDS).contains(interval),
        Condition::Forecast {
            window,
            capacity,
            horizon,
            min_confidence,
            min_points,
        } => {
            (1..=MAX_DURATION_SECONDS).contains(window)
                && (1..=MAX_DURATION_SECONDS).contains(horizon)
                && (MIN_CONFIDENCE..=MAX_CONFIDENCE).contains(min_confidence)
                && (MIN_FIT_POINTS..=MAX_FIT_POINTS).contains(min_points)
                && capacity_ok(capacity)
        }
    }
}


pub fn capacity_ok(capacity: &Capacity) -> bool {
    match capacity {
        Capacity::Fixed { value } => value.is_finite(),
        Capacity::Metric { name } => bounded(name, MAX_METRIC_LEN),
    }
}


pub fn clear_side_ok(direction: Direction, clear: f64, threshold: f64) -> bool {
    match direction {
        Direction::Above => clear <= threshold,
        Direction::Below => clear >= threshold,
    }
}

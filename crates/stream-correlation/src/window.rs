use crate::correlation::{Comparison, CorrelationRule, Kind, Threshold};
use crate::field::GROUP_SEPARATOR;
use crate::level::Level;
use crate::types::GroupMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_GROUPS_PER_RULE: usize = 10_000;


pub const MAX_EVENTS_PER_GROUP: usize = 1_000;


pub const LATENESS_MS: i64 = 60_000;


/// One event kept in a window; `rules` are the positions in the correlation rule's list that the event matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    pub timestamp_ms: i64,
    pub event_id: String,
    pub rules: Vec<usize>,
    pub value: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleState {
    pub fingerprint: String,
    pub groups: GroupMap,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub processed: u64,
    pub invalid: u64,
    pub late: u64,
    pub dropped_events: u64,
    pub dropped_groups: u64,
    pub alerts: u64,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub watermark_ms: Option<i64>,
    pub counters: Counters,
    pub rules: BTreeMap<String, RuleState>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub rule_id: String,
    pub rule_title: String,
    pub level: Level,
    pub group: BTreeMap<String, String>,
    pub first_ms: i64,
    pub last_ms: i64,
    pub event_ids: Vec<String>,
}


pub fn compare(threshold: &Threshold, count: u64) -> bool {
    match threshold.comparison {
        Comparison::Gt => count > threshold.value,
        Comparison::Gte => count >= threshold.value,
        Comparison::Lt => count < threshold.value,
        Comparison::Lte => count <= threshold.value,
        Comparison::Eq => count == threshold.value,
    }
}


fn ordered_progress(rule: &CorrelationRule, hits: &[Hit]) -> usize {
    hits.iter().fold(0, |progress, hit| {
        if progress < rule.rules.len() && hit.rules.contains(&progress) {
            progress + 1
        } else {
            progress
        }
    })
}


/// Whether the window of a group satisfies the rule: counts compare, `temporal` needs every rule seen, the ordered kind needs them in order.
pub fn holds(rule: &CorrelationRule, hits: &[Hit]) -> bool {
    match &rule.kind {
        Kind::EventCount(threshold) => compare(threshold, hits.len() as u64),
        Kind::ValueCount { threshold, .. } => {
            let distinct: BTreeSet<&str> = hits.iter().filter_map(|hit| hit.value.as_deref()).collect();
            compare(threshold, distinct.len() as u64)
        }
        Kind::Temporal => (0..rule.rules.len()).all(|position| hits.iter().any(|hit| hit.rules.contains(&position))),
        Kind::TemporalOrdered => ordered_progress(rule, hits) >= rule.rules.len(),
    }
}


/// Inserts in time order (after equal timestamps), drops hits older than the window ending at the newest hit, then enforces the cap; returns the capped-off count.
pub fn insert_hit(hits: &mut Vec<Hit>, hit: Hit, timespan_ms: i64) -> usize {
    let position = hits.partition_point(|existing| existing.timestamp_ms <= hit.timestamp_ms);
    hits.insert(position, hit);
    let newest = hits.last().map_or(0, |last| last.timestamp_ms);
    let oldest_allowed = newest.saturating_sub(timespan_ms);
    hits.retain(|existing| existing.timestamp_ms >= oldest_allowed);
    let excess = hits.len().saturating_sub(MAX_EVENTS_PER_GROUP);
    hits.drain(..excess);
    excess
}


fn evict_oldest(state: &mut RuleState, counters: &mut Counters) {
    let oldest: Vec<String> = state
        .groups
        .iter()
        .min_by_key(|(_, hits)| hits.last().map_or(i64::MIN, |hit| hit.timestamp_ms))
        .map(|(key, _)| key.clone())
        .into_iter()
        .collect();
    oldest.iter().for_each(|key| {
        state.groups.remove(key);
        counters.dropped_groups = counters.dropped_groups.saturating_add(1);
    });
}


pub fn build_alert(rule: &CorrelationRule, key: &str, hits: &[Hit]) -> Alert {
    Alert {
        rule_id: rule.id.clone(),
        rule_title: rule.title.clone(),
        level: rule.level,
        group: rule
            .group_by
            .iter()
            .cloned()
            .zip(key.split(GROUP_SEPARATOR).map(str::to_string))
            .collect(),
        first_ms: hits.first().map_or(0, |hit| hit.timestamp_ms),
        last_ms: hits.last().map_or(0, |hit| hit.timestamp_ms),
        event_ids: hits.iter().map(|hit| hit.event_id.clone()).collect(),
    }
}


/// Adds an event to its group window and returns the alert when the rule fires; a firing resets that group's window.
pub fn observe(rule: &CorrelationRule, state: &mut RuleState, counters: &mut Counters, key: &str, hit: Hit) -> Option<Alert> {
    if !state.groups.contains_key(key) && state.groups.len() >= MAX_GROUPS_PER_RULE {
        evict_oldest(state, counters);
    }
    let hits = state.groups.entry(key.to_string()).or_default();
    let dropped = insert_hit(hits, hit, rule.timespan_ms);
    counters.dropped_events = counters.dropped_events.saturating_add(dropped as u64);
    if holds(rule, hits) {
        let alert = build_alert(rule, key, hits);
        state.groups.remove(key);
        counters.alerts = counters.alerts.saturating_add(1);
        Some(alert)
    } else {
        None
    }
}

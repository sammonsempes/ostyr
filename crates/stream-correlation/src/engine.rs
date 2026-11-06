use crate::base::base_matches;
use crate::correlation::{CorrelationRule, Kind};
use crate::field::{event_time_ms, field_texts, group_key, VALUE_SEPARATOR};
use crate::ruleset::RuleSet;
use crate::window::{observe, Alert, Counters, Hit, RuleState, State, LATENESS_MS};
use core_config::reload::{current_config, ReloadEngine};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use tracing::{debug, warn};


/// The rule set swaps atomically through the reload engine; the windows live behind one mutex.
pub struct Engine {
    pub rules: Arc<ReloadEngine<RuleSet>>,
    pub state: Mutex<State>,
}


pub fn new_engine(rules: Arc<ReloadEngine<RuleSet>>, state: State) -> Engine {
    Engine {
        rules,
        state: Mutex::new(state),
    }
}


pub fn snapshot(engine: &Engine) -> State {
    engine.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
}


/// Keeps the windows of rules whose id and fingerprint are unchanged, drops the others and starts empty windows for new rules.
pub fn sync_state(state: &mut State, rules: &RuleSet) {
    state.rules.retain(|id, kept| {
        rules
            .correlations
            .iter()
            .any(|rule| rule.id == *id && rule.fingerprint == kept.fingerprint)
    });
    rules.correlations.iter().for_each(|rule| {
        state.rules.entry(rule.id.clone()).or_insert_with(|| RuleState {
            fingerprint: rule.fingerprint.clone(),
            groups: BTreeMap::new(),
        });
    });
}


pub fn is_late(state: &State, timestamp_ms: i64) -> bool {
    state
        .watermark_ms
        .is_some_and(|watermark| timestamp_ms < watermark.saturating_sub(LATENESS_MS))
}


fn hit_value(rule: &CorrelationRule, event: &Value) -> Option<Option<String>> {
    match &rule.kind {
        Kind::ValueCount { field, .. } => field_texts(event, field).map(|texts| Some(texts.join(VALUE_SEPARATOR))),
        _ => Some(None),
    }
}


pub struct Observation<'a> {
    pub event: &'a Value,
    pub event_id: &'a str,
    pub timestamp_ms: i64,
    pub matched: &'a [bool],
}


fn observe_rule(rule: &CorrelationRule, observation: &Observation, state: &mut RuleState, counters: &mut Counters) -> Option<Alert> {
    let positions: Vec<usize> = rule
        .rules
        .iter()
        .enumerate()
        .filter(|(_, base)| observation.matched.get(**base).is_some_and(|flag| *flag))
        .map(|(position, _)| position)
        .collect();
    let key = if positions.is_empty() {
        None
    } else {
        group_key(observation.event, &rule.group_by)
    };
    let measured = hit_value(rule, observation.event);
    key.zip(measured).and_then(|(group, value)| {
        let hit = Hit {
            timestamp_ms: observation.timestamp_ms,
            event_id: observation.event_id.to_string(),
            rules: positions,
            value,
        };
        observe(rule, state, counters, &group, hit)
    })
}


fn process_valid(state: &mut State, rules: &RuleSet, observation: &Observation) -> Vec<Alert> {
    state.watermark_ms = state.watermark_ms.max(Some(observation.timestamp_ms));
    let State {
        rules: rule_states,
        counters,
        ..
    } = state;
    rules
        .correlations
        .iter()
        .filter_map(|rule| observe_rule(rule, observation, rule_states.entry(rule.id.clone()).or_default(), counters))
        .collect()
}


/// Feeds one ECS event to every correlation rule and returns the alerts it triggers; an event without a usable `@timestamp`, or older than the lateness, is counted and ignored.
pub fn process_event(engine: &Engine, event_id: &str, event: &Value) -> Vec<Alert> {
    let rules = current_config(&engine.rules);
    let mut state = engine.state.lock().unwrap_or_else(PoisonError::into_inner);
    sync_state(&mut state, &rules);
    state.counters.processed = state.counters.processed.saturating_add(1);
    match event_time_ms(event) {
        Err(error) => {
            warn!(%error, event_id, "event ignored: no usable timestamp");
            state.counters.invalid = state.counters.invalid.saturating_add(1);
            Vec::new()
        }
        Ok(timestamp_ms) if is_late(&state, timestamp_ms) => {
            debug!(event_id, timestamp_ms, "event ignored: later than the allowed lateness");
            state.counters.late = state.counters.late.saturating_add(1);
            Vec::new()
        }
        Ok(timestamp_ms) => {
            let matched: Vec<bool> = rules.bases.iter().map(|base| base_matches(base, event)).collect();
            let observation = Observation {
                event,
                event_id,
                timestamp_ms,
                matched: &matched,
            };
            process_valid(&mut state, &rules, &observation)
        }
    }
}

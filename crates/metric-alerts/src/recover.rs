//! Restart recovery: the breach start of a forecast or absence rule is read back from the alerts the previous process stored.

use crate::alerting::{MICROS_PER_SECOND, RULE_ID_PREFIX};
use crate::evaluate::capacity_of;
use crate::forecast::{forecast_holds, window_points};
use crate::model::{Condition, Rule, RuleFile};
use crate::query::window_and_step;
use crate::round::{bind_tenant, state_key, RoundError, RoundStates, MAX_ROUND_STATES};
use crate::types::{Point, Timestamp};
use alerts::store::MAX_CREATED_MICROS;
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use serde_json::json;
use std::collections::BTreeMap;
use tracing::warn;


pub const SERIES_PREFIX: &str = "series:";


pub const SINCE_PREFIX: &str = "since:";


pub const RULE_PREFIX: &str = "rule:";


/// `$1` tenant, `$2` JSON list of `{rule_id, series}` for the rules being recovered: the newest unclosed alert of each, `(rule id, event ids)`.
pub const RECOVER_SQL: &str =
    "SELECT latest.rule_id, latest.event_ids::text FROM jsonb_to_recordset($2::text::jsonb) AS wanted(rule_id text, series text) \
                               CROSS JOIN LATERAL (SELECT alerts.rule_id, alerts.event_ids FROM alerts WHERE alerts.tenant = $1 \
                               AND alerts.rule_id = wanted.rule_id AND alerts.event_ids ? wanted.series AND NOT EXISTS \
                               (SELECT 1 FROM alert_triage WHERE alert_triage.tenant = alerts.tenant AND alert_triage.alert_id = alerts.id \
                               AND alert_triage.status = 'closed') ORDER BY alerts.created DESC, alerts.id DESC LIMIT 1) AS latest";


/// A forecast or absence rule has no breach start in its series, so only these two need a recovered `since`.
pub fn needs_recovery(rule: &Rule) -> bool {
    matches!(rule.condition, Condition::Forecast { .. } | Condition::Absence { .. })
}


/// The rules to recover, at most `MAX_ROUND_STATES` of them.
pub fn recoverable(rules: &RuleFile) -> Vec<&Rule> {
    rules.rules.iter().filter(|rule| needs_recovery(rule)).take(MAX_ROUND_STATES).collect()
}


/// `since` fits in alert microseconds.
pub fn fits(since: Timestamp) -> bool {
    since.checked_mul(MICROS_PER_SECOND).is_some_and(|micros| micros <= MAX_CREATED_MICROS)
}


/// The breach start a stored alert records for this rule and series; `None` unless its event ids name the rule and the series and `since` is in `[0, now]` and fits.
pub fn since_of(rule: &Rule, key: &str, events: &str, now: Timestamp) -> Option<Timestamp> {
    let event_ids: Vec<String> = serde_json::from_str(events).ok()?;
    let has = |wanted: String| event_ids.contains(&wanted);
    let since: Timestamp = event_ids.iter().find_map(|id| id.strip_prefix(SINCE_PREFIX))?.parse().ok()?;
    (has(format!("{RULE_PREFIX}{}", rule.id)) && has(format!("{SERIES_PREFIX}{key}")) && since <= now && fits(since)).then_some(since)
}


/// The first row whose rule id is exactly `metric.<rule id>` and whose event ids check out.
pub fn candidate_of(rule: &Rule, key: &str, now: Timestamp, rows: &[Row]) -> Option<Timestamp> {
    let rule_id = format!("{RULE_ID_PREFIX}{}", rule.id);
    rows.iter()
        .filter(|row| row.first() == Some(&rule_id))
        .find_map(|row| row.get(1).and_then(|events| since_of(rule, key, events, now)))
}


/// A candidate `since` per state key, for the rules that have no state yet; rows nobody accepted are counted in one warning.
pub fn candidates_of(rules: &RuleFile, rows: &[Row], now: Timestamp, states: &RoundStates) -> BTreeMap<String, Timestamp> {
    let found: BTreeMap<String, Timestamp> = recoverable(rules)
        .into_iter()
        .map(|rule| (state_key(rule), rule))
        .filter(|(key, _)| !states.states.contains_key(key))
        .filter_map(|(key, rule)| candidate_of(rule, &key, now, rows).map(|since| (key, since)))
        .collect();
    let refused = rows.len().saturating_sub(found.len());
    if refused > 0 {
        warn!(refused, "stored metric alerts refused for recovery");
    }
    found
}


/// The breach reaches back to `since` in the fetched window and still holds: an absence has no sample after `since`, a forecast holds now; threshold and rate never recover.
pub fn held_since(rule: &Rule, series: &[Point], capacity: Option<f64>, since: Timestamp, now: Timestamp) -> bool {
    let from = now.saturating_sub(window_and_step(rule).0);
    since >= from
        && match &rule.condition {
            Condition::Absence { .. } => series.iter().all(|point| point.0 <= since),
            Condition::Forecast {
                window,
                capacity: kind,
                horizon,
                min_confidence,
                min_points,
            } => capacity_of(kind, capacity)
                .is_some_and(|value| forecast_holds(&window_points(series, *window, now), value, (*horizon, *min_confidence, *min_points), now)),
            Condition::Threshold { .. } | Condition::Rate { .. } => false,
        }
}


/// On the first call for a `RoundStates` (the process start) reads the newest unclosed alert of each forecast and absence rule into `candidates`; later calls do nothing. Answers how many candidates were found.
pub async fn recover_states(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    rules: &RuleFile,
    now: Timestamp,
    states: &mut RoundStates,
) -> Result<usize, RoundError> {
    bind_tenant(states, scope)?;
    if states.recovered {
        Ok(0)
    } else {
        let wanted: Vec<_> = recoverable(rules)
            .into_iter()
            .map(|rule| json!({ "rule_id": format!("{RULE_ID_PREFIX}{}", rule.id), "series": format!("{SERIES_PREFIX}{}", state_key(rule)) }))
            .collect();
        let rows = if wanted.is_empty() {
            Vec::new()
        } else {
            exec(scope.clone(), RECOVER_SQL, vec![json!(wanted).to_string()]).await?
        };
        let found = candidates_of(rules, &rows, now, states);
        let count = found.len();
        states.candidates.extend(found);
        states.recovered = true;
        Ok(count)
    }
}

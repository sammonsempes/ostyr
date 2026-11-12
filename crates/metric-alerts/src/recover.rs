//! Restart recovery: the breach start of an absence rule is read back from the alerts the previous process stored.

use crate::alerting::{MICROS_PER_SECOND, RULE_ID_PREFIX};
use crate::model::{Condition, Rule, RuleFile};
use crate::query::window_and_step;
use crate::round::{bind_tenant, state_key, RoundError, RoundStates, MAX_ROUND_STATES};
use crate::types::{Point, Timestamp};
use alerts::store::MAX_CREATED_MICROS;
use alerts::types::{Executor, Row};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use serde_json::json;
use std::collections::BTreeMap;
use tracing::warn;


pub const SERIES_PREFIX: &str = "series:";


pub const SINCE_PREFIX: &str = "since:";


pub const RULE_PREFIX: &str = "rule:";


pub const MAX_ROWS_PER_RULE: usize = 5;


pub const MAX_RECOVERY_ATTEMPTS: u32 = 3;


/// `$1` tenant, `$2` JSON list of `{rule_id, series, from}` (`from` the rule's own lower creation bound in microseconds), `$3` the upper bound (now) in microseconds: per rule the newest unclosed alerts, `(rule id, event ids)`.
pub const RECOVER_SQL: &str =
    "SELECT latest.rule_id, latest.event_ids::text FROM jsonb_to_recordset($2::text::jsonb) AS wanted(rule_id text, series text, \"from\" text) \
                               CROSS JOIN LATERAL (SELECT alerts.rule_id, alerts.event_ids, alerts.created, alerts.id FROM alerts \
                               WHERE alerts.tenant = $1 AND alerts.created >= (wanted.from)::bigint AND alerts.created <= $3::text::bigint \
                               AND alerts.rule_id = wanted.rule_id AND alerts.event_ids ? wanted.series AND NOT EXISTS \
                               (SELECT 1 FROM alert_triage WHERE alert_triage.tenant = alerts.tenant AND alert_triage.alert_id = alerts.id \
                               AND alert_triage.status = 'closed') ORDER BY alerts.created DESC, alerts.id DESC LIMIT 5) AS latest \
                               ORDER BY latest.created DESC, latest.id DESC";


/// Only an absence rule has no breach start in its series; a forecast is never seeded (a restart raises a new alert), threshold and rate resume from the series.
pub fn needs_recovery(rule: &Rule) -> bool {
    matches!(rule.condition, Condition::Absence { .. })
}


/// The rules to recover, at most `MAX_ROUND_STATES` of them.
pub fn recoverable(rules: &RuleFile) -> Vec<&Rule> {
    rules.rules.iter().filter(|rule| needs_recovery(rule)).take(MAX_ROUND_STATES).collect()
}


/// Seconds as alert microseconds, never past `MAX_CREATED_MICROS`.
pub fn micros(seconds: Timestamp) -> u64 {
    seconds.saturating_mul(MICROS_PER_SECOND).min(MAX_CREATED_MICROS)
}


/// `since` fits in alert microseconds.
pub fn fits(since: Timestamp) -> bool {
    since.checked_mul(MICROS_PER_SECOND).is_some_and(|value| value <= MAX_CREATED_MICROS)
}


/// The breach start a stored alert records for this rule and series; `None` unless its event ids name the rule and the series and `since` is in `[0, now]` and fits.
pub fn since_of(rule: &Rule, key: &str, events: &str, now: Timestamp) -> Option<Timestamp> {
    let event_ids: Vec<String> = serde_json::from_str(events).ok()?;
    let has = |wanted: String| event_ids.contains(&wanted);
    let since: Timestamp = event_ids.iter().find_map(|id| id.strip_prefix(SINCE_PREFIX))?.parse().ok()?;
    (has(format!("{RULE_PREFIX}{}", rule.id)) && has(format!("{SERIES_PREFIX}{key}")) && since <= now && fits(since)).then_some(since)
}


/// The newest row (rows come newest first) of rule id exactly `metric.<rule id>` whose event ids check out, and how many newer rows of that rule were refused.
pub fn candidate_of(rule: &Rule, key: &str, now: Timestamp, rows: &[Row]) -> (Option<Timestamp>, usize) {
    let rule_id = format!("{RULE_ID_PREFIX}{}", rule.id);
    let sinces: Vec<Option<Timestamp>> = rows
        .iter()
        .filter(|row| row.first() == Some(&rule_id))
        .map(|row| row.get(1).and_then(|events| since_of(rule, key, events, now)))
        .collect();
    let newest = sinces.iter().position(Option::is_some);
    (newest.and_then(|at| sinces.get(at)).copied().flatten(), newest.unwrap_or(sinces.len()))
}


/// A candidate `since` per state key; refused rows are counted in one warning.
pub fn candidates_of(rules: &RuleFile, rows: &[Row], now: Timestamp) -> BTreeMap<String, Timestamp> {
    let judged: Vec<(String, Option<Timestamp>, usize)> = recoverable(rules)
        .into_iter()
        .map(|rule| {
            let key = state_key(rule);
            let (since, refused) = candidate_of(rule, &key, now, rows);
            (key, since, refused)
        })
        .collect();
    let refused: usize = judged.iter().map(|(_, _, count)| count).sum();
    if refused > 0 {
        warn!(refused, "stored metric alerts refused for recovery");
    }
    judged.into_iter().filter_map(|(key, since, _)| since.map(|value| (key, value))).collect()
}


/// The absence reaches back to `since`, at least one step inside the fetched window (a rollup bucket starting before the window bound is not fetched and ends before `from`), and still holds: no sample after `since`; any other rule never recovers.
pub fn held_since(rule: &Rule, series: &[Point], since: Timestamp, now: Timestamp) -> bool {
    let (window, step) = window_and_step(rule);
    let from = now.saturating_sub(window).saturating_add(step);
    since >= from && matches!(rule.condition, Condition::Absence { .. }) && series.iter().all(|point| point.0 <= since)
}


/// A fixed name per failure, never the text of the error.
pub fn recovery_class(fault: &PgError) -> &'static str {
    match fault {
        PgError::ConnectTimeout { .. } | PgError::StatementTimeout { .. } => "timeout",
        PgError::Server { .. } | PgError::Client(_) => "database",
        _ => "other",
    }
}


/// Reads the newest unclosed alerts of each absence rule created in `[now - its own window, now]`; asks nothing when there is no rule.
pub async fn read_candidates(exec: Executor<'_, '_>, scope: &TenantScope, wanted: &[&Rule], now: Timestamp) -> Result<Vec<Row>, PgError> {
    let asked: Vec<_> = wanted
        .iter()
        .map(|rule| {
            json!({
                "rule_id": format!("{RULE_ID_PREFIX}{}", rule.id),
                "series": format!("{SERIES_PREFIX}{}", state_key(rule)),
                "from": micros(now.saturating_sub(window_and_step(rule).0)).to_string(),
            })
        })
        .collect();
    let params = vec![json!(asked).to_string(), micros(now).to_string()];
    if wanted.is_empty() {
        Ok(Vec::new())
    } else {
        exec(scope.clone(), RECOVER_SQL, params).await
    }
}


/// On the first call for a `RoundStates` (the process start) reads the newest unclosed alert of each absence rule into `candidates`; later calls do nothing. Answers how many candidates were found. A failed read is an error until `MAX_RECOVERY_ATTEMPTS` attempts failed; then it gives up (one warning), so the absence rules start from `now`.
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
        match read_candidates(exec, scope, &recoverable(rules), now).await {
            Ok(rows) => {
                let found = candidates_of(rules, &rows, now);
                let count = found.len();
                states.candidates.extend(found);
                states.recovered = true;
                Ok(count)
            }
            Err(fault) => {
                states.recovery_attempts += 1;
                if states.recovery_attempts >= MAX_RECOVERY_ATTEMPTS {
                    let class = recovery_class(&fault);
                    let attempts = states.recovery_attempts;
                    warn!(class, attempts, "recovery given up, absence rules start from now");
                    states.recovered = true;
                    Ok(0)
                } else {
                    Err(RoundError::Store(fault))
                }
            }
        }
    }
}

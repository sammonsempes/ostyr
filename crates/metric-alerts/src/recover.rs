//! Restart recovery: the breach start of a forecast or absence rule is read back from the alerts the previous process stored.

use crate::model::{Condition, Rule, RuleFile};
use crate::round::{bind_tenant, state_key, RoundError, RoundStates};
use crate::state::AlertState;
use crate::types::Timestamp;
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use tracing::warn;


pub const MAX_RECOVER_ROWS: usize = 5000;


pub const SERIES_PREFIX: &str = "series:";


pub const SINCE_PREFIX: &str = "since:";


/// `$1` tenant, `$2` row cap: the event ids of the tenant's newest metric alerts that no analyst closed, newest first.
pub const RECOVER_SQL: &str = "SELECT event_ids::text FROM alerts WHERE tenant = $1 AND rule_id LIKE 'metric.%' AND NOT EXISTS \
                               (SELECT 1 FROM alert_triage WHERE alert_triage.tenant = alerts.tenant AND alert_triage.alert_id = alerts.id \
                               AND alert_triage.status = 'closed') ORDER BY alerts.created DESC, alerts.id DESC LIMIT $2::text::bigint";


/// A forecast or absence rule has no breach start in its series, so only these two need a recovered `since`.
pub fn needs_recovery(rule: &Rule) -> bool {
    matches!(rule.condition, Condition::Forecast { .. } | Condition::Absence { .. })
}


/// The series fingerprint and the breach start of one stored alert, `None` when its event ids do not hold both.
pub fn identity_of(row: &Row) -> Option<(String, Timestamp)> {
    let event_ids: Vec<String> = row.first().and_then(|text| serde_json::from_str(text).ok())?;
    let series = event_ids.iter().find_map(|id| id.strip_prefix(SERIES_PREFIX))?;
    let since = event_ids.iter().find_map(|id| id.strip_prefix(SINCE_PREFIX))?.parse().ok()?;
    Some((series.to_owned(), since))
}


/// Rows are newest first: the first row of a series wins.
pub fn since_by_series(rows: &[Row]) -> BTreeMap<String, Timestamp> {
    let identities: Vec<(String, Timestamp)> = rows.iter().filter_map(identity_of).collect();
    let unreadable = rows.len().saturating_sub(identities.len());
    if unreadable > 0 {
        warn!(unreadable, "stored metric alerts without a readable series or since");
    }
    identities.into_iter().rev().collect()
}


/// Marks each forecast or absence rule that has no state yet and a stored alert as `Firing` since that alert; answers how many.
pub fn seed(rules: &RuleFile, found: &BTreeMap<String, Timestamp>, states: &mut RoundStates) -> usize {
    let seeds: Vec<(String, AlertState)> = rules
        .rules
        .iter()
        .filter(|rule| needs_recovery(rule))
        .map(state_key)
        .filter(|key| !states.states.contains_key(key))
        .filter_map(|key| found.get(&key).map(|since| (key, AlertState::Firing { since: *since })))
        .collect();
    let count = seeds.len();
    states.states.extend(seeds);
    count
}


/// On the first call for a `RoundStates` (the process start) seeds the rules from their newest unclosed stored alert; later calls do nothing. Answers how many rules were seeded.
pub async fn recover_states(exec: Executor<'_, '_>, scope: &TenantScope, rules: &RuleFile, states: &mut RoundStates) -> Result<usize, RoundError> {
    bind_tenant(states, scope)?;
    if states.recovered {
        Ok(0)
    } else {
        let rows = exec(scope.clone(), RECOVER_SQL, vec![MAX_RECOVER_ROWS.to_string()]).await?;
        let found = since_by_series(&rows);
        states.recovered = true;
        Ok(seed(rules, &found, states))
    }
}

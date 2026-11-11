//! One evaluation round for one tenant: fetch every rule, evaluate it against its previous state, collect the firings.

use crate::alerting::{firing_alerts, store_firing_alerts, Firing};
use crate::error::RuleError;
use crate::evaluate::evaluate_with_capacity;
use crate::fetch::FetchError;
use crate::fingerprint::fingerprint;
use crate::model::{Rule, RuleFile};
use crate::query::{capacity_sql, latest_value, rule_sql};
use crate::state::AlertState;
use crate::types::{FetchFn, Timestamp};
use alerts::error::StoreError;
use alerts::types::Executor;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use siem_ingest::error::InsertClass;
use siem_schema::metrics::MetricsRetention;
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::warn;


pub const MAX_ROUND_STATES: usize = 1000;


/// Previous state per `fingerprint(rule id, selector labels)`; rebuilt every round, so a rule that left the file leaves the map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundStates {
    pub tenant: Option<String>,
    pub recovered: bool,
    pub states: BTreeMap<String, AlertState>,
}


#[derive(Debug, Error)]
pub enum RoundError {
    #[error("these round states belong to another tenant")]
    TenantMismatch,
    #[error("the stored alerts could not be read")]
    Store(#[from] PgError),
}


/// The first use records the tenant; any other tenant afterwards is refused.
pub fn bind_tenant(states: &mut RoundStates, scope: &TenantScope) -> Result<(), RoundError> {
    let tenant = states.tenant.get_or_insert_with(|| tenant_of(scope).to_owned());
    if tenant == tenant_of(scope) {
        Ok(())
    } else {
        Err(RoundError::TenantMismatch)
    }
}


/// `fetch_failures` is keyed by error class (`class_of`), a rule that could not compile included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundCounts {
    pub evaluated: usize,
    pub fetch_failures: BTreeMap<&'static str, usize>,
    pub capacity_missing: usize,
    pub skipped_by_cap: usize,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundOutcome {
    pub firings: Vec<Firing>,
    pub counts: RoundCounts,
}


#[derive(Debug, Error)]
pub enum RoundFault {
    #[error("the rule could not be compiled")]
    Query(#[from] RuleError),
    #[error("the fetch failed")]
    Fetch(#[from] FetchError),
}


/// What one rule produced: its new state and whether a metric capacity was missing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Evaluated {
    pub state: AlertState,
    pub capacity_missing: bool,
}


pub struct RoundContext<'a> {
    pub tenant: &'a TenantScope,
    pub now: Timestamp,
    pub settings: &'a MetricsRetention,
    pub fetch: FetchFn<'a>,
    pub states: &'a RoundStates,
}


pub struct Accumulator {
    pub next: BTreeMap<String, AlertState>,
    pub firings: Vec<Firing>,
    pub counts: RoundCounts,
}


/// A fixed class name per failure, never the text of the error.
pub fn class_of(fault: &RoundFault) -> &'static str {
    match fault {
        RoundFault::Query(_) => "query",
        RoundFault::Fetch(FetchError::Failed(class)) => match class {
            InsertClass::ParseError => "parse_error",
            InsertClass::Unavailable => "unavailable",
            InsertClass::Timeout => "timeout",
            InsertClass::Unauthorized => "unauthorized",
            InsertClass::Rejected => "rejected",
        },
        RoundFault::Fetch(FetchError::Body(_)) => "body",
        RoundFault::Fetch(FetchError::TooLarge | FetchError::TooManyPoints) => "too_large",
        RoundFault::Fetch(FetchError::Malformed(_)) => "malformed",
        RoundFault::Fetch(_) => "settings",
    }
}


/// The state key: the rule id and its selector, the labels of its firings.
pub fn state_key(rule: &Rule) -> String {
    let pairs: Vec<(String, String)> = rule.selector.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
    fingerprint(&rule.id, &pairs)
}


/// Fetches the rule's series (and the latest capacity of a metric forecast) and evaluates; any failure leaves the caller's state alone.
pub fn evaluate_rule(rule: &Rule, context: &RoundContext<'_>, previous: &AlertState) -> Result<Evaluated, RoundFault> {
    let query = rule_sql(rule, context.tenant, context.now, context.settings)?;
    let series = (context.fetch)(&query)?;
    let capacity_query = capacity_sql(rule, context.tenant, context.now, context.settings)?;
    let capacity = capacity_query
        .as_ref()
        .map(|asked| (context.fetch)(asked).map(|rows| latest_value(&rows)))
        .transpose()?
        .flatten();
    Ok(Evaluated {
        state: evaluate_with_capacity(rule, &series, capacity, previous, context.now),
        capacity_missing: capacity_query.is_some() && capacity.is_none(),
    })
}


pub fn firing_of(context: &RoundContext<'_>, rule: &Rule, state: &AlertState) -> Option<Firing> {
    match state {
        AlertState::Firing { since } => Some(Firing {
            tenant: context.tenant.clone(),
            rule_id: rule.id.clone(),
            labels: rule.selector.clone(),
            severity: rule.severity,
            since: *since,
        }),
        AlertState::Inactive | AlertState::Pending { .. } | AlertState::Resolved { .. } | AlertState::Closed => None,
    }
}


pub fn step_rule(mut acc: Accumulator, rule: &Rule, context: &RoundContext<'_>) -> Accumulator {
    let key = state_key(rule);
    let capped = acc.next.len() >= MAX_ROUND_STATES && !acc.next.contains_key(&key);
    let previous = if capped {
        AlertState::Inactive
    } else {
        context.states.states.get(&key).copied().unwrap_or(AlertState::Inactive)
    };
    let state = match evaluate_rule(rule, context, &previous) {
        Ok(evaluated) => {
            acc.counts.evaluated += 1;
            acc.counts.capacity_missing += usize::from(evaluated.capacity_missing);
            evaluated.state
        }
        Err(fault) => {
            *acc.counts.fetch_failures.entry(class_of(&fault)).or_default() += 1;
            previous
        }
    };
    acc.firings.extend(firing_of(context, rule, &state));
    if capped {
        acc.counts.skipped_by_cap += 1;
    } else {
        acc.next.insert(key, state);
    }
    acc
}


/// Evaluates every rule for the tenant. A rule whose fetch failed keeps its previous state, a state beyond `MAX_ROUND_STATES` is counted and evaluated from `Inactive`.
pub fn evaluate_round(
    rules: &RuleFile,
    tenant: &TenantScope,
    now: Timestamp,
    settings: &MetricsRetention,
    fetch: FetchFn<'_>,
    states: &mut RoundStates,
) -> Result<RoundOutcome, RoundError> {
    bind_tenant(states, tenant)?;
    let context = RoundContext {
        tenant,
        now,
        settings,
        fetch,
        states,
    };
    let start = Accumulator {
        next: BTreeMap::new(),
        firings: Vec::new(),
        counts: RoundCounts::default(),
    };
    let done = rules.rules.iter().fold(start, |acc, rule| step_rule(acc, rule, &context));
    let failed: usize = done.counts.fetch_failures.values().sum();
    let skipped = done.counts.skipped_by_cap;
    if failed > 0 || skipped > 0 {
        warn!(failed, skipped, "round finished with failed or skipped rules");
    }
    states.states = done.next;
    Ok(RoundOutcome {
        firings: done.firings,
        counts: done.counts,
    })
}


/// Stores the round's firings as alerts under the scope; answers how many were new (a rerun answers 0).
pub async fn store_round(exec: Executor<'_, '_>, scope: &TenantScope, outcome: &RoundOutcome, now: Timestamp) -> Result<usize, StoreError> {
    store_firing_alerts(exec, scope, &firing_alerts(scope, &outcome.firings, now)).await
}

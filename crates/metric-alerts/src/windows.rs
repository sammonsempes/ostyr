use crate::error::RuleError;
use crate::evaluate::evaluate;
use crate::model::{Condition, Rule};
use crate::state::AlertState;
use crate::types::{Labels, Point, Timestamp};
use chrono::{DateTime, Utc};
use oncall::model::Window;
use oncall::silence::in_maintenance;
use serde::Deserialize;
use std::slice::from_ref;


pub const ASSET_LABEL: &str = "asset";


/// The on-call maintenance windows loaded for one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TenantWindows {
    pub tenant: String,
    pub windows: Vec<Window>,
}


/// The tenant of the rule, the series labels (the `asset` label names the asset) and every loaded window set; sets of another tenant are ignored.
#[derive(Debug, Clone, Copy)]
pub struct WindowScope<'a> {
    pub tenant: &'a str,
    pub labels: &'a Labels,
    pub sets: &'a [TenantWindows],
}


/// `suppressed` is true while a matching window is open: the caller must not notify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    pub state: AlertState,
    pub suppressed: bool,
}


/// Like `evaluate`, but a breach inside a matching open window stays `Pending` from the window's end; a `Firing` alert stays `Firing`, flagged suppressed.
pub fn evaluate_in_windows(
    rule: &Rule,
    series: &[Point],
    previous: &AlertState,
    now: Timestamp,
    scope: &WindowScope,
) -> Result<Evaluation, RuleError> {
    let state = evaluate(rule, &since_breach(rule, series, previous), previous, now);
    let end = window_end(scope, to_datetime(now)?);
    Ok(Evaluation {
        state: end.map_or(state, |ends| hold_until(state, previous, ends)),
        suppressed: end.is_some(),
    })
}


/// A pending breach restarts at its `since` (possibly a window end): earlier samples of a threshold or rate series are dropped, or the fold would restart there.
pub fn since_breach(rule: &Rule, series: &[Point], previous: &AlertState) -> Vec<Point> {
    match (&rule.condition, previous) {
        (Condition::Threshold { .. } | Condition::Rate { .. }, AlertState::Pending { since }) => {
            series.iter().filter(|point| point.0 >= *since).copied().collect()
        }
        _ => series.to_vec(),
    }
}


pub fn to_datetime(now: Timestamp) -> Result<DateTime<Utc>, RuleError> {
    DateTime::from_timestamp(i64::try_from(now)?, 0).ok_or(RuleError::TimeOutOfRange)
}


/// Latest end among the open windows of the tenant that list the series asset.
pub fn window_end(scope: &WindowScope, now: DateTime<Utc>) -> Option<Timestamp> {
    let asset = scope.labels.get(ASSET_LABEL);
    scope
        .sets
        .iter()
        .filter(|set| set.tenant == scope.tenant)
        .flat_map(|set| set.windows.iter())
        .filter(|window| asset.is_some_and(|name| in_maintenance(name, from_ref(window), now)))
        .map(|window| window.ends_at.timestamp().unsigned_abs())
        .max()
}


pub fn hold_until(state: AlertState, previous: &AlertState, end: Timestamp) -> AlertState {
    match (state, previous) {
        (AlertState::Firing { .. }, AlertState::Firing { .. }) => state,
        (AlertState::Pending { .. } | AlertState::Firing { .. }, _) => AlertState::Pending { since: end },
        _ => state,
    }
}

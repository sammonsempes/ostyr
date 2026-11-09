use crate::config::{check_count, validate_config};
use crate::error::StatusPageError;
use crate::model::{CheckResult, ComponentState, Limits, ManualOverride, PageConfig, RuleConfig, ServiceState};
use crate::types::Series;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_CHECK_RESULTS: usize = 100_000;


/// Newest sample first, per (check, location), for the results of the rule's checks inside its window.
pub fn windowed_series<'a>(rule: &RuleConfig, results: &'a [CheckResult], now: i64) -> Series<'a> {
    let oldest = now.saturating_sub(i64::from(rule.window_seconds));
    let mut series: Series = results
        .iter()
        .filter(|result| result.at <= now && result.at > oldest && rule.checks.contains(&result.check))
        .fold(BTreeMap::new(), |mut grouped, result| {
            grouped
                .entry((result.check.as_str(), result.location.as_str()))
                .or_default()
                .push((result.at, result.passed));
            grouped
        });
    series.values_mut().for_each(|samples| samples.sort_by_key(|sample| Reverse(sample.0)));
    series
}


/// A location fails while any of its newest `recover_after` samples failed: one good sample does not recover it.
pub fn failing_locations<'a>(rule: &RuleConfig, series: &Series<'a>) -> BTreeSet<&'a str> {
    let recent = usize::try_from(rule.recover_after).unwrap_or(usize::MAX);
    series
        .iter()
        .filter(|(_, samples)| samples.iter().take(recent).any(|sample| !sample.1))
        .map(|((_, location), _)| *location)
        .collect()
}


pub fn rule_state(rule: &RuleConfig, results: &[CheckResult], now: i64) -> ComponentState {
    let series = windowed_series(rule, results, now);
    let failing = u32::try_from(failing_locations(rule, &series).len()).unwrap_or(u32::MAX);
    let unknown = rule.checks.iter().any(|check| !series.keys().any(|(seen, _)| seen == check));
    if failing >= rule.down_after {
        ComponentState::MajorOutage
    } else if failing >= rule.degraded_after {
        ComponentState::Degraded
    } else if unknown {
        rule.unknown_state.unwrap_or(ComponentState::Unknown)
    } else {
        ComponentState::Operational
    }
}


/// The active override of a service: not yet expired, the latest expiry wins.
pub fn active_override<'a>(overrides: &'a [ManualOverride], service: &str, now: i64) -> Option<&'a ManualOverride> {
    overrides
        .iter()
        .filter(|manual| manual.service == service && now < manual.expires_at)
        .max_by_key(|manual| manual.expires_at)
}


/// Component states from check results; `now` is an input. A component with neither rule nor active override gets no entry.
pub fn derive_states(
    config: &PageConfig,
    results: &[CheckResult],
    overrides: &[ManualOverride],
    now: i64,
    limits: &Limits,
) -> Result<Vec<ServiceState>, StatusPageError> {
    validate_config(config, limits)?;
    check_count("check results", results.len(), MAX_CHECK_RESULTS)?;
    check_count("overrides", overrides.len(), limits.max_components)?;
    let same_tenant = results.iter().all(|result| result.tenant == config.tenant) && overrides.iter().all(|manual| manual.tenant == config.tenant);
    if same_tenant {
        Ok(config
            .components
            .iter()
            .filter_map(|component| {
                active_override(overrides, &component.service, now)
                    .map(|manual| manual.state)
                    .or_else(|| component.rule.as_ref().map(|rule| rule_state(rule, results, now)))
                    .map(|state| ServiceState {
                        tenant: config.tenant.clone(),
                        service: component.service.clone(),
                        state,
                    })
            })
            .collect())
    } else {
        Err(StatusPageError::TenantMismatch)
    }
}

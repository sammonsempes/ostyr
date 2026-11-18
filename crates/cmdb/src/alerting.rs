//! A retired or destroyed asset seen again, as an alert of the alert store (spec section 14).

use crate::error::StoreError;
use crate::model::{Event, Lifecycle, Limits, Observation, Stored};
use crate::store::reconcile_stored;
use crate::types::{Executor, TruthMap};
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS};
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;
use std::collections::BTreeSet;


pub const REAPPEARED_RULE_ID: &str = "cmdb.retired_asset_reappeared";


pub const FLOOD_RULE_ID: &str = "cmdb.retired_asset_reappeared.flood";


pub const ASSET_REF_RULE_ID: &str = "cmdb.asset_ref";


pub const MAX_REAPPEARED_PER_RUN: usize = 100;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const SECONDS_PER_DAY: u64 = 86_400;


/// What one call did with its alerts: new ones, ones the store already held, events cut at `MAX_REAPPEARED_PER_RUN`, alerts whose insert failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlertCounts {
    pub inserted: usize,
    pub existing: usize,
    pub omitted: usize,
    pub alert_failed: usize,
}


/// The life-cycle name and severity of a state that raises an alert; `None` for the others.
pub fn lifecycle_of(lifecycle: Lifecycle) -> Option<(&'static str, Severity)> {
    match lifecycle {
        Lifecycle::Retired => Some(("retired", Severity::Medium)),
        Lifecycle::Destroyed => Some(("destroyed", Severity::High)),
        Lifecycle::Ordered | Lifecycle::InService | Lifecycle::InMaintenance => None,
    }
}


/// The asset id as a digest scoped to the tenant: an asset id may be longer than an event id of the alert store.
pub fn asset_ref(tenant: &str, asset: &str) -> String {
    alert_id(tenant, ASSET_REF_RULE_ID, &[asset.to_owned()])
}


/// One alert per asset and life-cycle state: the identity holds the tenant, the rule, the asset digest and the state, never a time.
pub fn reappeared_alert(scope: &TenantScope, source: &str, asset: &str, state: (&str, Severity), created_micros: u64) -> Alert {
    let (name, severity) = state;
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec![format!("asset:{}", asset_ref(&tenant, asset)), format!("lifecycle:{name}")];
    Alert {
        id: alert_id(&tenant, REAPPEARED_RULE_ID, &event_ids),
        tenant,
        rule_id: REAPPEARED_RULE_ID.to_owned(),
        rule_title: format!("Asset seen again while {name}"),
        severity,
        event_time: created_micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({ "asset": asset, "lifecycle": name, "source": source })),
    }
}


/// The visible cut: one alert per tenant and UTC day (counted from the epoch), with the number of events left without an alert in the run that first raised it.
pub fn flood_alert(scope: &TenantScope, omitted: usize, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let day = created_micros / MICROS_PER_SECOND / SECONDS_PER_DAY;
    let event_ids = vec!["flood".to_owned(), format!("day:{day}")];
    Alert {
        id: alert_id(&tenant, FLOOD_RULE_ID, &event_ids),
        tenant,
        rule_id: FLOOD_RULE_ID.to_owned(),
        rule_title: format!("Reappeared-asset alerts cut at {MAX_REAPPEARED_PER_RUN}, {omitted} more"),
        severity: Severity::Medium,
        event_time: created_micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({ "omitted": omitted, "limit": MAX_REAPPEARED_PER_RUN })),
    }
}


/// The alerts of the `Reappeared` events (distinct by identity, at most `MAX_REAPPEARED_PER_RUN`, then a flood alert) and how many events were cut; no attribute value enters an alert.
pub fn reappeared_alerts(scope: &TenantScope, source: &str, events: &[Event], now_micros: u64) -> (Vec<Alert>, usize) {
    let created_micros = now_micros.min(MAX_CREATED_MICROS);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let distinct: Vec<Alert> = events
        .iter()
        .filter_map(|event| match event {
            Event::Reappeared { asset, lifecycle } => {
                lifecycle_of(*lifecycle).map(|state| reappeared_alert(scope, source, asset, state, created_micros))
            }
            Event::Created { .. } => None,
        })
        .filter(|alert| seen.insert(alert.id.clone()))
        .collect();
    let omitted = distinct.len().saturating_sub(MAX_REAPPEARED_PER_RUN);
    let mut alerts: Vec<Alert> = distinct.into_iter().take(MAX_REAPPEARED_PER_RUN).collect();
    if omitted > 0 {
        alerts.push(flood_alert(scope, omitted, created_micros));
        tracing::warn!(omitted, "cmdb reappeared-asset alerts cut");
    }
    (alerts, omitted)
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT`; a failed batch is one warning and counted, never an error.
pub async fn store_reappeared_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert], omitted: usize) -> AlertCounts {
    let mut counts = AlertCounts {
        omitted,
        ..AlertCounts::default()
    };
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        match insert_alerts(exec, scope, batch).await {
            Ok(inserted) => {
                counts.inserted += inserted;
                counts.existing += batch.len().saturating_sub(inserted);
            }
            Err(error) => {
                let reason = error.to_string();
                let failed = batch.len();
                tracing::warn!(reason, failed, "cmdb alert insert failed, retried by the next sighting");
                counts.alert_failed += failed;
            }
        }
    }
    counts
}


/// `reconcile_stored`, then the alerts of its `Reappeared` events once the CMDB change is committed; a failed alert insert never undoes or fails it.
pub async fn reconcile_with_alerts(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    observation: &Observation,
    truth: &TruthMap,
    limits: &Limits,
    now_micros: u64,
) -> Result<(Stored, AlertCounts), StoreError> {
    let stored = reconcile_stored(exec, scope, observation, truth, limits).await?;
    let (alerts, omitted) = reappeared_alerts(scope, &observation.source, &stored.outcome.events, now_micros);
    let counts = store_reappeared_alerts(exec, scope, &alerts, omitted).await;
    Ok((stored, counts))
}

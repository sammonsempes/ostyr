use crate::model::{
    Candidate, KnownDevices, LeaseHints, Skipped, Stored, AGENT_PACKAGE, FLOOD_RULE_ID, MAX_ALERT_SERVICES, MAX_UNMANAGED_PER_RUN, MICROS_PER_MILLI,
    UNMANAGED_RULE_ID,
};
use crate::observe_cmdb::{asset_by_mac, hint_state, service_text, Hint};
use crate::types::Pending;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS};
use alerts::types::Executor;
use cmdb::model::Asset;
use core_pg::scope::{tenant_of, TenantScope};
use dhcp_kea::alerting::day_of;
use ecs_normalise::suricata::clean;
use serde_json::json;
use tracing::warn;


/// The alert identity of a device: `mac:<MAC>` when a lease valid for the candidate names one, else `ip:<address>`.
pub fn identity_of(candidate: &Candidate, mac: Option<&str>) -> String {
    mac.map_or_else(|| format!("ip:{}", candidate.address.to_canonical()), |found| format!("mac:{found}"))
}


/// Microseconds of a time in milliseconds, clamped to the range the store accepts.
pub fn micros_of(millis: i64) -> u64 {
    u64::try_from(millis)
        .unwrap_or(0)
        .saturating_mul(MICROS_PER_MILLI)
        .min(MAX_CREATED_MICROS)
}


/// The alert of one unmanaged device; the identity is the tenant, the rule and the device identity only (never the hostname).
pub fn unmanaged_alert(scope: &TenantScope, candidate: &Candidate, mac: Option<&str>, hostname: Option<&str>, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec![identity_of(candidate, mac)];
    let address = candidate.address.to_canonical().to_string();
    let services: Vec<String> = candidate.services.iter().take(MAX_ALERT_SERVICES).map(service_text).collect();
    let cleaned = hostname.map(clean);
    Alert {
        id: alert_id(&tenant, UNMANAGED_RULE_ID, &event_ids),
        tenant,
        rule_id: UNMANAGED_RULE_ID.to_owned(),
        rule_title: format!("Unmanaged device {address}: install the agent"),
        severity: Severity::Medium,
        event_time: micros_of(candidate.first_seen_ms).to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "address": address,
            "mac": mac,
            "services": services,
            "services_total": candidate.services.len() + candidate.services_omitted,
            "proposal": format!("install the agent {AGENT_PACKAGE}"),
            "labels": { "discovery_hostname": cleaned },
        })),
    }
}


/// The visible cut: one alert per tenant and UTC day, with the number of devices left without an alert in the run that first raised it.
pub fn flood_alert(scope: &TenantScope, omitted: usize, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec!["flood".to_owned(), format!("day:{}", day_of(created_micros))];
    Alert {
        id: alert_id(&tenant, FLOOD_RULE_ID, &event_ids),
        tenant,
        rule_id: FLOOD_RULE_ID.to_owned(),
        rule_title: format!("Unmanaged-device alerts cut at {MAX_UNMANAGED_PER_RUN}, {omitted} more"),
        severity: Severity::Medium,
        event_time: created_micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({ "omitted": omitted, "limit": MAX_UNMANAGED_PER_RUN })),
    }
}


/// One alert per unmanaged candidate (oldest first seen, then address), at most `MAX_UNMANAGED_PER_RUN`, plus a flood alert past it; a known address or a valid lease MAC keying an asset raises none.
pub fn unmanaged_alerts(
    scope: &TenantScope,
    candidates: &[Candidate],
    hints: &LeaseHints,
    inventory: &[Asset],
    known: &KnownDevices,
    now_micros: u64,
) -> (Vec<Alert>, Skipped) {
    let created_micros = now_micros.min(MAX_CREATED_MICROS);
    let by_mac = asset_by_mac(inventory);
    let same_tenant = hints.tenant == tenant_of(scope);
    let mut skipped = Skipped::default();
    let mut pending: Pending = Pending::new();
    candidates.iter().for_each(|candidate| {
        let address = candidate.address.to_canonical();
        let lease = hints
            .leases
            .get(&address)
            .filter(|found| same_tenant && !found.mac.is_empty() && hint_state(found, candidate) == Hint::Valid);
        let mac = lease.map(|found| found.mac.as_str());
        if known.addresses.contains(&address) {
            skipped.known += 1;
        } else if mac.is_some_and(|found| by_mac.contains_key(found)) {
            skipped.managed += 1;
        } else {
            let hostname = lease.and_then(|found| found.hostname.as_deref());
            pending.insert((candidate.first_seen_ms, address), (candidate, mac, hostname));
        }
    });
    skipped.omitted = pending.len().saturating_sub(MAX_UNMANAGED_PER_RUN);
    let mut alerts: Vec<Alert> = pending
        .values()
        .take(MAX_UNMANAGED_PER_RUN)
        .map(|(candidate, mac, hostname)| unmanaged_alert(scope, candidate, *mac, *hostname, created_micros))
        .collect();
    if skipped.omitted > 0 {
        alerts.push(flood_alert(scope, skipped.omitted, created_micros));
    }
    (alerts, skipped)
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; a refused batch is counted and warned once, the others are still stored.
pub async fn store_unmanaged_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Stored {
    let mut stored = Stored::default();
    let mut last_reason: Option<String> = None;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        match insert_alerts(exec, scope, batch).await {
            Ok(new) => stored.inserted += new,
            Err(error) => {
                stored.failed += batch.len();
                last_reason = Some(error.to_string());
            }
        }
    }
    if let Some(reason) = last_reason {
        let failed = stored.failed;
        warn!(failed, reason, "unmanaged-device alerts were not stored");
    }
    stored
}

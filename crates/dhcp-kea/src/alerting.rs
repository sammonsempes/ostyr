//! A lease for a device the CMDB does not know, as an alert of the alert store (spec section 14).

use crate::row::{normalise_mac, valid_hostname, Converted};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;


pub const UNKNOWN_RULE_ID: &str = "dhcp.unknown_device";


pub const FLOOD_RULE_ID: &str = "dhcp.unknown_device_flood";


pub const MAX_UNKNOWN_PER_RUN: usize = 200;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


/// What a run left out without an alert: leases with no usable MAC and known-MAC entries not in the ECS form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rejected {
    pub no_mac: usize,
    pub bad_known: usize,
}


/// The MAC of a lease in the ECS form, `None` when the lease has none or it is not in that form.
pub fn mac_of(lease: &Converted) -> Option<String> {
    lease
        .event
        .source
        .as_ref()
        .and_then(|source| source.mac.as_deref())
        .and_then(normalise_mac)
}


/// Microseconds of a Unix time in seconds, clamped to the range the store accepts.
pub fn micros_of(seconds: i64) -> u64 {
    u64::try_from(seconds)
        .unwrap_or(0)
        .saturating_mul(MICROS_PER_SECOND)
        .min(MAX_CREATED_MICROS)
}


/// The lease's checked hostname and IP, the only peer text that reaches the summary.
pub fn peer_fields(lease: &Converted) -> (Option<String>, Option<String>) {
    let hostname = lease
        .event
        .host
        .as_ref()
        .and_then(|host| host.hostname.as_deref())
        .and_then(valid_hostname);
    let address = lease
        .event
        .source
        .as_ref()
        .and_then(|source| source.ip.as_deref())
        .and_then(|text| IpAddr::from_str(text).ok())
        .map(|found| found.to_string());
    (hostname, address)
}


/// The alert of one unknown MAC; its identity is the tenant, the rule and `mac:<MAC>` only.
pub fn unknown_alert(scope: &TenantScope, mac: &str, lease: &Converted, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec![format!("mac:{mac}")];
    let (hostname, address) = peer_fields(lease);
    Alert {
        id: alert_id(&tenant, UNKNOWN_RULE_ID, &event_ids),
        tenant,
        rule_id: UNKNOWN_RULE_ID.to_owned(),
        rule_title: format!("DHCP lease for unknown device {mac}"),
        severity: Severity::Low,
        event_time: micros_of(lease.cltt).to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({ "mac": mac, "ip": address, "hostname": hostname })),
    }
}


/// The visible cut: one alert per run and `now`, with the number of unknown devices left without an alert.
pub fn flood_alert(scope: &TenantScope, omitted: usize, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec![format!("flood:{created_micros}")];
    Alert {
        id: alert_id(&tenant, FLOOD_RULE_ID, &event_ids),
        tenant,
        rule_id: FLOOD_RULE_ID.to_owned(),
        rule_title: format!("DHCP unknown-device alerts cut at {MAX_UNKNOWN_PER_RUN}, {omitted} more"),
        severity: Severity::Medium,
        event_time: created_micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({ "omitted": omitted, "limit": MAX_UNKNOWN_PER_RUN })),
    }
}


/// One alert per distinct unknown MAC of the batch (first lease wins, batch order), at most `MAX_UNKNOWN_PER_RUN`, plus a flood alert past it.
pub fn unknown_device_alerts(scope: &TenantScope, leases: &[Converted], known_macs: &BTreeSet<String>, now_micros: u64) -> (Vec<Alert>, Rejected) {
    let created_micros = now_micros.min(MAX_CREATED_MICROS);
    let bad_known = known_macs
        .iter()
        .filter(|entry| normalise_mac(entry).as_deref() != Some(entry.as_str()))
        .count();
    let macs: Vec<Option<String>> = leases.iter().map(mac_of).collect();
    let no_mac = macs.iter().filter(|mac| mac.is_none()).count();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let unknown: Vec<(&str, &Converted)> = macs
        .iter()
        .zip(leases)
        .filter_map(|(mac, lease)| mac.as_deref().map(|found| (found, lease)))
        .filter(|(mac, _lease)| !known_macs.contains(*mac) && seen.insert(*mac))
        .collect();
    let omitted = unknown.len().saturating_sub(MAX_UNKNOWN_PER_RUN);
    let mut alerts: Vec<Alert> = unknown
        .iter()
        .take(MAX_UNKNOWN_PER_RUN)
        .map(|(mac, lease)| unknown_alert(scope, mac, lease, created_micros))
        .collect();
    if omitted > 0 {
        alerts.push(flood_alert(scope, omitted, created_micros));
    }
    if no_mac > 0 || bad_known > 0 || omitted > 0 {
        tracing::warn!(no_mac, bad_known, omitted, "dhcp unknown-device run left leases or entries out");
    }
    (alerts, Rejected { no_mac, bad_known })
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_unknown_device_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}

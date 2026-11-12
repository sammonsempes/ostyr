//! A lease for a device the CMDB does not know, as an alert of the alert store (spec section 14).

use crate::cursor::{read_cursor, write_cursor};
use crate::row::{normalise_mac, valid_hostname, Converted};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;
use time::{Duration, OffsetDateTime};


pub const UNKNOWN_RULE_ID: &str = "dhcp.unknown_device";


pub const FLOOD_RULE_ID: &str = "dhcp.unknown_device_flood";


pub const MAX_UNKNOWN_PER_RUN: usize = 200;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const LOOKUP_FACTOR: usize = 25;


pub const MAX_LOOKUP_MACS: usize = MAX_UNKNOWN_PER_RUN * LOOKUP_FACTOR;


pub const MAX_LOOKUP_CHUNKS: usize = 10;


pub const SECONDS_PER_DAY: u64 = 86_400;


pub const MAX_DAY_SECONDS: u64 = 253_402_300_799;


pub const ALERTED_SQL: &str =
    "SELECT id FROM alerts WHERE tenant = $1 AND rule_id = 'dhcp.unknown_device' AND id IN (SELECT jsonb_array_elements_text($2::text::jsonb))";


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


/// The UTC day of a time in microseconds as `YYYY-MM-DD`, clamped to year 9999.
pub fn day_of(created_micros: u64) -> String {
    let seconds = (created_micros / MICROS_PER_SECOND).min(MAX_DAY_SECONDS);
    let day_start = seconds - seconds % SECONDS_PER_DAY;
    (OffsetDateTime::UNIX_EPOCH + Duration::seconds(day_start as i64)).date().to_string()
}


/// The visible cut: one alert per tenant and UTC day, with the number of unknown devices left without an alert in the run that first raised it.
pub fn flood_alert(scope: &TenantScope, omitted: usize, created_micros: u64) -> Alert {
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec!["flood".to_owned(), format!("day:{}", day_of(created_micros))];
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


/// The distinct unknown MACs of the batch in batch order with their first lease.
pub fn unknown_of<'a>(macs: &'a [Option<String>], leases: &'a [Converted], known_macs: &BTreeSet<String>) -> Vec<(&'a str, &'a Converted)> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    macs.iter()
        .zip(leases)
        .filter_map(|(mac, lease)| mac.as_deref().map(|found| (found, lease)))
        .filter(|(mac, _lease)| !known_macs.contains(*mac) && seen.insert(*mac))
        .collect()
}


/// The distinct unknown MACs of the batch in batch order.
pub fn candidate_macs(leases: &[Converted], known_macs: &BTreeSet<String>) -> Vec<String> {
    let macs: Vec<Option<String>> = leases.iter().map(mac_of).collect();
    unknown_of(&macs, leases, known_macs)
        .iter()
        .map(|(mac, _lease)| (*mac).to_owned())
        .collect()
}


/// The candidates already holding a stored alert of the tenant (one query, at most `MAX_LOOKUP_MACS` ids); empty on failure.
pub async fn alerted_macs(exec: Executor<'_, '_>, scope: &TenantScope, candidates: &[String]) -> BTreeSet<String> {
    let tenant = tenant_of(scope);
    let by_id: BTreeMap<String, &String> = candidates
        .iter()
        .take(MAX_LOOKUP_MACS)
        .map(|mac| (alert_id(tenant, UNKNOWN_RULE_ID, &[format!("mac:{mac}")]), mac))
        .collect();
    let found = if by_id.is_empty() {
        Ok(Vec::new())
    } else {
        let document = json!(by_id.keys().collect::<Vec<_>>()).to_string();
        exec(scope.clone(), ALERTED_SQL, vec![document]).await.map_err(|error| error.to_string())
    };
    match found {
        Ok(rows) => rows
            .iter()
            .filter_map(|row| row.first())
            .filter_map(|id| by_id.get(id.as_str()))
            .map(|mac| (*mac).clone())
            .collect(),
        Err(reason) => {
            tracing::warn!(reason, "dhcp already-alerted lookup failed, cap in batch order");
            BTreeSet::new()
        }
    }
}


/// What the lookup learned: the MACs to leave out of the run, the scanned MACs in scan order, how many of them already held an alert, and the chunk the next run starts at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lookup {
    pub skip: BTreeSet<String>,
    pub scan_order: Vec<String>,
    pub found: usize,
    pub next_chunk: usize,
}


/// The chunk to store after a run that scanned `scanned` chunks from `start`: the last one again when it held fresh MACs beyond the run's cap, else the one after it.
pub fn next_chunk_of(start: usize, scanned: usize, chunk_count: usize, fresh: usize) -> usize {
    let stay = usize::from(fresh > MAX_UNKNOWN_PER_RUN && scanned > 0);
    (start + scanned - stay) % chunk_count.max(1)
}


/// The MACs of the batch to leave out of this run and the order to pick the rest in: at most `MAX_LOOKUP_CHUNKS` chunk lookups from the tenant's stored cursor, wrapping around, until enough fresh MACs are seen; every MAC of an unscanned chunk is left out (its turn is a later run).
pub async fn alerted_in_batch(exec: Executor<'_, '_>, scope: &TenantScope, leases: &[Converted], known_macs: &BTreeSet<String>) -> Lookup {
    let candidates = candidate_macs(leases, known_macs);
    let chunks: Vec<&[String]> = candidates.chunks(MAX_LOOKUP_MACS).collect();
    let chunk_count = chunks.len();
    let start = read_cursor(exec, scope).await % chunk_count.max(1);
    let mut order = (0..chunk_count.min(MAX_LOOKUP_CHUNKS)).filter_map(|offset| {
        let index = (start + offset) % chunk_count;
        chunks.get(index).map(|chunk| (index, *chunk))
    });
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut alerted: BTreeSet<String> = BTreeSet::new();
    let mut scan_order: Vec<String> = Vec::new();
    let mut fresh = 0;
    let mut scanned = 0;
    let mut found_total = 0;
    let mut done = false;
    while !done && fresh < MAX_UNKNOWN_PER_RUN {
        match order.next() {
            Some((index, chunk)) => {
                visited.insert(index);
                let found = alerted_macs(exec, scope, chunk).await;
                fresh += chunk.len() - found.len();
                scanned += 1;
                found_total += found.len();
                alerted.extend(found);
                scan_order.extend(chunk.iter().cloned());
            }
            None => done = true,
        }
    }
    let deferred = chunks
        .iter()
        .enumerate()
        .filter(|(index, _chunk)| !visited.contains(index))
        .flat_map(|(_index, chunk)| chunk.iter().cloned());
    alerted.extend(deferred);
    if fresh < MAX_UNKNOWN_PER_RUN && scanned < chunk_count {
        let total = candidates.len();
        tracing::warn!(total, scanned, start, "dhcp lookup cap reached");
    }
    Lookup {
        skip: alerted,
        scan_order,
        found: found_total,
        next_chunk: next_chunk_of(start, scanned, chunk_count, fresh),
    }
}


/// Stores the position the next run starts at; call it after the alerts were stored, so a failed insert repeats the chunks instead of skipping them.
pub async fn advance_cursor(exec: Executor<'_, '_>, scope: &TenantScope, lookup: &Lookup) {
    write_cursor(exec, scope, lookup.next_chunk).await;
}


/// One alert per distinct unknown MAC of the batch (first lease wins, batch order), at most `MAX_UNKNOWN_PER_RUN`, plus a flood alert past it.
pub fn unknown_device_alerts(scope: &TenantScope, leases: &[Converted], known_macs: &BTreeSet<String>, now_micros: u64) -> (Vec<Alert>, Rejected) {
    unknown_device_alerts_in_order(scope, leases, known_macs, now_micros, &[])
}


/// Like `unknown_device_alerts`, but the MACs of `scan_order` come first, in that order (the lookup's scan order, never the batch order); the others follow in batch order.
pub fn unknown_device_alerts_in_order(
    scope: &TenantScope,
    leases: &[Converted],
    known_macs: &BTreeSet<String>,
    now_micros: u64,
    scan_order: &[String],
) -> (Vec<Alert>, Rejected) {
    let created_micros = now_micros.min(MAX_CREATED_MICROS);
    let bad_known = known_macs
        .iter()
        .filter(|entry| normalise_mac(entry).as_deref() != Some(entry.as_str()))
        .count();
    let macs: Vec<Option<String>> = leases.iter().map(mac_of).collect();
    let no_mac = macs.iter().filter(|mac| mac.is_none()).count();
    let rank: BTreeMap<&str, usize> = scan_order.iter().enumerate().map(|(position, mac)| (mac.as_str(), position)).collect();
    let mut unknown = unknown_of(&macs, leases, known_macs);
    unknown.sort_by_key(|(mac, _lease)| rank.get(mac).copied().unwrap_or(usize::MAX));
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

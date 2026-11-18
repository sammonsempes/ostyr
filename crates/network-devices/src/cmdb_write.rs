//! Declared devices as CMDB observations (spec sections 14 and 22): one observation per device, written per tenant under that tenant's scope.

use crate::model::{Device, DeviceKind};
use cmdb::alerting::{reconcile_with_alerts, AlertCounts};
use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, IdentityKey, Limits, Observation, Stored};
use cmdb::store::load_assets;
use cmdb::types::{Executor, TruthMap};
use core_pg::scope::tenant_scope;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;


pub const SOURCE: &str = "declared-network";


pub const NAME_PREFIX: &str = "netdev:";


pub const KIND_ATTRIBUTE: &str = "network.kind";


pub const ADDRESSES_ATTRIBUTE: &str = "network.addresses";


pub const POLLING_ATTRIBUTE: &str = "network.snmp_polling";


pub const DISCOVERY_IP_ATTRIBUTE: &str = "discovery.ip";


/// What one tenant's run did; `failed` is a fixed reason when a store error stopped the tenant's remaining devices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantReport {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub refused: usize,
    pub alerts_inserted: usize,
    pub failed: Option<&'static str>,
    pub agent_hosts: Vec<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub tenants: BTreeMap<String, TenantReport>,
}


pub fn asset_kind_of(kind: DeviceKind) -> AssetKind {
    match kind {
        DeviceKind::Switch | DeviceKind::Router | DeviceKind::Firewall | DeviceKind::AccessPoint => AssetKind::NetworkDevice,
        DeviceKind::Printer => AssetKind::Printer,
        DeviceKind::Ups | DeviceKind::Other => AssetKind::Iot,
    }
}


pub fn kind_text(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Switch => "switch",
        DeviceKind::Router => "router",
        DeviceKind::Firewall => "firewall",
        DeviceKind::AccessPoint => "access_point",
        DeviceKind::Printer => "printer",
        DeviceKind::Ups => "ups",
        DeviceKind::Other => "other",
    }
}


pub fn name_key_of(device: &Device) -> String {
    format!("{NAME_PREFIX}{}", device.name)
}


/// No `owner` attribute is ever written, so a device file cannot raise the owned ratio.
pub fn observation_of(device: &Device) -> Observation {
    let addresses: BTreeSet<String> = device.addresses.iter().map(IpAddr::to_string).collect();
    let polling = device.snmp.as_ref().is_some_and(|snmp| snmp.polling);
    Observation {
        source: SOURCE.to_owned(),
        kind: asset_kind_of(device.kind),
        keys: [(IdentityKey::Name, name_key_of(device))].into_iter().collect(),
        attributes: [
            (KIND_ATTRIBUTE.to_owned(), kind_text(device.kind).to_owned()),
            (ADDRESSES_ATTRIBUTE.to_owned(), addresses.into_iter().collect::<Vec<String>>().join(",")),
            (POLLING_ATTRIBUTE.to_owned(), polling.to_string()),
        ]
        .into_iter()
        .collect(),
    }
}


pub fn observations(devices: &[Device]) -> Vec<(String, Observation)> {
    devices.iter().map(|device| (device.tenant.clone(), observation_of(device))).collect()
}


pub fn asset_named<'a>(assets: &'a [Asset], name_key: &str) -> Option<&'a Asset> {
    assets
        .iter()
        .find(|asset| asset.keys.get(&IdentityKey::Name).is_some_and(|name| name == name_key))
}


pub fn is_agent_kind(kind: AssetKind) -> bool {
    matches!(kind, AssetKind::Server | AssetKind::Workstation)
}


/// Every `discovery.ip` a CMDB server or workstation reports, parsed once.
pub fn agent_addresses(assets: &[Asset]) -> BTreeSet<IpAddr> {
    assets
        .iter()
        .filter(|asset| is_agent_kind(asset.kind))
        .filter_map(|asset| asset.attributes.get(DISCOVERY_IP_ATTRIBUTE))
        .filter_map(|reported| reported.value.parse::<IpAddr>().ok())
        .collect()
}


/// Names of the devices of `tenant` declared `agent_managed: false` whose address a CMDB server or workstation reports as `discovery.ip`.
pub fn agent_host_devices(devices: &[Device], tenant: &str, assets: &[Asset]) -> Vec<String> {
    let reported = agent_addresses(assets);
    devices
        .iter()
        .filter(|device| device.tenant == tenant && !device.agent_managed)
        .filter(|device| device.addresses.iter().any(|address| reported.contains(address)))
        .map(|device| device.name.clone())
        .collect()
}


/// A fixed reason for a store error that stops one tenant: never the error text.
pub fn failure_reason(error: &StoreError) -> &'static str {
    match error {
        StoreError::CapReached { .. } => "cap_reached",
        StoreError::TooManyRows { .. } => "too_many_rows",
        StoreError::RetriesExhausted { .. } => "retries_exhausted",
        StoreError::Pg(_) => "database",
        _ => "store",
    }
}


pub fn tally(
    report: &mut TenantReport,
    before: Option<&Asset>,
    result: Result<(Stored, AlertCounts), StoreError>,
    name_key: &str,
    at: (&str, usize),
) {
    match result {
        Ok((stored, counts)) => {
            let after = asset_named(&stored.outcome.inventory, name_key);
            if before.is_none() {
                report.created += 1;
            } else if before == after {
                report.unchanged += 1;
            } else {
                report.updated += 1;
            }
            report.alerts_inserted += counts.inserted;
        }
        Err(StoreError::Cmdb(error)) => {
            let reason = error.to_string();
            let (tenant, index) = at;
            tracing::warn!(tenant, index, reason, "declared device refused by the CMDB checks");
            report.refused += 1;
        }
        Err(other) => report.failed = Some(failure_reason(&other)),
    }
}


/// One tenant under its own scope: a store error stops this tenant's remaining devices only and is kept in `failed`.
pub async fn write_tenant(
    exec: Executor<'_, '_>,
    devices: &[Device],
    tenant: &str,
    truth: &TruthMap,
    limits: &Limits,
    now_micros: u64,
) -> TenantReport {
    let mut report = TenantReport::default();
    match tenant_scope(tenant) {
        Err(_) => report.failed = Some("tenant"),
        Ok(scope) => match load_assets(exec, &scope, limits).await {
            Err(error) => report.failed = Some(failure_reason(&error)),
            Ok(snapshot) => {
                report.agent_hosts = agent_host_devices(devices, tenant, &snapshot.assets);
                for (index, device) in devices.iter().enumerate().filter(|(_, device)| device.tenant == tenant) {
                    if report.failed.is_none() {
                        let name_key = name_key_of(device);
                        let result = reconcile_with_alerts(exec, &scope, &observation_of(device), truth, limits, now_micros).await;
                        tally(&mut report, asset_named(&snapshot.assets, &name_key), result, &name_key, (tenant, index));
                    }
                }
            }
        },
    }
    report
}


/// One scoped run per tenant, in name order; a device the CMDB checks refuse is counted alone and a store error stops only its tenant (`failed`).
pub async fn write_devices(exec: Executor<'_, '_>, devices: &[Device], truth: &TruthMap, limits: &Limits, now_micros: u64) -> WriteReport {
    let tenants: BTreeSet<&str> = devices.iter().map(|device| device.tenant.as_str()).collect();
    let mut report = WriteReport::default();
    for tenant in tenants {
        let tenant_report = write_tenant(exec, devices, tenant, truth, limits, now_micros).await;
        if let Some(reason) = tenant_report.failed {
            tracing::warn!(tenant, reason, "declared devices not fully written for this tenant");
        }
        report.tenants.insert(tenant.to_owned(), tenant_report);
    }
    report
}

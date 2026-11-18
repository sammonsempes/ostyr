//! Declared devices as CMDB observations (spec sections 14 and 22): one observation per device, written per tenant under that tenant's scope.

use crate::model::{Device, DeviceKind};
use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, IdentityKey, Limits, Observation, Stored};
use cmdb::store::{load_assets, reconcile_stored};
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


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantReport {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub refused: usize,
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


pub fn holds_address(asset: &Asset, address: IpAddr) -> bool {
    is_agent_kind(asset.kind)
        && asset
            .attributes
            .get(DISCOVERY_IP_ATTRIBUTE)
            .is_some_and(|reported| reported.value.parse::<IpAddr>() == Ok(address))
}


/// Names of the devices of `tenant` declared `agent_managed: false` whose address a CMDB server or workstation reports as `discovery.ip`.
pub fn agent_host_devices(devices: &[Device], tenant: &str, assets: &[Asset]) -> Vec<String> {
    devices
        .iter()
        .filter(|device| device.tenant == tenant && !device.agent_managed)
        .filter(|device| {
            device
                .addresses
                .iter()
                .any(|address| assets.iter().any(|asset| holds_address(asset, *address)))
        })
        .map(|device| device.name.clone())
        .collect()
}


pub fn tally(report: &mut TenantReport, before: Option<&Asset>, result: Result<Stored, StoreError>, name_key: &str) -> Result<(), StoreError> {
    match result {
        Ok(stored) => {
            let after = asset_named(&stored.outcome.inventory, name_key);
            if before.is_none() {
                report.created += 1;
            } else if before == after {
                report.unchanged += 1;
            } else {
                report.updated += 1;
            }
            Ok(())
        }
        Err(StoreError::Cmdb(error)) => {
            let reason = error.to_string();
            tracing::warn!(reason, "declared device refused by the CMDB checks");
            report.refused += 1;
            Ok(())
        }
        Err(other) => Err(other),
    }
}


/// One scoped run per tenant; a device the CMDB checks refuse is counted alone, any other store error (cap reached, database) stops the run loudly.
pub async fn write_devices(exec: Executor<'_, '_>, devices: &[Device], truth: &TruthMap, limits: &Limits) -> Result<WriteReport, StoreError> {
    let tenants: BTreeSet<&str> = devices.iter().map(|device| device.tenant.as_str()).collect();
    let mut report = WriteReport::default();
    for tenant in tenants {
        let scope = tenant_scope(tenant)?;
        let snapshot = load_assets(exec, &scope, limits).await?;
        let mut tenant_report = TenantReport {
            agent_hosts: agent_host_devices(devices, tenant, &snapshot.assets),
            ..TenantReport::default()
        };
        for device in devices.iter().filter(|device| device.tenant == tenant) {
            let name_key = name_key_of(device);
            let result = reconcile_stored(exec, &scope, &observation_of(device), truth, limits).await;
            tally(&mut tenant_report, asset_named(&snapshot.assets, &name_key), result, &name_key)?;
        }
        report.tenants.insert(tenant.to_owned(), tenant_report);
    }
    Ok(report)
}

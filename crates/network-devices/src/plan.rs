use crate::model::{Device, PlanEntry};
use site_collector::listen_settings::source_key;
use site_collector::types::SourceKeySet;


/// Only devices with polling on and no agent, sorted by tenant then name.
pub fn polling_plan(devices: &[Device]) -> Vec<PlanEntry> {
    let mut plan: Vec<PlanEntry> = devices.iter().filter_map(entry_of).collect();
    plan.sort_by(|left, right| (&left.tenant, &left.name).cmp(&(&right.tenant, &right.name)));
    plan
}


pub fn entry_of(device: &Device) -> Option<PlanEntry> {
    device
        .snmp
        .as_ref()
        .filter(|snmp| snmp.polling && !device.agent_managed)
        .map(|snmp| PlanEntry {
            tenant: device.tenant.clone(),
            name: device.name.clone(),
            addresses: device.addresses.clone(),
            version: snmp.version,
            credentials: snmp.credentials.clone(),
        })
}


/// The source keys the collector listener admits for `tenant`: every declared address, polled or push-only.
pub fn declared_sources(devices: &[Device], tenant: &str) -> SourceKeySet {
    devices
        .iter()
        .filter(|device| device.tenant == tenant)
        .flat_map(|device| device.addresses.iter().copied().map(source_key))
        .collect()
}

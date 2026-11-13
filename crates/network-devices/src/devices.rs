use crate::error::DeviceError;
use crate::model::{Claims, Device, DeviceFile, LoadResult, SecurityLevel, SnmpSettings, SnmpVersion, Warning};
use core_config::parse::{parse_document, read_text_capped};
use core_pg::scope::tenant_scope;
use site_collector::listen_settings::source_key;
use std::collections::BTreeSet;
use std::io::Read;


pub const MAX_FILE_BYTES: u64 = 262_144;


pub const MAX_DEVICES_PER_FILE: usize = 1000;


pub const MAX_DEVICES: usize = 4000;


pub const MAX_ADDRESSES: usize = 8;


pub const MAX_NAME_BYTES: usize = 128;


pub const MAX_REFERENCE_BYTES: usize = 128;


pub const MAX_TRAPS_PER_MINUTE: u32 = 60_000;


pub const MAX_FLOW_RECORDS_PER_SECOND: u32 = 100_000;


pub const MAX_STALE_SECONDS: u64 = 2_592_000;


/// Reads at most `MAX_FILE_BYTES`, parses strictly, validates every device and checks names and addresses are unique inside the file.
pub fn parse_device_file(reader: &mut dyn Read, file: &str) -> Result<LoadResult, DeviceError> {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    let parsed = parse_document::<DeviceFile>(&text, file)?;
    (parsed.devices.len() <= MAX_DEVICES_PER_FILE)
        .then_some(())
        .ok_or_else(|| DeviceError::TooManyDevices {
            file: file.to_owned(),
            count: parsed.devices.len(),
        })?;
    parsed.devices.iter().enumerate().try_for_each(|(index, device)| {
        validate_device(device).map_err(|field| DeviceError::Invalid {
            file: file.to_owned(),
            index,
            field,
        })
    })?;
    claim_devices(&mut Claims::default(), &parsed.devices, file)?;
    Ok(LoadResult {
        warnings: warnings_of(&parsed.devices),
        devices: parsed.devices,
    })
}


/// The first failed rule as a fixed field name.
pub fn validate_device(device: &Device) -> Result<(), &'static str> {
    let checks = [
        ("name", name_ok(&device.name)),
        ("tenant", tenant_scope(&device.tenant).is_ok()),
        ("addresses", (1..=MAX_ADDRESSES).contains(&device.addresses.len())),
        (
            "volumes.max_traps_per_minute",
            (1..=MAX_TRAPS_PER_MINUTE).contains(&device.volumes.max_traps_per_minute),
        ),
        (
            "volumes.max_flow_records_per_second",
            (1..=MAX_FLOW_RECORDS_PER_SECOND).contains(&device.volumes.max_flow_records_per_second),
        ),
        ("stale_after_seconds", (1..=MAX_STALE_SECONDS).contains(&device.stale_after_seconds)),
    ];
    let snmp_failure = device.snmp.as_ref().and_then(|snmp| failed_snmp_field(snmp, device.agent_managed));
    first_failed(&checks).or(snmp_failure).map_or(Ok(()), Err)
}


pub fn first_failed(checks: &[(&'static str, bool)]) -> Option<&'static str> {
    checks.iter().find(|check| !check.1).map(|check| check.0)
}


pub fn failed_snmp_field(snmp: &SnmpSettings, agent_managed: bool) -> Option<&'static str> {
    let is_v3 = snmp.version == SnmpVersion::V3;
    first_failed(&[
        ("snmp.credentials", reference_ok(&snmp.credentials)),
        ("snmp.polling", !(snmp.polling && agent_managed)),
        ("snmp.version", is_v3 || snmp.accept_insecure),
        ("snmp.v3", !is_v3 || v3_complete(snmp)),
    ])
}


/// Version 3 needs authentication and privacy, both named: the protocol enums hold only the accepted algorithms.
pub fn v3_complete(snmp: &SnmpSettings) -> bool {
    snmp.security_level == Some(SecurityLevel::AuthPriv) && snmp.auth_protocol.is_some() && snmp.priv_protocol.is_some()
}


/// Alphanumeric first, then alphanumerics and `.`, `_`, `-`: no empty segment, no `..`, no leading `-`, no hidden character.
pub fn segment_ok(segment: &str) -> bool {
    segment.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && segment
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


pub fn name_ok(name: &str) -> bool {
    name.len() <= MAX_NAME_BYTES && segment_ok(name)
}


/// A path below the secrets directory: every `/` separated segment passes `segment_ok`.
pub fn reference_ok(reference: &str) -> bool {
    reference.len() <= MAX_REFERENCE_BYTES && reference.split('/').all(segment_ok)
}


/// Claims each device's name and each distinct source key of its addresses for its tenant, the first duplicate is an error.
pub fn claim_devices(claims: &mut Claims, devices: &[Device], file: &str) -> Result<(), DeviceError> {
    devices.iter().enumerate().try_for_each(|(index, device)| {
        claims
            .names
            .insert((device.tenant.clone(), device.name.clone()))
            .then_some(())
            .ok_or_else(|| DeviceError::DuplicateName {
                file: file.to_owned(),
                index,
            })?;
        device
            .addresses
            .iter()
            .copied()
            .map(source_key)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .try_for_each(|key| {
                claims
                    .addresses
                    .insert((device.tenant.clone(), key))
                    .then_some(())
                    .ok_or_else(|| DeviceError::DuplicateAddress {
                        file: file.to_owned(),
                        index,
                    })
            })
    })
}


pub fn warnings_of(devices: &[Device]) -> Vec<Warning> {
    devices
        .iter()
        .filter_map(|device| {
            device.snmp.as_ref().filter(|snmp| snmp.version != SnmpVersion::V3).map(|snmp| Warning {
                tenant: device.tenant.clone(),
                device: device.name.clone(),
                version: snmp.version,
            })
        })
        .collect()
}

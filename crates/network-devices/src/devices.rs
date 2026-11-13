use crate::bounded::TOO_MANY_ELEMENTS;
use crate::error::DeviceError;
use crate::model::{Claims, CountFile, Device, DeviceFile, LoadResult, SecurityLevel, SnmpSettings, SnmpVersion, Warning};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use core_pg::scope::tenant_scope;
use site_collector::listen_settings::source_key;
use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};


pub const MAX_FILE_BYTES: u64 = 262_144;


pub const MAX_DEVICES_PER_FILE: usize = 1000;


pub const MAX_DEVICES: usize = 4000;


pub const MAX_ADDRESSES: usize = 8;


pub const IPV6_ZERO_PREFIX_BYTES: usize = 8;


pub const IPV6_BITS: u32 = 128;


pub const NAT64_PREFIX_BITS: u32 = 96;


pub const NAT64_LOCAL_PREFIX_BITS: u32 = 48;


pub const TEREDO_PREFIX_BITS: u32 = 32;


pub const SIX_TO_FOUR_PREFIX_BITS: u32 = 16;


pub const DISCARD_PREFIX_BITS: u32 = 64;


pub const SITE_LOCAL_PREFIX_BITS: u32 = 10;


pub const TRANSLATION_PREFIX_SEGMENT: u16 = 0x64;


pub const NAT64_SEGMENT: u16 = 0xff9b;


pub const TEREDO_SEGMENT: u16 = 0x2001;


pub const SIX_TO_FOUR_SEGMENT: u16 = 0x2002;


pub const DISCARD_SEGMENT: u16 = 0x100;


pub const SITE_LOCAL_SEGMENT: u16 = 0xfec0;


pub const REFUSED_V6_PREFIXES: [(Ipv6Addr, u32); 6] = [
    (
        Ipv6Addr::new(TRANSLATION_PREFIX_SEGMENT, NAT64_SEGMENT, 0, 0, 0, 0, 0, 0),
        NAT64_PREFIX_BITS,
    ),
    (
        Ipv6Addr::new(TRANSLATION_PREFIX_SEGMENT, NAT64_SEGMENT, 1, 0, 0, 0, 0, 0),
        NAT64_LOCAL_PREFIX_BITS,
    ),
    (Ipv6Addr::new(TEREDO_SEGMENT, 0, 0, 0, 0, 0, 0, 0), TEREDO_PREFIX_BITS),
    (Ipv6Addr::new(SIX_TO_FOUR_SEGMENT, 0, 0, 0, 0, 0, 0, 0), SIX_TO_FOUR_PREFIX_BITS),
    (Ipv6Addr::new(DISCARD_SEGMENT, 0, 0, 0, 0, 0, 0, 0), DISCARD_PREFIX_BITS),
    (Ipv6Addr::new(SITE_LOCAL_SEGMENT, 0, 0, 0, 0, 0, 0, 0), SITE_LOCAL_PREFIX_BITS),
];


pub const MAX_NAME_BYTES: usize = 128;


pub const MAX_REFERENCE_BYTES: usize = 128;


pub const MAX_TRAPS_PER_MINUTE: u32 = 60_000;


pub const MAX_FLOW_RECORDS_PER_SECOND: u32 = 100_000;


pub const MAX_STALE_SECONDS: u64 = 2_592_000;


/// Reads at most `MAX_FILE_BYTES`, parses strictly, validates every device and checks names and addresses are unique inside the file.
pub fn parse_device_file(reader: &mut dyn Read, file: &str) -> Result<LoadResult, DeviceError> {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    count_elements(&text, file)?;
    let parsed = parse_document::<DeviceFile>(&text, file)?;
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


/// Pass 1: counts `devices` and every `addresses` without building them; a failure is only ever a fixed text, never the erased parser message.
pub fn count_elements(text: &str, file: &str) -> Result<(), DeviceError> {
    parse_document::<CountFile>(text, file).map(drop).map_err(|error| match error {
        ConfigError::Parse { message, .. } if message.starts_with(TOO_MANY_ELEMENTS) => DeviceError::TooManyElements { file: file.to_owned() },
        _ => DeviceError::InvalidDocument { file: file.to_owned() },
    })
}


/// The first failed rule as a fixed field name.
pub fn validate_device(device: &Device) -> Result<(), &'static str> {
    let checks = [
        ("name", name_ok(&device.name)),
        ("tenant", tenant_scope(&device.tenant).is_ok()),
        (
            "addresses",
            (1..=MAX_ADDRESSES).contains(&device.addresses.len()) && device.addresses.iter().all(address_ok),
        ),
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
    let snmp_failure = device
        .snmp
        .as_ref()
        .and_then(|snmp| failed_snmp_field(snmp, &device.tenant, device.agent_managed));
    first_failed(&checks).or(snmp_failure).map_or(Ok(()), Err)
}


pub fn first_failed(checks: &[(&'static str, bool)]) -> Option<&'static str> {
    checks.iter().find(|check| !check.1).map(|check| check.0)
}


pub fn failed_snmp_field(snmp: &SnmpSettings, tenant: &str, agent_managed: bool) -> Option<&'static str> {
    let is_v3 = snmp.version == SnmpVersion::V3;
    first_failed(&[
        (
            "snmp.credentials",
            reference_ok(&snmp.credentials) && tenant_bound(&snmp.credentials, tenant),
        ),
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


/// A reference whose first path segment is the device tenant, so a tenant cannot name another tenant's secret.
pub fn tenant_bound(reference: &str, tenant: &str) -> bool {
    reference.strip_prefix(tenant).is_some_and(|rest| rest.starts_with('/'))
}


/// A usable source: `source_key` folds IPv6 to /64 and IPv4-mapped to IPv4, so every address that folds onto an unusable key is refused.
pub fn address_ok(address: &IpAddr) -> bool {
    let refused = match address {
        IpAddr::V4(v4) => [
            v4.is_unspecified(),
            v4.is_loopback(),
            v4.is_multicast(),
            v4.is_broadcast(),
            v4.is_link_local(),
            v4.octets().first() == Some(&0),
        ],
        IpAddr::V6(v6) => [
            v6.octets().iter().take(IPV6_ZERO_PREFIX_BYTES).all(|byte| *byte == 0),
            v6.is_loopback(),
            v6.is_multicast(),
            v6.to_ipv4_mapped().is_some(),
            v6.is_unicast_link_local(),
            in_refused_v6_prefix(v6),
        ],
    };
    !refused.contains(&true)
}


/// Translation, tunnel, discard-only and site-local ranges: one address of them would admit a whole /64 of another population.
pub fn in_refused_v6_prefix(address: &Ipv6Addr) -> bool {
    REFUSED_V6_PREFIXES
        .iter()
        .any(|(prefix, bits)| (u128::from(*address) ^ u128::from(*prefix)) >> (IPV6_BITS - bits) == 0)
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

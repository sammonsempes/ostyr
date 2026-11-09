use crate::error::{PolicyError, ValidationError};
use crate::limits::RolloutLimits;
use crate::model::{GroupPolicy, RingPolicy, RolloutPolicy};
use core_config::parse::{parse_document, read_file};
use std::collections::BTreeMap;
use std::path::Path;


pub fn ring_groups<'policy>(policy: &'policy RolloutPolicy, ring: &RingPolicy) -> Result<Vec<&'policy GroupPolicy>, ValidationError> {
    ring.groups
        .iter()
        .map(|group| {
            policy.groups.get(group).ok_or_else(|| ValidationError::UnknownGroup {
                ring: ring.name.clone(),
                group: group.clone(),
            })
        })
        .collect()
}


pub fn check_count(what: &'static str, count: usize, max: usize) -> Result<(), ValidationError> {
    (count <= max).then_some(()).ok_or(ValidationError::TooMany { what, max })
}


pub fn check_caps(policy: &RolloutPolicy, limits: &RolloutLimits) -> Result<(), ValidationError> {
    check_count("rings", policy.rings.len(), limits.max_rings)?;
    check_count("groups", policy.groups.len(), limits.max_groups)?;
    check_count(
        "devices",
        policy.groups.values().map(|group| group.devices.len()).sum(),
        limits.max_devices,
    )
}


/// Refuses unknown groups, a ring naming no device and a device in two rings.
pub fn validate_policy(policy: &RolloutPolicy, limits: &RolloutLimits) -> Result<(), ValidationError> {
    check_caps(policy, limits)?;
    policy.rings.iter().try_fold(BTreeMap::<&str, &str>::new(), |owners, ring| {
        let devices: Vec<&str> = ring_groups(policy, ring)?
            .into_iter()
            .flat_map(|group| group.devices.iter().map(String::as_str))
            .collect();
        if devices.is_empty() {
            Err(ValidationError::EmptyRing { ring: ring.name.clone() })
        } else {
            devices
                .into_iter()
                .try_fold(owners, |mut seen, device| match seen.insert(device, &ring.name) {
                    Some(first) if first != ring.name => Err(ValidationError::DeviceInTwoRings {
                        device: device.to_owned(),
                        first: first.to_owned(),
                        second: ring.name.clone(),
                    }),
                    _ => Ok(seen),
                })
        }
    })?;
    Ok(())
}


pub fn parse_policy(text: &str, file: &str, limits: &RolloutLimits) -> Result<RolloutPolicy, PolicyError> {
    let policy: RolloutPolicy = parse_document(text, file)?;
    validate_policy(&policy, limits)?;
    Ok(policy)
}


pub fn load_policy(path: &Path, limits: &RolloutLimits) -> Result<RolloutPolicy, PolicyError> {
    let text = read_file(path)?;
    parse_policy(&text, &path.display().to_string(), limits)
}

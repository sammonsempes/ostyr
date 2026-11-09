use crate::error::{PolicyError, ValidationError};
use crate::limits::{RolloutLimits, PERCENT};
use crate::model::{GroupPolicy, RingPolicy, RolloutPolicy};
use core_config::parse::{parse_document, read_file};
use std::collections::{BTreeMap, BTreeSet};
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


pub fn check_rings(policy: &RolloutPolicy) -> Result<(), ValidationError> {
    policy.rings.iter().try_fold(BTreeSet::<&str>::new(), |mut names, ring| {
        if ring.max_failure_percent > PERCENT {
            Err(ValidationError::PercentOver {
                ring: ring.name.clone(),
                percent: ring.max_failure_percent,
            })
        } else if names.insert(ring.name.as_str()) {
            Ok(names)
        } else {
            Err(ValidationError::DuplicateRing { ring: ring.name.clone() })
        }
    })?;
    Ok(())
}


pub fn check_device_groups(policy: &RolloutPolicy) -> Result<(), ValidationError> {
    policy.groups.iter().try_fold(BTreeMap::<&str, &str>::new(), |owners, (name, group)| {
        group
            .devices
            .iter()
            .try_fold(owners, |mut seen, device| match seen.insert(device.as_str(), name.as_str()) {
                Some(first) if first != name => Err(ValidationError::DeviceInTwoGroups {
                    device: device.clone(),
                    first: first.to_owned(),
                    second: name.clone(),
                }),
                _ => Ok(seen),
            })
    })?;
    Ok(())
}


/// Refuses over-cap policies, duplicate ring names, a percentage over 100, a device in two groups, unknown groups, empty rings and a group in two rings.
pub fn validate_policy(policy: &RolloutPolicy, limits: &RolloutLimits) -> Result<(), ValidationError> {
    check_caps(policy, limits)?;
    check_rings(policy)?;
    check_device_groups(policy)?;
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

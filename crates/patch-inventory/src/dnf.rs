//! `dnf updateinfo list --updates` and `dnf check-update`.

use crate::error::InventoryError;
use crate::finish::{finish, insert_preferring_security, key_of};
use crate::model::{Device, Inventory, Limits, Outcome, SkipReason, Update};
use crate::scan::{classify, read_input};
use crate::types::UpdateKey;
use crate::validate::is_valid_rpm;
use std::collections::BTreeMap;
use std::io::Read;
use vuln_match::model::Family;


const METADATA_PREFIX: &str = "Last metadata expiration check:";


const OBSOLETING_LINE: &str = "Obsoleting Packages";


const SECURITY_MARK: &str = "Sec.";


const SECURITY_KIND: &str = "security";


const UNKNOWN_SEVERITY: &str = "unknown";


pub fn parse_dnf<Advisories: Read, Available: Read>(
    device: &Device,
    updateinfo: Advisories,
    check_update: Available,
    limits: &Limits,
) -> Result<Inventory, InventoryError> {
    let advisory_buffer = read_input(updateinfo, limits)?;
    let advisories = classify(&advisory_buffer, limits, |line| parse_updateinfo_line(device, line))?;
    let available_buffer = read_input(check_update, limits)?;
    let available = classify(&available_buffer, limits, |line| parse_check_update_line(device, line))?;
    let mut merged: BTreeMap<UpdateKey, Update> = BTreeMap::new();
    advisories
        .records
        .into_iter()
        .for_each(|update| insert_preferring_security(&mut merged, update));
    available.records.into_iter().for_each(|update| merge_available(&mut merged, update));
    let skipped = available.skipped.into_iter().fold(advisories.skipped, |mut total, (reason, count)| {
        *total.entry(reason).or_insert(0) += count;
        total
    });
    Ok(finish(Family::Rpm, merged.into_values().collect(), skipped))
}


pub fn merge_available(merged: &mut BTreeMap<UpdateKey, Update>, update: Update) {
    merged
        .entry(key_of(&update))
        .and_modify(|existing| {
            existing.candidate_version = update.candidate_version.clone();
            existing.origin = update.origin.clone();
        })
        .or_insert(update);
}


pub fn parse_updateinfo_line(device: &Device, line: &str) -> Outcome<Update> {
    if line.is_empty() || line.starts_with(METADATA_PREFIX) {
        Outcome::Ignored
    } else {
        updateinfo_update(device, line).map_or(Outcome::Skipped(SkipReason::Malformed), Outcome::Record)
    }
}


pub fn updateinfo_update(device: &Device, line: &str) -> Option<Update> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        [advisory, kind, nevra] => advisory_update(device, advisory, kind, nevra),
        _ => None,
    }
}


pub fn advisory_update(device: &Device, advisory: &str, kind: &str, nevra: &str) -> Option<Update> {
    let (package, candidate, architecture) = split_nevra(nevra)?;
    let (security, severity) = match kind.split_once('/') {
        Some((severity, SECURITY_MARK)) => (true, Some(severity.to_lowercase()).filter(|text| text != UNKNOWN_SEVERITY)),
        _ => (kind.eq_ignore_ascii_case(SECURITY_KIND), None),
    };
    Some(Update {
        advisory_id: Some(advisory.to_string()),
        severity,
        security,
        ..bare_update(device, package, architecture, candidate, None)
    })
    .filter(is_valid_rpm)
}


pub fn split_nevra(nevra: &str) -> Option<(&str, &str, &str)> {
    let (rest, architecture) = nevra.rsplit_once('.')?;
    let (name_version, release) = rest.rsplit_once('-')?;
    let (name, _) = name_version.rsplit_once('-')?;
    let version_release = rest.strip_prefix(name)?.strip_prefix('-')?;
    let complete = [name, release, architecture].iter().all(|part| !part.is_empty());
    complete.then_some((name, version_release, architecture))
}


pub fn parse_check_update_line(device: &Device, line: &str) -> Outcome<Update> {
    if line.is_empty() || line.starts_with(METADATA_PREFIX) {
        Outcome::Ignored
    } else if line == OBSOLETING_LINE {
        Outcome::Stop
    } else {
        check_update_update(device, line).map_or(Outcome::Skipped(SkipReason::Malformed), Outcome::Record)
    }
}


pub fn check_update_update(device: &Device, line: &str) -> Option<Update> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        [name_architecture, candidate, repository] => {
            let (package, architecture) = name_architecture.rsplit_once('.')?;
            Some(bare_update(device, package, architecture, candidate, Some(repository))).filter(is_valid_rpm)
        }
        _ => None,
    }
}


pub fn bare_update(device: &Device, package: &str, architecture: &str, candidate: &str, origin: Option<&str>) -> Update {
    Update {
        tenant: device.tenant.clone(),
        device_id: device.device_id.clone(),
        package: package.to_string(),
        architecture: architecture.to_string(),
        installed_version: None,
        candidate_version: candidate.to_string(),
        origin: origin.map(str::to_string),
        security: false,
        advisory_id: None,
        severity: None,
    }
}

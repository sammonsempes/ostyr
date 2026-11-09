//! `dnf updateinfo list --updates` and `dnf check-update`.

use crate::error::InventoryError;
use crate::finish::{finish, key_of};
use crate::model::{Device, Inventory, Limits, Outcome, SkipReason, Update};
use crate::scan::{classify, read_input};
use crate::types::UpdateKey;
use crate::validate::is_valid_rpm;
use std::collections::BTreeMap;
use std::io::Read;
use vuln_match::model::Family;


const METADATA_PREFIX: &str = "Last metadata expiration check:";


const OBSOLETING_LINE: &str = "Obsoleting Packages";


const SEVERITY_ORDER: [&str; 4] = ["low", "moderate", "important", "critical"];


const PROGRESS_BAR: &str = "|";


const PROGRESS_UNIT_MAX: usize = 3;


const PROGRESS_TAIL_TOKENS: usize = 6;


const PROGRESS_NAME_TOKENS_MAX: usize = 16;


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
    let groups = advisories
        .records
        .into_iter()
        .fold(BTreeMap::<UpdateKey, Vec<Update>>::new(), |mut grouped, update| {
            grouped.entry(key_of(&update)).or_default().push(update);
            grouped
        });
    let mut merged: BTreeMap<UpdateKey, Update> = groups
        .iter()
        .filter_map(|(key, listed)| strongest(listed).map(|update| (key.clone(), update.clone())))
        .collect();
    available.records.into_iter().for_each(|update| {
        let matching = groups
            .get(&key_of(&update))
            .and_then(|listed| listed.iter().find(|advisory| advisory.candidate_version == update.candidate_version));
        match matching {
            Some(advisory) => {
                merged.insert(
                    key_of(&update),
                    Update {
                        origin: update.origin.clone(),
                        ..advisory.clone()
                    },
                );
            }
            None => merge_available(&mut merged, update),
        }
    });
    let skipped = available.skipped.into_iter().fold(advisories.skipped, |mut total, (reason, count)| {
        *total.entry(reason).or_insert(0) += count;
        total
    });
    Ok(finish(Family::Rpm, merged.into_values().collect(), skipped))
}


pub fn severity_rank(update: &Update) -> (bool, usize) {
    let rank = update
        .severity
        .as_deref()
        .and_then(|severity| SEVERITY_ORDER.iter().position(|known| *known == severity))
        .map_or(0, |position| position + 1);
    (update.security, rank)
}


pub fn strongest(listed: &[Update]) -> Option<&Update> {
    listed
        .iter()
        .reduce(|best, update| if severity_rank(update) > severity_rank(best) { update } else { best })
}


pub fn is_progress_line(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let name_count = tokens.len().saturating_sub(PROGRESS_TAIL_TOKENS);
    match tokens.split_at_checked(name_count) {
        Some((name, [rate, unit, PROGRESS_BAR, size, size_unit, elapsed])) => {
            (1..=PROGRESS_NAME_TOKENS_MAX).contains(&name.len())
                && rate.chars().all(|character| character.is_ascii_digit() || character == '.')
                && unit.ends_with("/s")
                && size.chars().all(|character| character.is_ascii_digit() || character == '.')
                && size_unit.len() <= PROGRESS_UNIT_MAX
                && elapsed
                    .split(':')
                    .all(|part| !part.is_empty() && part.chars().all(|character| character.is_ascii_digit()))
        }
        _ => false,
    }
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
    if line.is_empty() || line.starts_with(METADATA_PREFIX) || is_progress_line(line) {
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
    if line.is_empty() || line.starts_with(METADATA_PREFIX) || is_progress_line(line) {
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

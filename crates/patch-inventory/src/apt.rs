//! `apt list --upgradable` (C locale).

use crate::error::InventoryError;
use crate::finish::finish;
use crate::model::{Device, Inventory, Limits, Outcome, SkipReason, Update};
use crate::scan::{classify, read_input};
use std::io::Read;
use vuln_match::model::Family;


const LISTING_LINE: &str = "Listing...";


const WARNING_PREFIX: &str = "WARNING:";


const SECURITY_SUFFIX: &str = "-security";


pub fn parse_apt<Source: Read>(device: &Device, reader: Source, limits: &Limits) -> Result<Inventory, InventoryError> {
    let buffer = read_input(reader, limits)?;
    let scanned = classify(&buffer, limits, |line| parse_apt_line(device, line))?;
    Ok(finish(Family::Debian, scanned.records, scanned.skipped))
}


pub fn parse_apt_line(device: &Device, line: &str) -> Outcome<Update> {
    if line.is_empty() || line == LISTING_LINE || line.starts_with(WARNING_PREFIX) {
        Outcome::Ignored
    } else {
        apt_update(device, line).map_or(Outcome::Skipped(SkipReason::Malformed), Outcome::Record)
    }
}


pub fn apt_update(device: &Device, line: &str) -> Option<Update> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let (head, candidate, architecture, installed) = match tokens.as_slice() {
        [head, candidate, architecture, "[upgradable", "from:", installed] => installed
            .strip_suffix(']')
            .map(|version| (*head, *candidate, *architecture, Some(version))),
        [head, candidate, architecture] => Some((*head, *candidate, *architecture, None)),
        _ => None,
    }?;
    let (package, origin) = head.split_once('/')?;
    let complete = !package.is_empty() && !origin.is_empty();
    complete.then(|| Update {
        tenant: device.tenant.clone(),
        device_id: device.device_id.clone(),
        package: package.to_string(),
        architecture: architecture.to_string(),
        installed_version: installed.map(str::to_string),
        candidate_version: candidate.to_string(),
        origin: Some(origin.to_string()),
        security: origin.split(',').any(|suite| suite.ends_with(SECURITY_SUFFIX)),
        advisory_id: None,
        severity: None,
    })
}

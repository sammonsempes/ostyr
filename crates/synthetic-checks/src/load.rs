use crate::error::CheckError;
use crate::model::{
    CertificateDay, Check, CheckFile, FailureRun, RawCheck, RawCheckFile, MAX_CERT_THRESHOLDS, MAX_CHECKS, MAX_INTERVAL_SECONDS, MAX_LOCATIONS,
    MAX_LOCATION_LEN, MAX_NAME_LEN, MAX_SCOPE_ENTRIES, MAX_TARGET_LEN, MAX_TIMEOUT_SECONDS, MIN_INTERVAL_SECONDS, NAT64_PREFIX_LENGTHS,
};
use core_config::error::ConfigError;
use core_config::load::load_file;
use ipnet::Ipv6Net;
use std::collections::BTreeSet;
use std::path::Path;


pub fn load_checks(path: &Path) -> Result<CheckFile, ConfigError> {
    load_file(path)
}


pub fn within(field: &'static str, value: u64, min: u64, max: u64) -> Result<(), CheckError> {
    (min..=max)
        .contains(&value)
        .then_some(())
        .ok_or(CheckError::OutOfRange { field, min, max })
}


pub fn count_within(field: &'static str, count: usize, min: u64, max: usize) -> Result<(), CheckError> {
    within(field, count as u64, min, max as u64)
}


pub fn text_ok(field: &'static str, value: &str, max: usize) -> Result<(), CheckError> {
    let valid = !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control);
    valid.then_some(()).ok_or(CheckError::BadText { field, max })
}


pub fn all_unique<'a>(field: &'static str, values: impl Iterator<Item = &'a String>) -> Result<(), CheckError> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .try_for_each(|value| seen.insert(value.as_str()).then_some(()).ok_or(CheckError::Duplicate { field }))
}


pub fn validate_nat64_prefix(prefix: Option<Ipv6Net>) -> Result<(), CheckError> {
    prefix.iter().try_for_each(|net| {
        (NAT64_PREFIX_LENGTHS.contains(&net.prefix_len()) && net.trunc() == *net)
            .then_some(())
            .ok_or(CheckError::BadNat64Prefix)
    })
}


pub fn validate_check(raw: RawCheck) -> Result<Check, CheckError> {
    text_ok("name", &raw.name, MAX_NAME_LEN)?;
    text_ok("target", &raw.target, MAX_TARGET_LEN)?;
    within("interval_seconds", raw.interval_seconds, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)?;
    within("timeout_seconds", raw.timeout_seconds, 1, MAX_TIMEOUT_SECONDS)?;
    (raw.timeout_seconds <= raw.interval_seconds)
        .then_some(())
        .ok_or(CheckError::TimeoutAboveInterval)?;
    validate_nat64_prefix(raw.nat64_prefix)?;
    let consecutive_failures = FailureRun::try_from(raw.consecutive_failures)?;
    count_within("locations", raw.locations.len(), 1, MAX_LOCATIONS)?;
    raw.locations
        .iter()
        .try_for_each(|location| text_ok("locations", location, MAX_LOCATION_LEN))?;
    all_unique("locations", raw.locations.iter())?;
    within("min_failing_locations", raw.min_failing_locations, 1, raw.locations.len() as u64)?;
    count_within("certificate_days", raw.certificate_days.len(), 1, MAX_CERT_THRESHOLDS)?;
    let certificate_days = raw
        .certificate_days
        .iter()
        .map(|days| CertificateDay::try_from(*days))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Check {
        name: raw.name,
        kind: raw.kind,
        target: raw.target,
        interval_seconds: raw.interval_seconds,
        timeout_seconds: raw.timeout_seconds,
        consecutive_failures,
        locations: raw.locations,
        min_failing_locations: raw.min_failing_locations,
        certificate_days,
        nat64_prefix: raw.nat64_prefix,
    })
}


pub fn validate_file(raw: RawCheckFile) -> Result<CheckFile, CheckError> {
    count_within("scope", raw.scope.len(), 0, MAX_SCOPE_ENTRIES)?;
    count_within("checks", raw.checks.len(), 0, MAX_CHECKS)?;
    all_unique("checks", raw.checks.iter().map(|check| &check.name))?;
    raw.ca_file.iter().try_for_each(|path| text_ok("ca_file", path, MAX_TARGET_LEN))?;
    Ok(CheckFile {
        scope: raw.scope,
        ca_file: raw.ca_file,
        checks: raw.checks,
    })
}


impl TryFrom<RawCheck> for Check {
    type Error = CheckError;

    fn try_from(raw: RawCheck) -> Result<Self, Self::Error> {
        validate_check(raw)
    }
}


impl TryFrom<RawCheckFile> for CheckFile {
    type Error = CheckError;

    fn try_from(raw: RawCheckFile) -> Result<Self, Self::Error> {
        validate_file(raw)
    }
}

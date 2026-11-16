use crate::error::LimitsError;
use crate::model::GroupLimits;
use core_config::load::load_file;
use std::path::Path;


pub const MAX_WINDOW_MICROS: u64 = 604_800_000_000;


pub const MAX_ALERTS_CEILING: u64 = 1_000_000;


pub const MAX_GROUPS_CEILING: u64 = 1_000_000;


pub const MAX_ALERTS_PER_GROUP_CEILING: u64 = 10_000;


pub fn check_range(field: &'static str, value: u64, max: u64) -> Result<(), LimitsError> {
    (1..=max)
        .contains(&value)
        .then_some(())
        .ok_or(LimitsError::OutOfRange { field, value, min: 1, max })
}


pub fn check_limits(limits: &GroupLimits) -> Result<(), LimitsError> {
    check_range("window_micros", limits.window_micros, MAX_WINDOW_MICROS)?;
    check_range("max_alerts", limits.max_alerts as u64, MAX_ALERTS_CEILING)?;
    check_range("max_groups", limits.max_groups as u64, MAX_GROUPS_CEILING)?;
    check_range("max_alerts_per_group", limits.max_alerts_per_group as u64, MAX_ALERTS_PER_GROUP_CEILING)
}


pub fn load_limits(path: &Path) -> Result<GroupLimits, LimitsError> {
    let limits: GroupLimits = load_file(path)?;
    check_limits(&limits)?;
    Ok(limits)
}

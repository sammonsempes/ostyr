use crate::error::{SlaError, SlaLoadError};
use crate::model::Severity;
use core_config::load::load_file;
use serde::{Deserialize, Serialize};
use std::path::Path;


pub const MIN_SLA_MINUTES: u32 = 1;


/// Thirty days.
pub const MAX_SLA_MINUTES: u32 = 43_200;


pub const MIN_NEAR_PERCENT: u32 = 1;


pub const MAX_NEAR_PERCENT: u32 = 99;


const SECONDS_PER_MINUTE: i64 = 60;


const PERCENT: i64 = 100;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaSettings {
    pub low_minutes: u32,
    pub medium_minutes: u32,
    pub high_minutes: u32,
    pub critical_minutes: u32,
    pub near_percent: u32,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaState {
    Within,
    Near,
    Past,
}


pub fn sla_minutes(settings: &SlaSettings, severity: Severity) -> u32 {
    match severity {
        Severity::Low => settings.low_minutes,
        Severity::Medium => settings.medium_minutes,
        Severity::High => settings.high_minutes,
        Severity::Critical => settings.critical_minutes,
    }
}


pub fn check_range(field: &'static str, value: u32, min: u32, max: u32) -> Result<(), SlaError> {
    (min..=max)
        .contains(&value)
        .then_some(())
        .ok_or(SlaError::OutOfRange { field, value, min, max })
}


pub fn validate_sla(settings: SlaSettings) -> Result<SlaSettings, SlaError> {
    check_range("low_minutes", settings.low_minutes, MIN_SLA_MINUTES, MAX_SLA_MINUTES)?;
    check_range("medium_minutes", settings.medium_minutes, MIN_SLA_MINUTES, MAX_SLA_MINUTES)?;
    check_range("high_minutes", settings.high_minutes, MIN_SLA_MINUTES, MAX_SLA_MINUTES)?;
    check_range("critical_minutes", settings.critical_minutes, MIN_SLA_MINUTES, MAX_SLA_MINUTES)?;
    check_range("near_percent", settings.near_percent, MIN_NEAR_PERCENT, MAX_NEAR_PERCENT)?;
    Ok(settings)
}


/// Strict YAML through core-config (errors name file, line and field), then the bounds.
pub fn load_sla(path: &Path) -> Result<SlaSettings, SlaLoadError> {
    let settings: SlaSettings = load_file(path)?;
    Ok(validate_sla(settings)?)
}


/// Past from the deadline itself, near from `near_percent` of the delay; a clock behind the creation reads as within.
pub fn sla_state(created_at: i64, severity: Severity, settings: &SlaSettings, now: i64) -> SlaState {
    let elapsed = now.saturating_sub(created_at);
    let limit = i64::from(sla_minutes(settings, severity)) * SECONDS_PER_MINUTE;
    let near = limit * i64::from(settings.near_percent) / PERCENT;
    if elapsed >= limit {
        SlaState::Past
    } else if elapsed >= near {
        SlaState::Near
    } else {
        SlaState::Within
    }
}

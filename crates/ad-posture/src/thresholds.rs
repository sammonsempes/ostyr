use crate::error::ThresholdsError;
use crate::model::Thresholds;
use core_config::load::load_file;
use serde::Deserialize;
use std::path::Path;


pub const DEFAULT_KRBTGT_MAX_AGE_DAYS: u32 = 180;


pub const DEFAULT_PRIVILEGED_MAX_MEMBERS: usize = 5;


pub const DEFAULT_INACTIVE_DAYS: u32 = 90;


pub const MAX_DAYS: u64 = 36_500;


pub const MAX_MEMBERS: u64 = 100_000;


/// Strict YAML document: every key is optional and defaults to the constants above.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ThresholdSettings {
    pub krbtgt_max_age_days: u32,
    pub privileged_max_members: usize,
    pub inactive_days: u32,
}


impl Default for ThresholdSettings {
    fn default() -> Self {
        Self {
            krbtgt_max_age_days: DEFAULT_KRBTGT_MAX_AGE_DAYS,
            privileged_max_members: DEFAULT_PRIVILEGED_MAX_MEMBERS,
            inactive_days: DEFAULT_INACTIVE_DAYS,
        }
    }
}


pub fn check_range(field: &'static str, value: u64, max: u64) -> Result<(), ThresholdsError> {
    if (1..=max).contains(&value) {
        Ok(())
    } else {
        Err(ThresholdsError::Range { field, min: 1, max })
    }
}


pub fn validate(settings: &ThresholdSettings) -> Result<Thresholds, ThresholdsError> {
    check_range("krbtgt_max_age_days", u64::from(settings.krbtgt_max_age_days), MAX_DAYS)?;
    check_range("privileged_max_members", settings.privileged_max_members as u64, MAX_MEMBERS)?;
    check_range("inactive_days", u64::from(settings.inactive_days), MAX_DAYS)?;
    Ok(Thresholds {
        krbtgt_max_age_days: settings.krbtgt_max_age_days,
        privileged_max_members: settings.privileged_max_members,
        inactive_days: settings.inactive_days,
    })
}


pub fn load_thresholds(path: &Path) -> Result<Thresholds, ThresholdsError> {
    validate(&load_file::<ThresholdSettings>(path)?)
}

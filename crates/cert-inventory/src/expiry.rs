use crate::model::{CertRecord, ExpiryState};


pub const SECONDS_PER_DAY: i64 = 86_400;


/// Expired once `not_after` is reached, else the smallest threshold (in days) the remaining time has crossed, else valid.
pub fn expiry_state(record: &CertRecord, now: i64, thresholds_days: &[u32]) -> ExpiryState {
    let remaining = record.not_after.saturating_sub(now);
    if remaining <= 0 {
        ExpiryState::Expired
    } else {
        thresholds_days
            .iter()
            .filter(|days| i64::from(**days) * SECONDS_PER_DAY >= remaining)
            .min()
            .map_or(ExpiryState::Valid, |days| ExpiryState::Crossed { threshold_days: *days })
    }
}

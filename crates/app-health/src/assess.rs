//! Verdict from a tracking sample, the timedatectl state and the thresholds.

use crate::model::{BlindReason, LeapStatus, NtpHealth, Thresholds, TimeSync, Tracking};


pub fn assess(tracking: &Tracking, time_sync: Option<&TimeSync>, thresholds: &Thresholds) -> NtpHealth {
    let unsynchronised = thresholds.require_synchronized && time_sync.and_then(|state| state.synchronized) == Some(false);
    let too_far = tracking.stratum.filter(|stratum| *stratum > thresholds.max_stratum);
    match (tracking.leap_status, tracking.system_time_offset) {
        (LeapStatus::NotSynchronised, _) => NtpHealth::BlindSpot(BlindReason::NotSynchronised),
        (_, None) => NtpHealth::BlindSpot(BlindReason::NoOffset),
        (_, Some(offset)) if offset.abs() > thresholds.max_offset_seconds => NtpHealth::Drift { offset },
        _ => match too_far {
            Some(stratum) => NtpHealth::Stratum { stratum },
            None if unsynchronised => NtpHealth::Unsynchronised,
            None => NtpHealth::Healthy,
        },
    }
}

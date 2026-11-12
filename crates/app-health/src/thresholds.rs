//! Threshold file.

use crate::error::NtpError;
use crate::limits::{MAX_OFFSET_SECONDS_LIMIT, MAX_STRATUM_LIMIT, MIN_OFFSET_SECONDS_EXCLUSIVE, MIN_STRATUM_LIMIT};
use crate::model::Thresholds;
use core_config::parse::parse_document;


pub fn load_thresholds(text: &str, file: &str) -> Result<Thresholds, NtpError> {
    let thresholds: Thresholds = parse_document(text, file)?;
    let offset_ok = thresholds.max_offset_seconds > MIN_OFFSET_SECONDS_EXCLUSIVE && thresholds.max_offset_seconds <= MAX_OFFSET_SECONDS_LIMIT;
    let stratum_ok = (MIN_STRATUM_LIMIT..=MAX_STRATUM_LIMIT).contains(&thresholds.max_stratum);
    if !offset_ok {
        Err(NtpError::OutOfRange { field: "max_offset_seconds" })
    } else if !stratum_ok {
        Err(NtpError::OutOfRange { field: "max_stratum" })
    } else {
        Ok(thresholds)
    }
}

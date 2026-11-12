pub use crate::suite::types::TestResult;
use app_health::model::{LeapStatus, Thresholds, Tracking};


pub const SYNCHRONISED: &str = include_str!("../fixtures/synchronised.csv");


pub const UNSYNCHRONISED: &str = include_str!("../fixtures/unsynchronised.csv");


pub const MAX_BYTES: u64 = 4096;


pub const LIMIT_OFFSET: f64 = 0.5;


pub const LIMIT_STRATUM: u32 = 5;


pub const THRESHOLDS: Thresholds = Thresholds {
    max_offset_seconds: LIMIT_OFFSET,
    max_stratum: LIMIT_STRATUM,
    require_synchronized: true,
};


pub fn tracking(offset: Option<f64>, stratum: Option<u32>, leap_status: LeapStatus) -> Tracking {
    Tracking {
        reference_id: "A9FE0101".to_string(),
        reference_name: None,
        stratum,
        system_time_offset: offset,
        last_offset: None,
        rms_offset: None,
        frequency: None,
        residual_frequency: None,
        skew: None,
        root_delay: None,
        root_dispersion: None,
        update_interval: None,
        leap_status,
        rejected_fields: 0,
    }
}

//! Default caps.

use crate::model::Limits;


pub const DEFAULT_MAX_BYTES: u64 = 1_048_576;


pub const DEFAULT_MAX_ATTRIBUTES: usize = 256;


pub const DEFAULT_MAX_UPS_LINES: usize = 512;


pub const MAX_THRESHOLDS_BYTES: usize = 4096;


pub const DEFAULT_MIN_BATTERY_CHARGE: u8 = 50;


pub const DEFAULT_MIN_RUNTIME_SECONDS: u32 = 300;


pub fn default_min_battery_charge() -> u8 {
    DEFAULT_MIN_BATTERY_CHARGE
}


pub fn default_min_runtime_seconds() -> u32 {
    DEFAULT_MIN_RUNTIME_SECONDS
}


pub fn default_limits() -> Limits {
    Limits {
        max_bytes: DEFAULT_MAX_BYTES,
        max_attributes: DEFAULT_MAX_ATTRIBUTES,
    }
}

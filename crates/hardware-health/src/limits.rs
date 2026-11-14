//! Default caps.

use crate::model::{Limits, RedfishLimits};


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


pub const DEFAULT_MAX_SENSORS: usize = 256;


pub const MAX_SCALAR_BYTES: usize = 128;


pub const MAX_NESTING_DEPTH: usize = 32;


pub fn default_redfish_limits() -> RedfishLimits {
    RedfishLimits {
        max_bytes: DEFAULT_MAX_BYTES,
        max_sensors: DEFAULT_MAX_SENSORS,
    }
}


pub fn default_limits() -> Limits {
    Limits {
        max_bytes: DEFAULT_MAX_BYTES,
        max_attributes: DEFAULT_MAX_ATTRIBUTES,
    }
}


pub const MAX_DEVICES: usize = 512;


pub const MAX_DEVICES_BYTES: usize = 262_144;


pub const MAX_PATH_TEXT_BYTES: usize = 4096;


pub const MIN_TIMEOUT_MS: u64 = 1000;


pub const MAX_TIMEOUT_MS: u64 = 60_000;


pub const MAX_USERNAME_CHARS: usize = 64;


pub const MAX_MEMBERS: usize = 64;


pub const MAX_ID_BYTES: usize = 128;


pub const HTTP_OK: u16 = 200;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const AUTH_CAPACITY: usize = 1536;


pub const CHASSIS_COLLECTION: &str = "/redfish/v1/Chassis";


pub const SYSTEMS_COLLECTION: &str = "/redfish/v1/Systems";


pub const ACCOUNTS_COLLECTION: &str = "/redfish/v1/AccountService/Accounts";


pub const ADMINISTRATOR_ROLE: &str = "Administrator";


pub const MIN_PORT: u16 = 1;

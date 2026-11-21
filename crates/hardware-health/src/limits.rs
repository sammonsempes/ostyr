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


pub const MAX_SCAN_BYTES: u64 = 262_144;


pub const MAX_SCAN_DEVICES: usize = 64;


pub const MAX_DEVICE_NAME_BYTES: usize = 64;


pub const MAX_DEVICE_TYPE_BYTES: usize = 32;


pub const MAX_SETTINGS_BYTES: usize = 4096;


pub const MIN_DEADLINE_SECONDS: u64 = 1;


pub const MAX_DEADLINE_SECONDS: u64 = 120;


pub const DEFAULT_DEADLINE_SECONDS: u64 = 30;


pub const MIN_ROUND_DEADLINE_SECONDS: u64 = 1;


pub const MAX_ROUND_DEADLINE_SECONDS: u64 = 3600;


pub const DEFAULT_ROUND_DEADLINE_SECONDS: u64 = 600;


pub const MAX_JSON_NODES: usize = 32_768;


pub fn default_deadline_seconds() -> u64 {
    DEFAULT_DEADLINE_SECONDS
}


pub fn default_round_deadline_seconds() -> u64 {
    DEFAULT_ROUND_DEADLINE_SECONDS
}


pub const MAX_UPS_SETTINGS_BYTES: usize = 32_768;


pub const MAX_UPS_TARGETS: usize = 64;


pub const MAX_TARGET_BYTES: usize = 300;


pub const MAX_UPS_NAME_BYTES: usize = 32;


pub const MAX_DNS_NAME_BYTES: usize = 253;


pub const MAX_DNS_LABEL_BYTES: usize = 63;


pub const MAX_PORT_DIGITS: usize = 5;


pub const IPV4_OCTETS: usize = 4;


pub const MAX_OCTET_DIGITS: usize = 3;


pub const DEFAULT_UPS_PORT: &str = "3493";

//! Every cap of the crate.

pub const DEFAULT_MAX_RINGS: usize = 32;


pub const DEFAULT_MAX_GROUPS: usize = 1024;


pub const DEFAULT_MAX_DEVICES: usize = 100_000;


pub const PERCENT: usize = 100;


/// Caps checked when a policy loads (`max_groups`, and `max_devices` over all groups) and on every call (`max_rings`, `max_devices`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloutLimits {
    pub max_rings: usize,
    pub max_groups: usize,
    pub max_devices: usize,
}


impl Default for RolloutLimits {
    fn default() -> Self {
        Self {
            max_rings: DEFAULT_MAX_RINGS,
            max_groups: DEFAULT_MAX_GROUPS,
            max_devices: DEFAULT_MAX_DEVICES,
        }
    }
}

use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("ring `{ring}` names the unknown group `{group}`")]
    UnknownGroup { ring: String, group: String },
    #[error("ring `{ring}` names no device")]
    EmptyRing { ring: String },
    #[error("device `{device}` is in the rings `{first}` and `{second}`")]
    DeviceInTwoRings { device: String, first: String, second: String },
    #[error("device `{device}` is in the groups `{first}` and `{second}`")]
    DeviceInTwoGroups { device: String, first: String, second: String },
    #[error("the ring name `{ring}` is used twice")]
    DuplicateRing { ring: String },
    #[error("ring `{ring}` allows {percent} percent of failures, over 100")]
    PercentOver { ring: String, percent: usize },
    #[error("too many {what}: the cap is {max}")]
    TooMany { what: &'static str, max: usize },
}


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("invalid rollout policy: {0}")]
    Invalid(#[from] ValidationError),
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum RolloutError {
    #[error("a state of tenant `{found}` was given for the policy of tenant `{expected}`")]
    TenantMismatch { expected: String, found: String },
    #[error("a state names the ring `{ring}` which is not in the policy")]
    UnknownRingState { ring: String },
    #[error("two states were given for the ring `{ring}`")]
    DuplicateRingState { ring: String },
    #[error("two states were given for the device `{device}`")]
    DuplicateDeviceState { device: String },
}

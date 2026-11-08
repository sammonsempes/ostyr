use std::net::IpAddr;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CheckError {
    #[error("`{field}` must be between {min} and {max}, got {value}")]
    OutOfRange { field: &'static str, value: u64, min: u64, max: u64 },
    #[error("`{field}` must be 1 to {max} characters without control characters")]
    BadText { field: &'static str, max: usize },
    #[error("`{field}` has a duplicate entry `{value}`")]
    Duplicate { field: &'static str, value: String },
    #[error("`timeout_seconds` ({timeout}) must not exceed `interval_seconds` ({interval})")]
    TimeoutAboveInterval { timeout: u64, interval: u64 },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    Private,
    LinkLocal,
    UniqueLocal,
    Multicast,
    Unspecified,
    Metadata,
}


#[derive(Debug, Error)]
pub enum GuardError {
    #[error("address {address} is refused: {class:?} and not in the declared scope")]
    Refused { address: IpAddr, class: AddressClass },
}

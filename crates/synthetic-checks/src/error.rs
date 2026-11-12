use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CheckError {
    #[error("`{field}` must be between {min} and {max}")]
    OutOfRange { field: &'static str, min: u64, max: u64 },
    #[error("`{field}` must be 1 to {max} characters without control characters")]
    BadText { field: &'static str, max: usize },
    #[error("`{field}` has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("`nat64_prefix` must be a network of length 32, 40, 48, 56, 64 or 96 without host bits")]
    BadNat64Prefix,
    #[error("an `icmp` target must be an IP address or a host name without port, path or leading `-`")]
    BadIcmpTarget,
    #[error("`timeout_seconds` must not exceed `interval_seconds`")]
    TimeoutAboveInterval,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    Private,
    LinkLocal,
    UniqueLocal,
    Multicast,
    Unspecified,
    Reserved,
    Metadata,
}


#[derive(Debug, Error)]
pub enum GuardError {
    #[error("address {address} is refused: {class:?} and not in the declared scope")]
    Refused { address: IpAddr, class: AddressClass },
    #[error("the declared NAT64 prefix is invalid")]
    BadPrefix(#[source] CheckError),
}


#[derive(Debug, Error)]
pub enum ProbeError {
    #[error(transparent)]
    Refused(#[from] GuardError),
    #[error("name resolution failed")]
    Resolve(#[source] std::io::Error),
    #[error("transport failed")]
    Transport(#[source] std::io::Error),
    #[error("more than {max} foreign ICMP packets arrived before the reply")]
    ForeignFlood { max: usize },
    #[error("the {limit:?} check deadline passed")]
    Timeout { limit: Duration },
    #[error("more than {max} redirects")]
    TooManyRedirects { max: usize },
    #[error("target `{target}` is not a usable http or https URL")]
    BadTarget { target: String },
    #[error("redirect location is not a valid URL")]
    BadRedirect(#[source] url::ParseError),
    #[error("redirect location exceeds {max} bytes")]
    RedirectTooLong { max: usize },
    #[error(transparent)]
    BadLimits(#[from] CheckError),
    #[error("no address to connect to")]
    NoAddress,
    #[error("certificate chain exceeds {max_certs} certificates of {max_bytes} bytes")]
    ChainTooLarge { max_certs: usize, max_bytes: usize },
}


#[derive(Debug, Error)]
#[error("an unprivileged ICMP socket cannot be created: check net.ipv4.ping_group_range")]
pub struct PingSocketError(#[source] pub std::io::Error);

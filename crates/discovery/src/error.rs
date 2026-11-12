use core_config::error::ConfigError;
use core_pg::error::PgError;
use ipnet::IpNet;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("not a valid tenant name: {0}")]
    Tenant(#[from] PgError),
    #[error("the scope lists no owned range")]
    NoRanges,
    #[error("the scope lists {count} owned ranges, at most {max} are allowed")]
    TooManyRanges { count: usize, max: usize },
    #[error("owned range {range} is broader than the minimum prefix /{min_prefix}")]
    RangeTooBroad { range: IpNet, min_prefix: u8 },
    #[error("owned range {range} is an IPv4-mapped or IPv4-compatible IPv6 range, which never matches: write the IPv4 range")]
    MappedRange { range: IpNet },
    #[error("retention_days {0} is outside 1 to 400")]
    Retention(u32),
    #[error("max_edges {0} is outside 1 to 1000000")]
    MaxEdges(usize),
}

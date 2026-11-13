use cmdb::error::CmdbError;
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
    #[error("owned range {range} overlaps ::ffff:0:0/96 (IPv4-mapped, which never matches because addresses are canonicalised to IPv4) or ::/96 (IPv4-compatible, ::1/128 included, refused as deprecated and ambiguous): write the IPv4 range")]
    MappedRange { range: IpNet },
    #[error("retention_days {0} is outside 1 to 400")]
    Retention(u32),
    #[error("max_edges {0} is outside 1 to 1000000")]
    MaxEdges(usize),
    #[error("a time outside the supported calendar range")]
    Time(#[from] time::error::ComponentRange),
    #[error("a time that cannot be written as RFC 3339")]
    Format(#[from] time::error::Format),
    #[error("the observation is refused by the CMDB checks")]
    Refused(#[from] CmdbError),
}

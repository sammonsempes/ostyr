use crate::types::TenantMap;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::types::{ConfigState, LoaderFn};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;


pub const DEFAULT_ISOLATIONS_PER_HOUR: u64 = 5;


pub const DEFAULT_ISOLATIONS_PER_DAY: u64 = 20;


pub const DEFAULT_DISABLINGS_PER_HOUR: u64 = 3;


pub const DEFAULT_BLOCKS_PER_HOUR: u64 = 50;


pub const DEFAULT_BLOCK_MAX_DAYS: u64 = 7;


pub const DEFAULT_RMM_MAX_MACHINES: u64 = 20;


pub const DEFAULT_MAX_ISOLATED_PERCENT: u64 = 2;


pub const PRIVATE_V4_A: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8);


pub const PRIVATE_V4_B: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12);


pub const PRIVATE_V4_C: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16);


pub const LOOPBACK_V4: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8);


pub const LINK_LOCAL_V4: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16);


pub const LOOPBACK_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128);


pub const UNIQUE_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7);


pub const LINK_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10);


/// Every limit, tag name and reserved range of one tenant; the defaults are the spec section 10 table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub isolations_per_hour: u64,
    pub isolations_per_day: u64,
    pub disablings_per_hour: u64,
    pub blocks_per_hour: u64,
    pub block_max_days: u64,
    pub rmm_max_machines: u64,
    pub max_isolated_percent: u64,
    pub protected_host_tags: Vec<String>,
    pub protected_account_tags: Vec<String>,
    pub reserved_ranges: Vec<IpNet>,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            isolations_per_hour: DEFAULT_ISOLATIONS_PER_HOUR,
            isolations_per_day: DEFAULT_ISOLATIONS_PER_DAY,
            disablings_per_hour: DEFAULT_DISABLINGS_PER_HOUR,
            blocks_per_hour: DEFAULT_BLOCKS_PER_HOUR,
            block_max_days: DEFAULT_BLOCK_MAX_DAYS,
            rmm_max_machines: DEFAULT_RMM_MAX_MACHINES,
            max_isolated_percent: DEFAULT_MAX_ISOLATED_PERCENT,
            protected_host_tags: ["domain-controller", "hypervisor", "critical"].map(str::to_owned).to_vec(),
            protected_account_tags: ["privileged", "break-glass", "service"].map(str::to_owned).to_vec(),
            reserved_ranges: vec![
                IpNet::V4(PRIVATE_V4_A),
                IpNet::V4(PRIVATE_V4_B),
                IpNet::V4(PRIVATE_V4_C),
                IpNet::V4(LOOPBACK_V4),
                IpNet::V4(LINK_LOCAL_V4),
                IpNet::V6(LOOPBACK_V6),
                IpNet::V6(UNIQUE_LOCAL_V6),
                IpNet::V6(LINK_LOCAL_V6),
            ],
        }
    }
}


/// The fields a tenant replaces; an absent field keeps the base value.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitOverrides {
    pub isolations_per_hour: Option<u64>,
    pub isolations_per_day: Option<u64>,
    pub disablings_per_hour: Option<u64>,
    pub blocks_per_hour: Option<u64>,
    pub block_max_days: Option<u64>,
    pub rmm_max_machines: Option<u64>,
    pub max_isolated_percent: Option<u64>,
    pub protected_host_tags: Option<Vec<String>>,
    pub protected_account_tags: Option<Vec<String>>,
    pub reserved_ranges: Option<Vec<IpNet>>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BreakerConfig {
    pub limits: Limits,
    pub tenants: TenantMap,
}


pub fn apply_overrides(base: &Limits, overrides: &LimitOverrides) -> Limits {
    Limits {
        isolations_per_hour: overrides.isolations_per_hour.unwrap_or(base.isolations_per_hour),
        isolations_per_day: overrides.isolations_per_day.unwrap_or(base.isolations_per_day),
        disablings_per_hour: overrides.disablings_per_hour.unwrap_or(base.disablings_per_hour),
        blocks_per_hour: overrides.blocks_per_hour.unwrap_or(base.blocks_per_hour),
        block_max_days: overrides.block_max_days.unwrap_or(base.block_max_days),
        rmm_max_machines: overrides.rmm_max_machines.unwrap_or(base.rmm_max_machines),
        max_isolated_percent: overrides.max_isolated_percent.unwrap_or(base.max_isolated_percent),
        protected_host_tags: overrides.protected_host_tags.clone().unwrap_or_else(|| base.protected_host_tags.clone()),
        protected_account_tags: overrides
            .protected_account_tags
            .clone()
            .unwrap_or_else(|| base.protected_account_tags.clone()),
        reserved_ranges: overrides.reserved_ranges.clone().unwrap_or_else(|| base.reserved_ranges.clone()),
    }
}


/// The limits that apply to `tenant`: the base limits with the tenant's replacements, if any.
pub fn limits_for(config: &BreakerConfig, tenant: &str) -> Limits {
    config
        .tenants
        .get(tenant)
        .map_or_else(|| config.limits.clone(), |overrides| apply_overrides(&config.limits, overrides))
}


/// One entry per section, in `Debug` form: stable, and the diff of a reload shows which section changed.
pub fn config_state(config: &BreakerConfig) -> ConfigState {
    let base = ("limits".to_owned(), format!("{:?}", config.limits));
    let tenants = config
        .tenants
        .iter()
        .map(|(tenant, overrides)| (format!("tenants.{tenant}"), format!("{overrides:?}")));
    std::iter::once(base).chain(tenants).collect()
}


pub fn breaker_loader(path: PathBuf) -> Box<LoaderFn<BreakerConfig>> {
    Box::new(move || -> Result<BreakerConfig, ConfigError> { load_file(&path) })
}

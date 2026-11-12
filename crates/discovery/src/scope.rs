use crate::error::DiscoveryError;
use crate::model::{
    Scope, ScopeFile, DEFAULT_MAX_EDGES, MAX_EDGES_CEILING, MAX_RANGES, MAX_RETENTION_DAYS, MILLIS_PER_DAY, MIN_PREFIX_V4, MIN_PREFIX_V6,
    MIN_RETENTION_DAYS,
};
use crate::types::ScopeResult;
use core_config::load::load_file;
use ipnet::{IpNet, Ipv6Net};
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;


fn check_count(count: usize) -> Result<(), DiscoveryError> {
    match count {
        0 => Err(DiscoveryError::NoRanges),
        1..=MAX_RANGES => Ok(()),
        _ => Err(DiscoveryError::TooManyRanges { count, max: MAX_RANGES }),
    }
}


fn check_prefix(range: &IpNet) -> Result<(), DiscoveryError> {
    let min_prefix = match range {
        IpNet::V4(_) => MIN_PREFIX_V4,
        IpNet::V6(_) => MIN_PREFIX_V6,
    };
    if range.prefix_len() < min_prefix {
        Err(DiscoveryError::RangeTooBroad { range: *range, min_prefix })
    } else {
        Ok(())
    }
}


const MAPPED_PREFIX: u8 = 96;


const MAPPED_SEGMENT: u16 = 0xffff;


const COMPATIBLE_BLOCK: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, MAPPED_PREFIX);


const MAPPED_BLOCK: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0, MAPPED_SEGMENT, 0, 0), MAPPED_PREFIX);


fn check_not_mapped(range: &IpNet) -> Result<(), DiscoveryError> {
    let overlaps = match range {
        IpNet::V4(_) => false,
        IpNet::V6(net) => [COMPATIBLE_BLOCK, MAPPED_BLOCK]
            .iter()
            .any(|block| block.contains(net) || net.contains(block)),
    };
    if overlaps {
        Err(DiscoveryError::MappedRange { range: *range })
    } else {
        Ok(())
    }
}


fn check_retention(days: u32) -> Result<(), DiscoveryError> {
    if (MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&days) {
        Ok(())
    } else {
        Err(DiscoveryError::Retention(days))
    }
}


fn check_edges(max_edges: usize) -> Result<(), DiscoveryError> {
    if (1..=MAX_EDGES_CEILING).contains(&max_edges) {
        Ok(())
    } else {
        Err(DiscoveryError::MaxEdges(max_edges))
    }
}


/// Checks a scope file: range count, prefixes and mapped ranges (before anything is merged, prefixes again after), retention and edge cap; ranges are masked, merged and sorted.
pub fn validate_scope(file: &ScopeFile) -> ScopeResult {
    check_count(file.owned_ranges.len())?;
    file.owned_ranges.iter().try_for_each(check_prefix)?;
    file.owned_ranges.iter().try_for_each(check_not_mapped)?;
    check_retention(file.retention_days)?;
    let max_edges = file.max_edges.unwrap_or(DEFAULT_MAX_EDGES);
    check_edges(max_edges)?;
    let masked: Vec<IpNet> = file.owned_ranges.iter().map(IpNet::trunc).collect();
    let mut ranges = IpNet::aggregate(&masked);
    ranges.iter().try_for_each(check_prefix)?;
    ranges.sort();
    Ok(Scope {
        ranges,
        retention_ms: i64::from(file.retention_days) * MILLIS_PER_DAY,
        max_edges,
    })
}


pub fn load_scope(path: &Path) -> ScopeResult {
    let file: ScopeFile = load_file(path)?;
    validate_scope(&file)
}


/// Whether `address` lies in an owned range: the ranges are disjoint and sorted, so one binary search finds the only candidate.
pub fn in_scope(scope: &Scope, address: IpAddr) -> bool {
    let after = scope.ranges.partition_point(|range| range.network() <= address);
    after
        .checked_sub(1)
        .and_then(|index| scope.ranges.get(index))
        .is_some_and(|range| range.contains(&address))
}

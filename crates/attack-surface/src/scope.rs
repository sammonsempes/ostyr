use crate::error::{Refusal, ScopeError};
use crate::model::{
    PortEntry, PortRange, Scope, ScopeFile, ScopeKind, TargetEntry, MAX_FILE_BYTES, MAX_PORTS, MAX_PORT_ENTRIES, MAX_RATE, MAX_REFERENCE_BYTES,
    MAX_TARGETS, MIN_PORT, MIN_PREFIX_V4, MIN_PREFIX_V6, MIN_RATE,
};
use crate::text::{shown, valid_hostname, valid_text};
use crate::types::ScopeResult;
use core_config::parse::{parse_document, read_text_capped};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;


const PRIVATE_BLOCKS: [IpNet; 4] = [
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16)),
    IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)),
];


const EXTERNAL_BLOCKED: [IpNet; 15] = [
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 2, 0), 24)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(198, 51, 100, 0), 24)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(203, 0, 113, 0), 24)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4)),
    IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)),
];


const GLOBAL_V6: IpNet = IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3));


const V4_ADDRESS_BITS: u32 = 32;


const V6_ADDRESS_BITS: u32 = 128;


const PORT_SEPARATOR: char = '-';


pub enum Target {
    Net(IpNet),
    Name(String),
}


fn refuse(file: &str, field: &str, refusal: Refusal) -> ScopeError {
    ScopeError::Refused {
        file: file.to_string(),
        field: field.to_string(),
        refusal,
    }
}


fn check_count(count: usize, max: usize) -> Result<(), Refusal> {
    match count {
        0 => Err(Refusal::Empty),
        _ if count > max => Err(Refusal::TooMany { count, max }),
        _ => Ok(()),
    }
}


fn check_rate(rate: u32) -> Result<(), Refusal> {
    if (MIN_RATE..=MAX_RATE).contains(&rate) {
        Ok(())
    } else {
        Err(Refusal::Outside {
            value: rate,
            min: MIN_RATE,
            max: MAX_RATE,
        })
    }
}


fn parse_target(value: &str) -> Option<Target> {
    value
        .parse::<IpNet>()
        .ok()
        .or_else(|| value.parse::<IpAddr>().ok().map(IpNet::from))
        .map(|net| Target::Net(net.trunc()))
        .or_else(|| valid_hostname(value).then(|| Target::Name(value.to_string())))
}


fn check_prefix(net: &IpNet, value: &str) -> Result<(), Refusal> {
    let min_prefix = match net {
        IpNet::V4(_) => MIN_PREFIX_V4,
        IpNet::V6(_) => MIN_PREFIX_V6,
    };
    (net.prefix_len() >= min_prefix).then_some(()).ok_or_else(|| Refusal::TooBroad {
        shown: shown(value),
        min_prefix,
    })
}


fn overlaps(block: &IpNet, net: &IpNet) -> bool {
    block.contains(net) || net.contains(block)
}


fn permitted(net: &IpNet, kind: ScopeKind) -> bool {
    match (kind, net) {
        (ScopeKind::Internal, _) => PRIVATE_BLOCKS.iter().any(|block| block.contains(net)),
        (ScopeKind::External, IpNet::V4(_)) => !EXTERNAL_BLOCKED.iter().any(|block| overlaps(block, net)),
        (ScopeKind::External, IpNet::V6(_)) => GLOBAL_V6.contains(net) && !EXTERNAL_BLOCKED.iter().any(|block| overlaps(block, net)),
    }
}


fn check_net(net: &IpNet, kind: ScopeKind, value: &str) -> Result<(), Refusal> {
    check_prefix(net, value)?;
    permitted(net, kind)
        .then_some(())
        .ok_or_else(|| Refusal::WrongClass { shown: shown(value), kind })
}


fn check_value(entry: &TargetEntry, kind: ScopeKind) -> Result<Target, Refusal> {
    let target = parse_target(&entry.value).ok_or_else(|| Refusal::BadTarget { shown: shown(&entry.value) })?;
    if let Target::Net(net) = &target {
        check_net(net, kind, &entry.value)?;
    }
    Ok(target)
}


fn check_reference(entry: &TargetEntry) -> Result<(), Refusal> {
    valid_text(&entry.ownership.reference, MAX_REFERENCE_BYTES)
        .then_some(())
        .ok_or_else(|| Refusal::BadText {
            shown: shown(&entry.ownership.reference),
            max: MAX_REFERENCE_BYTES,
        })
}


fn check_target(entry: &TargetEntry, kind: ScopeKind, file: &str, index: usize) -> Result<Target, ScopeError> {
    let target = check_value(entry, kind).map_err(|refusal| refuse(file, &format!("targets[{index}].value"), refusal))?;
    check_reference(entry).map_err(|refusal| refuse(file, &format!("targets[{index}].ownership.reference"), refusal))?;
    Ok(target)
}


fn address_count(net: &IpNet) -> u128 {
    1u128 << (net.max_prefix_len() - net.prefix_len())
}


/// The merged ranges may cover at most as many addresses as one /16 (IPv4) plus one /48 (IPv6): two adjacent /16 or a /16 and a /24 are refused.
fn check_total(ranges: &[IpNet]) -> Result<(), Refusal> {
    let limit_v4 = 1u128 << (V4_ADDRESS_BITS - u32::from(MIN_PREFIX_V4));
    let limit_v6 = 1u128 << (V6_ADDRESS_BITS - u32::from(MIN_PREFIX_V6));
    let (total_v4, total_v6) = ranges.iter().fold((0u128, 0u128), |(v4, v6), net| match net {
        IpNet::V4(_) => (v4 + address_count(net), v6),
        IpNet::V6(_) => (v4, v6 + address_count(net)),
    });
    if total_v4 > limit_v4 {
        Err(Refusal::TooWide {
            count: total_v4,
            max: limit_v4,
        })
    } else if total_v6 > limit_v6 {
        Err(Refusal::TooWide {
            count: total_v6,
            max: limit_v6,
        })
    } else {
        Ok(())
    }
}


fn parse_port(text: &str) -> Option<u16> {
    text.chars()
        .all(|next| next.is_ascii_digit())
        .then(|| text.parse::<u16>().ok())
        .flatten()
        .filter(|port| *port >= MIN_PORT)
}


fn port_range(entry: &PortEntry) -> Option<PortRange> {
    match entry {
        PortEntry::Number(number) => u16::try_from(*number)
            .ok()
            .filter(|port| *port >= MIN_PORT)
            .map(|port| PortRange { first: port, last: port }),
        PortEntry::Text(text) => match text.split_once(PORT_SEPARATOR) {
            Some((first, last)) => parse_port(first)
                .zip(parse_port(last))
                .filter(|(low, high)| low <= high)
                .map(|(low, high)| PortRange { first: low, last: high }),
            None => parse_port(text).map(|port| PortRange { first: port, last: port }),
        },
    }
}


fn entry_text(entry: &PortEntry) -> String {
    match entry {
        PortEntry::Number(number) => number.to_string(),
        PortEntry::Text(text) => text.clone(),
    }
}


fn check_port(entry: &PortEntry, file: &str, index: usize) -> Result<PortRange, ScopeError> {
    port_range(entry).ok_or_else(|| {
        refuse(
            file,
            &format!("ports[{index}]"),
            Refusal::BadPort {
                shown: shown(&entry_text(entry)),
            },
        )
    })
}


fn merge_ports(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort();
    ranges.into_iter().fold(Vec::new(), |mut merged: Vec<PortRange>, next| {
        match merged.last_mut() {
            Some(last) if u32::from(next.first) <= u32::from(last.last) + 1 => last.last = last.last.max(next.last),
            _ => merged.push(next),
        }
        merged
    })
}


fn port_count(ranges: &[PortRange]) -> u32 {
    ranges.iter().map(|range| u32::from(range.last) - u32::from(range.first) + 1).sum()
}


fn check_ports(entries: &[PortEntry], file: &str) -> Result<Vec<PortRange>, ScopeError> {
    check_count(entries.len(), MAX_PORT_ENTRIES).map_err(|refusal| refuse(file, "ports", refusal))?;
    let parsed = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| check_port(entry, file, index))
        .collect::<Result<Vec<_>, _>>()?;
    let merged = merge_ports(parsed);
    let count = port_count(&merged);
    (count <= MAX_PORTS)
        .then_some(merged)
        .ok_or_else(|| refuse(file, "ports", Refusal::TooManyPorts { count, max: MAX_PORTS }))
}


fn target_text(target: &Target) -> String {
    match target {
        Target::Net(net) => net.to_string(),
        Target::Name(name) => name.clone(),
    }
}


/// Checks every rule of a scope file; `file` only labels errors. Ranges are masked and merged, hostnames and targets sorted and deduplicated.
pub fn validate_scope(parsed: &ScopeFile, file: &str) -> ScopeResult {
    check_rate(parsed.rate_per_second).map_err(|refusal| refuse(file, "rate_per_second", refusal))?;
    let ports = check_ports(&parsed.ports, file)?;
    check_count(parsed.targets.len(), MAX_TARGETS).map_err(|refusal| refuse(file, "targets", refusal))?;
    let targets = parsed
        .targets
        .iter()
        .enumerate()
        .map(|(index, entry)| check_target(entry, parsed.kind, file, index))
        .collect::<Result<Vec<_>, _>>()?;
    let nets: Vec<IpNet> = targets
        .iter()
        .filter_map(|target| match target {
            Target::Net(net) => Some(*net),
            Target::Name(_) => None,
        })
        .collect();
    let mut ranges = IpNet::aggregate(&nets);
    check_total(&ranges).map_err(|refusal| refuse(file, "targets", refusal))?;
    ranges.sort();
    let hostnames: BTreeSet<String> = targets
        .iter()
        .filter_map(|target| match target {
            Target::Name(name) => Some(name.clone()),
            Target::Net(_) => None,
        })
        .collect();
    let listed: BTreeSet<String> = targets.iter().map(target_text).collect();
    Ok(Scope {
        kind: parsed.kind,
        rate_per_second: parsed.rate_per_second,
        ports,
        ranges,
        hostnames: hostnames.into_iter().collect(),
        targets: listed.into_iter().collect(),
    })
}


/// Reads at most `MAX_FILE_BYTES` from `reader`, parses strictly and validates; `file` only labels errors.
pub fn parse_scope(reader: &mut dyn Read, file: &str) -> ScopeResult {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    let parsed = parse_document::<ScopeFile>(&text, file)?;
    validate_scope(&parsed, file)
}


pub fn load_scope(path: &Path) -> ScopeResult {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| core_config::error::ConfigError::Io { file: file.clone(), source })?;
    parse_scope(&mut handle, &file)
}


/// Whether `address` (IPv4-mapped form canonicalised) lies in a target range: the ranges are disjoint and sorted, so one binary search suffices.
pub fn in_ranges(scope: &Scope, address: IpAddr) -> bool {
    let canonical = address.to_canonical();
    let after = scope.ranges.partition_point(|range| range.network() <= canonical);
    after
        .checked_sub(1)
        .and_then(|index| scope.ranges.get(index))
        .is_some_and(|range| range.contains(&canonical))
}


pub fn port_allowed(scope: &Scope, port: u16) -> bool {
    scope.ports.iter().any(|range| (range.first..=range.last).contains(&port))
}

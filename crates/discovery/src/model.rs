use crate::types::{EdgeMap, Millis, SeenIndex};
use core_pg::scope::TenantScope;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};


pub const MAX_RANGES: usize = 1024;


pub const MIN_PREFIX_V4: u8 = 8;


pub const MIN_PREFIX_V6: u8 = 32;


pub const MIN_RETENTION_DAYS: u32 = 1;


pub const MAX_RETENTION_DAYS: u32 = 400;


pub const DEFAULT_MAX_EDGES: usize = 100_000;


pub const MAX_EDGES_CEILING: usize = 1_000_000;


pub const MILLIS_PER_DAY: Millis = 86_400_000;


pub const WELL_KNOWN_PORT_LIMIT: u16 = 1024;


pub const MAX_SERVICES_PER_CANDIDATE: usize = 32;


pub const PROTOCOL_SCTP: u8 = 132;


pub const LOWEST_KEY: EdgeKey = EdgeKey {
    source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    port: 0,
    protocol: 0,
};


/// The scope file of one tenant; `max_edges` defaults to `DEFAULT_MAX_EDGES`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeFile {
    pub owned_ranges: Vec<IpNet>,
    pub retention_days: u32,
    pub max_edges: Option<usize>,
}


/// A checked scope: disjoint ranges sorted by address, the retention in milliseconds and the edge cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub ranges: Vec<IpNet>,
    pub retention_ms: Millis,
    pub max_edges: usize,
}


/// `source` is the client side and `destination` the service side; `port` is the service port, 0 for a protocol without ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct EdgeKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub port: u16,
    pub protocol: u8,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EdgeStats {
    pub first_seen_ms: Millis,
    pub last_seen_ms: Millis,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Counters {
    pub recorded: u64,
    pub out_of_scope: u64,
    pub wrong_tenant: u64,
    pub evicted: u64,
    pub expired: u64,
    pub clamped_times: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Recorded,
    OutOfScope,
    WrongTenant,
}


/// The map of one tenant: the edges and the index ordered by last seen move together, so they are only changed through `map`.
#[derive(Debug, Clone)]
pub struct ServiceMap {
    pub(crate) tenant: TenantScope,
    pub(crate) scope: Scope,
    pub(crate) edges: EdgeMap,
    pub(crate) by_last_seen: SeenIndex,
    pub(crate) counters: Counters,
}


/// The managed addresses the caller knows, in canonical form (an IPv4-mapped IPv6 address is its IPv4 address).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnownDevices {
    pub addresses: BTreeSet<IpAddr>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ServiceRef {
    pub port: u16,
    pub protocol: u8,
}


/// An owned address seen in the map and not known; `services` is cut at `MAX_SERVICES_PER_CANDIDATE`, the rest counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub address: IpAddr,
    pub first_seen_ms: Millis,
    pub last_seen_ms: Millis,
    pub services: Vec<ServiceRef>,
    pub services_omitted: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gathered {
    pub first_seen_ms: Millis,
    pub last_seen_ms: Millis,
    pub services: BTreeSet<ServiceRef>,
}

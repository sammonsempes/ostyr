use ipnet::IpNet;
use serde::Deserialize;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::IpAddr;


pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_TARGETS: usize = 1024;


pub const MAX_PORT_ENTRIES: usize = 1024;


pub const MAX_PORTS: u32 = 1024;


pub const MIN_RATE: u32 = 1;


pub const MAX_RATE: u32 = 1000;


pub const MIN_PORT: u16 = 1;


pub const MIN_PREFIX_V4: u8 = 16;


pub const MIN_PREFIX_V6: u8 = 48;


pub const MAX_REFERENCE_BYTES: usize = 128;


pub const DEFAULT_MAX_BYTES: u64 = 33_554_432;


pub const DEFAULT_MAX_LINES: usize = 200_000;


pub const DEFAULT_MAX_LINE_BYTES: usize = 1024;


pub const MAX_TIMESTAMP_BYTES: usize = 64;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    External,
    Internal,
}


impl Display for ScopeKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            ScopeKind::External => "external",
            ScopeKind::Internal => "internal",
        })
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipMethod {
    DnsTxt,
    Attestation,
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub method: OwnershipMethod,
    pub reference: String,
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    pub value: String,
    pub ownership: Ownership,
}


#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortEntry {
    Number(u64),
    Text(String),
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeFile {
    pub kind: ScopeKind,
    pub rate_per_second: u32,
    pub ports: Vec<PortEntry>,
    pub targets: Vec<TargetEntry>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}


#[derive(Debug, Clone)]
pub struct Scope {
    pub kind: ScopeKind,
    pub rate_per_second: u32,
    pub ports: Vec<PortRange>,
    pub ranges: Vec<IpNet>,
    pub targets: Vec<String>,
}


#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_lines: usize,
    pub max_line_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: DEFAULT_MAX_BYTES,
            max_lines: DEFAULT_MAX_LINES,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub ip: IpAddr,
    pub port: u16,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub malformed: usize,
    pub out_of_scope: usize,
    pub duplicate: usize,
    pub oversize_lines: usize,
    pub truncated: bool,
}


#[derive(Debug, Clone, Default)]
pub struct Report {
    pub found: Vec<Found>,
    pub counts: Counts,
}

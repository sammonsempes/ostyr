use crate::error::CheckError;
use crate::load::within;
use ipnet::{IpNet, Ipv6Net};
use serde::Deserialize;


pub const MAX_CHECKS: usize = 1000;


pub const MAX_SCOPE_ENTRIES: usize = 256;


pub const MAX_NAME_LEN: usize = 128;


pub const MAX_TARGET_LEN: usize = 2048;


pub const MAX_LOCATIONS: usize = 16;


pub const MAX_LOCATION_LEN: usize = 64;


pub const MAX_CERT_THRESHOLDS: usize = 8;


pub const MAX_CERT_DAYS: u64 = 3650;


pub const MIN_INTERVAL_SECONDS: u64 = 10;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_TIMEOUT_SECONDS: u64 = 300;


pub const MAX_CONSECUTIVE_FAILURES: u64 = 100;


pub const DEFAULT_INTERVAL_SECONDS: u64 = 60;


pub const DEFAULT_TIMEOUT_SECONDS: u64 = 10;


pub const DEFAULT_CONSECUTIVE_FAILURES: u64 = 3;


pub const DEFAULT_MIN_FAILING_LOCATIONS: u64 = 1;


pub const DEFAULT_CERT_DAYS: [u64; 3] = [30, 14, 7];


pub const MAX_BODY_EXCERPT_BYTES: usize = 512;


pub const NAT64_PREFIX_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Http,
    Tcp,
    Icmp,
    Dns,
    Tls,
}


/// One validated check; deserialised through `RawCheck` so every limit error carries the file and line of its entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawCheck")]
pub struct Check {
    pub name: String,
    pub kind: CheckKind,
    pub target: String,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub consecutive_failures: FailureRun,
    pub locations: Vec<String>,
    pub min_failing_locations: u64,
    pub certificate_days: Vec<CertificateDay>,
    pub nat64_prefix: Option<Ipv6Net>,
}


/// A validated number of consecutive failures, 1 to `MAX_CONSECUTIVE_FAILURES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureRun(u64);


/// A validated certificate threshold in days, 1 to `MAX_CERT_DAYS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateDay(u64);


pub fn failure_run_len(run: FailureRun) -> usize {
    run.0 as usize
}


pub fn certificate_day_value(day: CertificateDay) -> u64 {
    day.0
}


impl TryFrom<u64> for FailureRun {
    type Error = CheckError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        within("consecutive_failures", value, 1, MAX_CONSECUTIVE_FAILURES)?;
        Ok(FailureRun(value))
    }
}


impl TryFrom<u64> for CertificateDay {
    type Error = CheckError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        within("certificate_days", value, 1, MAX_CERT_DAYS)?;
        Ok(CertificateDay(value))
    }
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCheck {
    pub name: String,
    pub kind: CheckKind,
    pub target: String,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_consecutive_failures")]
    pub consecutive_failures: u64,
    pub locations: Vec<String>,
    #[serde(default = "default_min_failing_locations")]
    pub min_failing_locations: u64,
    #[serde(default = "default_certificate_days")]
    pub certificate_days: Vec<u64>,
    #[serde(default)]
    pub nat64_prefix: Option<Ipv6Net>,
}


pub fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECONDS
}


pub fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}


pub fn default_consecutive_failures() -> u64 {
    DEFAULT_CONSECUTIVE_FAILURES
}


pub fn default_min_failing_locations() -> u64 {
    DEFAULT_MIN_FAILING_LOCATIONS
}


pub fn default_certificate_days() -> Vec<u64> {
    DEFAULT_CERT_DAYS.to_vec()
}


/// The checks plus the declared scope: networks a check may reach although they are private or reserved.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawCheckFile")]
pub struct CheckFile {
    pub scope: Vec<IpNet>,
    pub ca_file: Option<String>,
    pub checks: Vec<Check>,
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCheckFile {
    #[serde(default)]
    pub scope: Vec<IpNet>,
    #[serde(default)]
    pub ca_file: Option<String>,
    pub checks: Vec<Check>,
}


/// The latest results of one location, oldest first; `true` is a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationHistory {
    pub location: String,
    pub results: Vec<bool>,
}


/// One probe result; the body is never kept in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub check: String,
    pub location: String,
    pub succeeded: bool,
    pub body_excerpt: String,
}

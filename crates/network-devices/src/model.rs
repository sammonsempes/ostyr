use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;


pub const DEFAULT_MAX_TRAPS_PER_MINUTE: u32 = 600;


pub const DEFAULT_MAX_FLOW_RECORDS_PER_SECOND: u32 = 10_000;


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFile {
    #[serde(deserialize_with = "crate::bounded::bounded_devices")]
    pub devices: Vec<Device>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Switch,
    Router,
    Firewall,
    AccessPoint,
    Printer,
    Ups,
    Other,
}


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: String,
    pub tenant: String,
    pub kind: DeviceKind,
    #[serde(deserialize_with = "crate::bounded::bounded_addresses")]
    pub addresses: Vec<IpAddr>,
    #[serde(default)]
    pub agent_managed: bool,
    pub snmp: Option<SnmpSettings>,
    #[serde(default)]
    pub volumes: Volumes,
    pub stale_after_seconds: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    AuthPriv,
    AuthNoPriv,
    NoAuthNoPriv,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProtocol {
    Sha256,
    Sha384,
    Sha512,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivProtocol {
    Aes128,
    Aes192,
    Aes256,
}


/// `credentials` is a reference relative to the secrets directory; the file it names is never opened by this crate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnmpSettings {
    pub polling: bool,
    pub version: SnmpVersion,
    #[serde(default)]
    pub accept_insecure: bool,
    pub security_level: Option<SecurityLevel>,
    pub auth_protocol: Option<AuthProtocol>,
    pub priv_protocol: Option<PrivProtocol>,
    pub credentials: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volumes {
    pub max_traps_per_minute: u32,
    pub max_flow_records_per_second: u32,
}


impl Default for Volumes {
    fn default() -> Self {
        Self {
            max_traps_per_minute: DEFAULT_MAX_TRAPS_PER_MINUTE,
            max_flow_records_per_second: DEFAULT_MAX_FLOW_RECORDS_PER_SECOND,
        }
    }
}


/// An insecure SNMP version accepted for a named device; the CMDB slice stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub tenant: String,
    pub device: String,
    pub version: SnmpVersion,
}


impl fmt::Display for Warning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tenant {:?} device {:?}: insecure SNMP {:?} accepted by the device file",
            self.tenant, self.device, self.version
        )
    }
}


#[derive(Debug, Clone, Default)]
pub struct LoadResult {
    pub devices: Vec<Device>,
    pub warnings: Vec<Warning>,
}


/// What the polling slice will poll: one entry per polled device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    pub tenant: String,
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub version: SnmpVersion,
    pub credentials: String,
}


#[derive(Debug, Default)]
pub struct Claims {
    pub names: BTreeSet<(String, String)>,
    pub addresses: BTreeSet<(String, IpAddr)>,
}

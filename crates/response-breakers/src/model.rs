use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitName {
    IsolationsPerHour,
    IsolationsPerDay,
    DisablingsPerHour,
    BlocksPerHour,
    BlockDuration,
    RmmMachines,
    FleetIsolatedPercent,
}


pub const ALL_LIMITS: [LimitName; 7] = [
    LimitName::IsolationsPerHour,
    LimitName::IsolationsPerDay,
    LimitName::DisablingsPerHour,
    LimitName::BlocksPerHour,
    LimitName::BlockDuration,
    LimitName::RmmMachines,
    LimitName::FleetIsolatedPercent,
];


pub fn limit_label(limit: LimitName) -> &'static str {
    match limit {
        LimitName::IsolationsPerHour => "isolations_per_hour",
        LimitName::IsolationsPerDay => "isolations_per_day",
        LimitName::DisablingsPerHour => "disablings_per_hour",
        LimitName::BlocksPerHour => "blocks_per_hour",
        LimitName::BlockDuration => "block_duration",
        LimitName::RmmMachines => "rmm_machines",
        LimitName::FleetIsolatedPercent => "fleet_isolated_percent",
    }
}


impl fmt::Display for LimitName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(limit_label(*self))
    }
}


impl FromStr for LimitName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        ALL_LIMITS
            .iter()
            .find(|limit| limit_label(**limit) == text)
            .copied()
            .ok_or_else(|| text.to_owned())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Counter {
    Isolation,
    Disabling,
    Block,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub tags: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    IsolateEndpoint { fleet_size: u64, isolated_now: u64 },
    DisableAccount,
    BlockIp { address: IpAddr, duration: Duration },
    BlockDomain { duration: Duration },
    RmmScript { machines: u64 },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedAction {
    pub tenant: String,
    pub request_id: String,
    pub kind: ActionKind,
    pub target: Target,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    LimitReached { limit: LimitName, current: u64, max: u64 },
    ProtectedTag { tag: String },
    ReservedRange { range: String },
    RecordFailed { message: String },
}


impl fmt::Display for Reason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::LimitReached { limit, current, max } => write!(formatter, "limit {limit} reached: {current} of {max}"),
            Reason::ProtectedTag { tag } => write!(formatter, "protected target tagged `{tag}`"),
            Reason::ReservedRange { range } => write!(formatter, "address inside the reserved range {range}"),
            Reason::RecordFailed { message } => write!(formatter, "cannot record the action durably: {message}"),
        }
    }
}


/// `overridden` lists the limits this action passed only thanks to an administrator override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed { overridden: Vec<LimitName> },
    NeedsApproval { reason: Reason, alert_on_call: bool },
}


impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Allowed { overridden } if overridden.is_empty() => write!(formatter, "allowed"),
            Verdict::Allowed { overridden } => write!(
                formatter,
                "allowed only by override of {}",
                overridden.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
            ),
            Verdict::NeedsApproval { reason, alert_on_call } => write!(formatter, "needs-approval alert={alert_on_call} reason={reason}"),
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub limit: LimitName,
    pub current: u64,
    pub max: u64,
}

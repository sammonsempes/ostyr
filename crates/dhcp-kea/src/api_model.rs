use crate::types::{AtLookupFn, MacLookupFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct DhcpBackend {
    pub at: AtLookupFn,
    pub by_mac: MacLookupFn,
}


/// `GET /dhcp/leases/at` query: every value is checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AtQuery {
    /// IPv4 or IPv6 address, no zone id.
    pub address: Option<String>,
    /// Unix seconds.
    pub at: Option<String>,
}


/// `GET /dhcp/leases/mac` query.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct MacQuery {
    /// MAC address, colon or dash separated, 6 groups of 2 hex digits.
    pub mac: Option<String>,
    /// Window start, Unix seconds.
    pub from: Option<String>,
    /// Window end, Unix seconds, at most 400 days after `from`.
    pub to: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LeaseView {
    pub address: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// A hostname was sent and refused; its text is never kept.
    pub hostname_refused: bool,
    pub starts: String,
    pub ends: String,
    pub action: String,
    pub subnet_id: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LookupView {
    pub intervals: Vec<LeaseView>,
    pub skipped: usize,
    pub truncated: bool,
}

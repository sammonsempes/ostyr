use crate::error::DiscoveryError;
use crate::model::{EdgeKey, EdgeStats, Lease, Scope};
use cmdb::model::Asset;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;


pub type Millis = i64;


pub type EdgeMap = BTreeMap<EdgeKey, EdgeStats>;


pub type SeenIndex = BTreeSet<(Millis, EdgeKey)>;


pub type ScopeResult = Result<Scope, DiscoveryError>;


pub type LeaseMap = BTreeMap<IpAddr, Lease>;


pub type Matched<'a> = Option<(&'a Lease, Option<&'a Asset>)>;

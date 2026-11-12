use crate::error::DiscoveryError;
use crate::model::{EdgeKey, EdgeStats, Scope};
use std::collections::{BTreeMap, BTreeSet};


pub type Millis = i64;


pub type EdgeMap = BTreeMap<EdgeKey, EdgeStats>;


pub type SeenIndex = BTreeSet<(Millis, EdgeKey)>;


pub type ScopeResult = Result<Scope, DiscoveryError>;

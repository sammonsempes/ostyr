use crate::model::SourceState;
use std::collections::BTreeMap;
use std::net::IpAddr;


pub type Millis = u64;


pub type SourceId = IpAddr;


pub type SourceMap = BTreeMap<SourceId, SourceState>;

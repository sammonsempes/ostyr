use crate::model::SourceState;
use crate::spool_model::Segment;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;


pub type Millis = u64;


pub type SourceId = IpAddr;


pub type SourceMap = BTreeMap<SourceId, SourceState>;


pub type SegmentList = VecDeque<Segment>;

use crate::model::{DropReason, SPAN_ID_BYTES, TRACE_ID_BYTES};
use std::collections::BTreeMap;


pub type Dropped = BTreeMap<DropReason, u64>;


pub type Attributes = Vec<(String, String)>;


pub type TraceId = [u8; TRACE_ID_BYTES];


pub type SpanId = [u8; SPAN_ID_BYTES];


pub type ServiceName = Result<String, DropReason>;


pub type ServiceRatios = BTreeMap<String, f64>;

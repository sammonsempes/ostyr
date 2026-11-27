use crate::insert::RefusedSpan;
use crate::model::{DropReason, SPAN_ID_BYTES, TRACE_ID_BYTES};
use prost::DecodeError;
use std::collections::BTreeMap;


pub type Dropped = BTreeMap<DropReason, u64>;


pub type RefusedCounts = BTreeMap<RefusedSpan, u64>;


pub type Attributes = Vec<(String, String)>;


pub type TraceId = [u8; TRACE_ID_BYTES];


pub type SpanId = [u8; SPAN_ID_BYTES];


pub type ServiceName = Result<String, DropReason>;


pub type ServiceRatios = BTreeMap<String, f64>;


/// One wire field: its tag and its payload when length-delimited; the length is validated against the buffer.
pub type WireField<'a> = Result<(u32, Option<&'a [u8]>), DecodeError>;


/// Whether the sender of the request is still admitted: asked before every batch is sent.
pub type AdmittedFn<'a> = dyn Fn() -> bool + 'a;


/// Token digest (64 lower-case hex) to sender name.
pub type SenderTable = BTreeMap<String, String>;

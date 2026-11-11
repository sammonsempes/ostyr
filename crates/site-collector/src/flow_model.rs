use crate::model::DropReason;
use serde::Serialize;
use std::net::Ipv4Addr;
use thiserror::Error;


pub const FLOW_HEADER_BYTES: usize = 24;


pub const FLOW_RECORD_BYTES: usize = 48;


pub const MAX_FLOW_RECORDS: usize = 30;


pub const MAX_FLOW_DATAGRAM_BYTES: usize = FLOW_HEADER_BYTES + FLOW_RECORD_BYTES * MAX_FLOW_RECORDS;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowLimits {
    pub max_records_per_datagram: usize,
}


impl Default for FlowLimits {
    fn default() -> Self {
        Self {
            max_records_per_datagram: MAX_FLOW_RECORDS,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowRecord {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub input_interface: u16,
    pub output_interface: u16,
    pub packets: u32,
    pub octets: u32,
    pub start_unix_ms: i64,
    pub end_unix_ms: i64,
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub source_as: u16,
    pub destination_as: u16,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowBatch {
    pub export_unix_ms: i64,
    pub exporter_uptime_ms: u32,
    pub sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u16,
    pub sampling_interval: u16,
    pub records: Vec<FlowRecord>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FlowDrop {
    #[error("the flow datagram exceeds the size cap")]
    TooLarge,
    #[error("the flow datagram is malformed")]
    Malformed,
    #[error("the flow datagram is not NetFlow version 5")]
    Unsupported,
}


impl From<FlowDrop> for DropReason {
    fn from(flow_drop: FlowDrop) -> Self {
        match flow_drop {
            FlowDrop::TooLarge => Self::FlowTooLarge,
            FlowDrop::Malformed => Self::FlowMalformed,
            FlowDrop::Unsupported => Self::FlowUnsupported,
        }
    }
}

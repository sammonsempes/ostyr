use crate::model::DropReason;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;


pub const V5_VERSION: u16 = 5;


pub const FLOW_HEADER_BYTES: usize = 24;


pub const FLOW_RECORD_BYTES: usize = 48;


pub const MAX_FLOW_RECORDS: usize = 30;


pub const MAX_FLOW_DATAGRAM_BYTES: usize = FLOW_HEADER_BYTES + FLOW_RECORD_BYTES * MAX_FLOW_RECORDS;


pub const MAX_TEMPLATE_DATAGRAM_BYTES: usize = 9216;


pub const DEFAULT_TEMPLATES_PER_EXPORTER: usize = 64;


pub const MAX_TEMPLATES_PER_EXPORTER: usize = 1024;


pub const DEFAULT_TEMPLATE_EXPORTERS: usize = 256;


pub const MAX_TEMPLATE_EXPORTERS: usize = 4096;


pub const DEFAULT_FIELDS_PER_TEMPLATE: usize = 64;


pub const MAX_FIELDS_PER_TEMPLATE: usize = 256;


pub const DEFAULT_RECORD_BYTES: usize = 1500;


pub const MAX_RECORD_BYTES: usize = 4096;


pub const DEFAULT_TEMPLATE_AGE_SECONDS: u64 = 1800;


pub const MAX_TEMPLATE_AGE_SECONDS: u64 = 86_400;


pub const DEFAULT_EXPORTERS_PER_SOURCE_KEY: usize = 4;


pub const MAX_EXPORTERS_PER_SOURCE_KEY: usize = 64;


pub const DEFAULT_TEMPLATES_TOTAL: usize = 4096;


pub const MAX_TEMPLATES_TOTAL: usize = 65_536;


pub const FLOW_FRAME_VERSION: u8 = 1;


/// The most a stored flow frame may hold: four IPv6 texts, the numbers and the field names come to under 700 bytes.
pub const MAX_FLOW_FRAME_BYTES: usize = 1024;


pub const DEFAULT_TEMPLATE_RECORDS: usize = 75;


pub const MAX_TEMPLATE_RECORDS: usize = MAX_TEMPLATE_DATAGRAM_BYTES;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FlowLimits {
    pub max_records_per_datagram: usize,
    pub max_templates_per_exporter: usize,
    pub max_template_exporters: usize,
    pub max_fields_per_template: usize,
    pub max_record_bytes: usize,
    pub max_template_age_seconds: u64,
    pub max_template_records_per_datagram: usize,
    pub max_exporters_per_source_key: usize,
    pub max_templates_total: usize,
}


impl Default for FlowLimits {
    fn default() -> Self {
        Self {
            max_records_per_datagram: MAX_FLOW_RECORDS,
            max_templates_per_exporter: DEFAULT_TEMPLATES_PER_EXPORTER,
            max_template_exporters: DEFAULT_TEMPLATE_EXPORTERS,
            max_fields_per_template: DEFAULT_FIELDS_PER_TEMPLATE,
            max_record_bytes: DEFAULT_RECORD_BYTES,
            max_template_age_seconds: DEFAULT_TEMPLATE_AGE_SECONDS,
            max_template_records_per_datagram: DEFAULT_TEMPLATE_RECORDS,
            max_exporters_per_source_key: DEFAULT_EXPORTERS_PER_SOURCE_KEY,
            max_templates_total: DEFAULT_TEMPLATES_TOTAL,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRecord {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub next_hop: IpAddr,
    pub input_interface: u32,
    pub output_interface: u32,
    pub packets: u64,
    pub octets: u64,
    pub start_unix_ms: i64,
    pub end_unix_ms: i64,
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub source_as: u32,
    pub destination_as: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowFrame<'a> {
    #[serde(rename = "v")]
    pub version: u8,
    pub exporter: IpAddr,
    #[serde(flatten)]
    pub record: &'a FlowRecord,
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
    #[error("the flow datagram is not NetFlow version 5, 9 or IPFIX")]
    Unsupported,
    #[error("the flow data has no known template")]
    NoTemplate,
    #[error("the flow template was refused by a cap")]
    TemplateRefused,
}


impl From<FlowDrop> for DropReason {
    fn from(flow_drop: FlowDrop) -> Self {
        match flow_drop {
            FlowDrop::TooLarge => Self::FlowTooLarge,
            FlowDrop::Malformed => Self::FlowMalformed,
            FlowDrop::Unsupported => Self::FlowUnsupported,
            FlowDrop::NoTemplate => Self::FlowNoTemplate,
            FlowDrop::TemplateRefused => Self::FlowTemplateRefused,
        }
    }
}

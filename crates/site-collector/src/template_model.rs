use crate::flow_model::{FlowLimits, FlowRecord};
use crate::types::{ExporterMap, KeyCountMap, LruIndex, SourceKeySet, TemplateMap};
use std::net::IpAddr;


pub const SET_HEADER_BYTES: usize = 4;


pub const TEMPLATE_HEADER_BYTES: usize = 4;


pub const FIELD_SPEC_BYTES: usize = 4;


pub const ENTERPRISE_NUMBER_BYTES: usize = 4;


pub const V9_VERSION: u16 = 9;


pub const IPFIX_VERSION: u16 = 10;


pub const V9_HEADER_BYTES: usize = 20;


pub const IPFIX_HEADER_BYTES: usize = 16;


pub const V9_TEMPLATE_SET: u16 = 0;


pub const V9_OPTIONS_SET: u16 = 1;


pub const IPFIX_TEMPLATE_SET: u16 = 2;


pub const IPFIX_OPTIONS_SET: u16 = 3;


pub const MIN_DATA_SET_ID: u16 = 256;


pub const WITHDRAW_ALL_TEMPLATE_ID: u16 = 2;


pub const ENTERPRISE_BIT: u16 = 0x8000;


pub const VARIABLE_LENGTH: u16 = 0xFFFF;


pub const LONG_VARIABLE_MARKER: u8 = 255;


pub const MAX_PADDING_BYTES: usize = 3;


pub const MILLIS_PER_SECOND: u64 = 1000;


pub const ELEMENT_OCTET_DELTA: u16 = 1;


pub const ELEMENT_PACKET_DELTA: u16 = 2;


pub const ELEMENT_PROTOCOL: u16 = 4;


pub const ELEMENT_TOS: u16 = 5;


pub const ELEMENT_TCP_FLAGS: u16 = 6;


pub const ELEMENT_SOURCE_PORT: u16 = 7;


pub const ELEMENT_SOURCE_IPV4: u16 = 8;


pub const ELEMENT_INPUT_INTERFACE: u16 = 10;


pub const ELEMENT_DESTINATION_PORT: u16 = 11;


pub const ELEMENT_DESTINATION_IPV4: u16 = 12;


pub const ELEMENT_OUTPUT_INTERFACE: u16 = 14;


pub const ELEMENT_NEXT_HOP_IPV4: u16 = 15;


pub const ELEMENT_SOURCE_AS: u16 = 16;


pub const ELEMENT_DESTINATION_AS: u16 = 17;


pub const ELEMENT_LAST_SWITCHED: u16 = 21;


pub const ELEMENT_FIRST_SWITCHED: u16 = 22;


pub const ELEMENT_SOURCE_IPV6: u16 = 27;


pub const ELEMENT_DESTINATION_IPV6: u16 = 28;


pub const ELEMENT_NEXT_HOP_IPV6: u16 = 62;


pub const ELEMENT_OCTET_TOTAL: u16 = 85;


pub const ELEMENT_PACKET_TOTAL: u16 = 86;


pub const ELEMENT_START_SECONDS: u16 = 150;


pub const ELEMENT_END_SECONDS: u16 = 151;


pub const ELEMENT_START_MILLIS: u16 = 152;


pub const ELEMENT_END_MILLIS: u16 = 153;


pub const BITS_PER_BYTE: u32 = 8;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    V9,
    Ipfix,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TemplateKey {
    pub exporter: IpAddr,
    pub domain: u32,
    pub template_id: u16,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateField {
    pub element: u16,
    pub length: u16,
    pub variable: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub fields: Vec<TemplateField>,
    pub min_record_bytes: usize,
    pub refreshed_ms: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExporterState {
    pub last_used: u64,
    pub templates: usize,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TemplateStats {
    pub evicted_exporters: u64,
    pub expired_templates: u64,
    pub refused_templates: u64,
    pub no_template_sets: u64,
    pub index_steps: u64,
}


#[derive(Debug, Clone, Default)]
pub struct TemplateCache {
    pub templates: TemplateMap,
    pub exporters: ExporterMap,
    pub declared: SourceKeySet,
    pub per_key: KeyCountMap,
    pub undeclared_lru: LruIndex,
    pub declared_lru: LruIndex,
    pub tick: u64,
    pub stats: TemplateStats,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateDef {
    pub template_id: u16,
    pub fields: Vec<TemplateField>,
}


#[derive(Debug, Clone, Copy)]
pub struct DecodeContext {
    pub export_ms: i64,
    pub uptime_ms: u32,
}


#[derive(Debug, Default)]
pub struct Progress {
    pub records: Vec<FlowRecord>,
    pub no_template: usize,
    pub refused: usize,
    pub exporter_refused: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    Template,
    Data,
    Skipped,
}


#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    pub protocol: Protocol,
    pub exporter: IpAddr,
    pub domain: u32,
    pub sequence: u32,
    pub context: DecodeContext,
    pub now_ms: u64,
    pub age_ms: u64,
    pub limits: &'a FlowLimits,
}

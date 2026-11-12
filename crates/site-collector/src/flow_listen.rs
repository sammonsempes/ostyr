//! The flow side of the listener: admission, version detection, parsing over the template cache, one spool frame per record.

use crate::admission::{admit_extra_record, admit_up_to, collector_config};
use crate::error::FlowStoreError;
use crate::flow::parse_netflow_v5;
use crate::flow_model::{FlowBatch, FlowDrop, FlowFrame, FlowLimits, FlowRecord, FLOW_FRAME_VERSION, MAX_TEMPLATE_DATAGRAM_BYTES, V5_VERSION};
use crate::listen::{bump, count_reason};
use crate::listen_model::Runtime;
use crate::listen_settings::source_key;
use crate::model::DropReason;
use crate::spool::append;
use crate::spool_model::Priority;
use crate::template_model::{TemplateCache, IPFIX_VERSION, V9_VERSION};
use crate::template_parse::{parse_ipfix, parse_netflow_v9};
use crate::types::{FrameEncoder, Millis};
use std::net::{IpAddr, SocketAddr};


const VERSION_BYTES: usize = 2;


/// The version field of a flow datagram, when it holds at least two bytes.
pub fn flow_version(payload: &[u8]) -> Option<u16> {
    payload.first_chunk::<VERSION_BYTES>().map(|bytes| u16::from_be_bytes(*bytes))
}


pub fn parse_flow(cache: &mut TemplateCache, limits: &FlowLimits, exporter: IpAddr, payload: &[u8], now: Millis) -> Result<FlowBatch, FlowDrop> {
    match flow_version(payload) {
        Some(V5_VERSION) => parse_netflow_v5(payload, limits),
        Some(V9_VERSION) => parse_netflow_v9(payload, exporter, cache, now, limits),
        Some(IPFIX_VERSION) => parse_ipfix(payload, exporter, cache, now, limits),
        _ => Err(FlowDrop::Unsupported),
    }
}


pub fn encode_frame(frame: &FlowFrame) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(frame)
}


/// Flows of a declared exporter are stored at high priority, so an undeclared source never evicts them; undeclared ones at low priority.
pub fn flow_priority(runtime: &Runtime, source: SocketAddr) -> Priority {
    if collector_config(&runtime.collector).sources.contains(&source_key(source.ip())) {
        Priority::High
    } else {
        Priority::Low
    }
}


pub fn store_record(runtime: &mut Runtime, exporter: IpAddr, priority: Priority, record: &FlowRecord, encode: FrameEncoder) {
    let frame = FlowFrame {
        version: FLOW_FRAME_VERSION,
        exporter,
        record,
    };
    let stored = encode(&frame)
        .map_err(FlowStoreError::from)
        .and_then(|payload| append(&mut runtime.spool, priority, &payload).map_err(FlowStoreError::from));
    match stored {
        Ok(_) => bump(&mut runtime.stats.flow_records),
        Err(error) => {
            bump(&mut runtime.stats.spool_errors);
            tracing::error!(%error, %exporter, "cannot store a flow record");
        }
    }
}


/// The first record rides on the datagram's admission; every further one takes a token, so records are bounded like datagrams.
pub fn budgeted_records<'a>(runtime: &mut Runtime, source: SocketAddr, records: &'a [FlowRecord], now: Millis) -> Vec<&'a FlowRecord> {
    let key = source_key(source.ip());
    records
        .iter()
        .enumerate()
        .filter(|(index, _)| *index == 0 || admit_extra_record(&mut runtime.collector, key, now).is_ok())
        .map(|(_, record)| record)
        .collect()
}


pub fn store_flows(runtime: &mut Runtime, source: SocketAddr, payload: &[u8], now: Millis, encode: FrameEncoder) {
    let exporter = source.ip().to_canonical();
    match parse_flow(&mut runtime.templates, &runtime.applied.flow, exporter, payload, now) {
        Ok(batch) => {
            bump(&mut runtime.stats.flows_accepted);
            let admitted = budgeted_records(runtime, source, &batch.records, now);
            let over_budget = batch.records.len().saturating_sub(admitted.len());
            runtime.stats.flow_records_over_budget = runtime.stats.flow_records_over_budget.saturating_add(over_budget as u64);
            let priority = flow_priority(runtime, source);
            admitted
                .into_iter()
                .for_each(|record| store_record(runtime, exporter, priority, record, encode));
        }
        Err(flow_drop) => {
            tracing::debug!(%source, %flow_drop, "flow datagram dropped");
            count_reason(&mut runtime.stats, DropReason::from(flow_drop));
        }
    }
}


pub fn handle_flow_with(runtime: &mut Runtime, source: SocketAddr, payload: &[u8], now: Millis, encode: FrameEncoder) {
    bump(&mut runtime.stats.received);
    match admit_up_to(
        &mut runtime.collector,
        source_key(source.ip()),
        payload.len(),
        MAX_TEMPLATE_DATAGRAM_BYTES,
        now,
    ) {
        Err(reason) => count_reason(&mut runtime.stats, reason),
        Ok(()) => store_flows(runtime, source, payload, now, encode),
    }
}


pub fn handle_flow_datagram(runtime: &mut Runtime, source: SocketAddr, payload: &[u8], now: Millis) {
    handle_flow_with(runtime, source, payload, now, encode_frame);
}

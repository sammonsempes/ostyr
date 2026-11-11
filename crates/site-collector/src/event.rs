use crate::event_model::{
    COLLECTOR_MODULE, MAX_FLOW_AGE_MS, MAX_FLOW_SKEW_MS, MAX_TRAP_OID_BYTES, MAX_VARBIND_LABEL_BYTES, MILLIS_PER_SECOND, NETFLOW_DATASET,
    PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP, SNMP_TRAP_DATASET,
};
use crate::flow_model::{FlowBatch, FlowRecord};
use crate::forward::clean_text;
use crate::model::{TrapKind, TrapRecord, TrapVersion};
use core_export::ecs::{blank_event, EcsEvent, EndpointFields, EventFields, NetworkFields};
use core_export::types::LabelMap;
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};


pub fn base_labels(epoch: &str, sequence: u64) -> LabelMap {
    [("collector_sequence", sequence.to_string()), ("collector_epoch", epoch.to_owned())]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}


pub fn version_name(version: TrapVersion) -> &'static str {
    match version {
        TrapVersion::V1 => "v1",
        TrapVersion::V2c => "v2c",
    }
}


pub fn kind_name(kind: TrapKind) -> &'static str {
    match kind {
        TrapKind::TrapV1 => "trap_v1",
        TrapKind::TrapV2 => "trap_v2",
        TrapKind::Inform => "inform",
    }
}


/// One SNMP trap as an event: the source is the datagram peer, `agent_address` is only a claim in a label, varbinds are cut labels.
pub fn trap_event(record: &TrapRecord, source: IpAddr, epoch: &str, sequence: u64, now: OffsetDateTime) -> EcsEvent {
    let mut labels = base_labels(epoch, sequence);
    labels.insert("snmp_version".to_owned(), version_name(record.version).to_owned());
    labels.insert("snmp_kind".to_owned(), kind_name(record.kind).to_owned());
    labels.insert("snmp_uptime_ticks".to_owned(), record.uptime_ticks.to_string());
    if let Some(agent) = record.agent_address {
        labels.insert("snmp_agent_address_claimed".to_owned(), agent.to_string());
    }
    if record.varbinds_omitted > 0 {
        labels.insert("snmp_varbinds_omitted".to_owned(), record.varbinds_omitted.to_string());
    }
    record.varbinds.iter().enumerate().for_each(|(index, varbind)| {
        labels.insert(
            format!("snmp_varbind_{index}"),
            clean_text(&format!("{}={}", varbind.oid, varbind.value), MAX_VARBIND_LABEL_BYTES),
        );
    });
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_owned()),
            module: Some(COLLECTOR_MODULE.to_owned()),
            dataset: Some(SNMP_TRAP_DATASET.to_owned()),
            code: Some(clean_text(&record.trap_oid, MAX_TRAP_OID_BYTES)),
            ..EventFields::default()
        },
        source: Some(EndpointFields {
            ip: Some(source.to_string()),
            ..EndpointFields::default()
        }),
        labels,
        ..blank_event(now)
    }
}


/// The transport name of an IP protocol number: tcp, udp, icmp, else the number.
pub fn transport_name(protocol: u8) -> String {
    match protocol {
        PROTOCOL_TCP => "tcp".to_owned(),
        PROTOCOL_UDP => "udp".to_owned(),
        PROTOCOL_ICMP => "icmp".to_owned(),
        other => other.to_string(),
    }
}


/// A flow time inside `[now - MAX_FLOW_AGE_MS, now + MAX_FLOW_SKEW_MS]` is kept, any other is the receive time, flagged.
pub fn clamp_flow_ms(value_ms: i64, now_ms: i64) -> (i64, bool) {
    if value_ms < now_ms.saturating_sub(MAX_FLOW_AGE_MS) || value_ms > now_ms.saturating_add(MAX_FLOW_SKEW_MS) {
        (now_ms, true)
    } else {
        (value_ms, false)
    }
}


pub fn flow_time(value_ms: i64, now_ms: i64, now: OffsetDateTime) -> OffsetDateTime {
    now.saturating_add(Duration::milliseconds(value_ms.saturating_sub(now_ms)))
}


pub fn flow_event(flow: &FlowRecord, batch: &FlowBatch, exporter: IpAddr, epoch: &str, sequence: u64, index: usize, now: OffsetDateTime) -> EcsEvent {
    let now_ms = now.unix_timestamp().saturating_mul(MILLIS_PER_SECOND);
    let (start_ms, start_clamped) = clamp_flow_ms(flow.start_unix_ms, now_ms);
    let (end_ms, end_clamped) = clamp_flow_ms(flow.end_unix_ms, now_ms);
    let end = flow_time(end_ms, now_ms, now);
    let mut labels = base_labels(epoch, sequence);
    labels.insert("collector_index".to_owned(), index.to_string());
    labels.insert("netflow_exporter_ip".to_owned(), exporter.to_string());
    labels.insert("netflow_engine".to_owned(), format!("{}/{}", batch.engine_type, batch.engine_id));
    if start_clamped || end_clamped {
        labels.insert("flow_time_clamped".to_owned(), "true".to_owned());
    }
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_owned()),
            module: Some(COLLECTOR_MODULE.to_owned()),
            dataset: Some(NETFLOW_DATASET.to_owned()),
            category: vec!["network".to_owned()],
            types: vec!["connection".to_owned()],
            start: Some(flow_time(start_ms, now_ms, now)),
            end: Some(end),
            ..EventFields::default()
        },
        source: Some(EndpointFields {
            ip: Some(flow.source.to_string()),
            port: Some(flow.source_port),
            bytes: Some(u64::from(flow.octets)),
            packets: Some(u64::from(flow.packets)),
            ..EndpointFields::default()
        }),
        destination: Some(EndpointFields {
            ip: Some(flow.destination.to_string()),
            port: Some(flow.destination_port),
            ..EndpointFields::default()
        }),
        network: Some(NetworkFields {
            transport: Some(transport_name(flow.protocol)),
            ..NetworkFields::default()
        }),
        labels,
        ..blank_event(end)
    }
}


/// One event per flow record of the batch; `exporter` is the datagram peer.
pub fn flow_events(batch: &FlowBatch, exporter: IpAddr, epoch: &str, sequence: u64, now: OffsetDateTime) -> Vec<EcsEvent> {
    batch
        .records
        .iter()
        .enumerate()
        .map(|(index, flow)| flow_event(flow, batch, exporter, epoch, sequence, index, now))
        .collect()
}

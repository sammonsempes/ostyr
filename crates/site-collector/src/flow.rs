//! NetFlow v5 parsing: one datagram into a bounded batch of flow records (spec section 22).

use crate::error::ConfigError;
use crate::flow_model::{
    FlowBatch, FlowDrop, FlowLimits, FlowRecord, FLOW_HEADER_BYTES, FLOW_RECORD_BYTES, MAX_FIELDS_PER_TEMPLATE, MAX_FLOW_DATAGRAM_BYTES,
    MAX_FLOW_RECORDS, MAX_RECORD_BYTES, MAX_TEMPLATES_PER_EXPORTER, MAX_TEMPLATE_AGE_SECONDS, MAX_TEMPLATE_EXPORTERS, MAX_TEMPLATE_RECORDS,
};
use std::net::{IpAddr, Ipv4Addr};


const NETFLOW_VERSION: u16 = 5;


const U16_BYTES: usize = 2;


const U32_BYTES: usize = 4;


const MILLIS_PER_SECOND: i64 = 1000;


const NANOS_PER_MILLI: u32 = 1_000_000;


const SAMPLING_INTERVAL_MASK: u16 = 0x3fff;


const SAMPLING_MODE_SHIFT: u32 = 14;


const PAD_BYTE: usize = 1;


const PAD_WORD: usize = 2;


const MASK_BYTES: usize = 2;


fn take<const LENGTH: usize>(rest: &mut &[u8]) -> Result<[u8; LENGTH], FlowDrop> {
    let (chunk, tail) = rest.split_first_chunk::<LENGTH>().ok_or(FlowDrop::Malformed)?;
    *rest = tail;
    Ok(*chunk)
}


pub fn skip(rest: &mut &[u8], count: usize) -> Result<(), FlowDrop> {
    *rest = rest.get(count..).ok_or(FlowDrop::Malformed)?;
    Ok(())
}


pub fn read_u8(rest: &mut &[u8]) -> Result<u8, FlowDrop> {
    Ok(u8::from_be_bytes(take::<PAD_BYTE>(rest)?))
}


pub fn read_u16(rest: &mut &[u8]) -> Result<u16, FlowDrop> {
    Ok(u16::from_be_bytes(take::<U16_BYTES>(rest)?))
}


pub fn read_u32(rest: &mut &[u8]) -> Result<u32, FlowDrop> {
    Ok(u32::from_be_bytes(take::<U32_BYTES>(rest)?))
}


fn read_ipv4(rest: &mut &[u8]) -> Result<Ipv4Addr, FlowDrop> {
    Ok(Ipv4Addr::from(take::<U32_BYTES>(rest)?))
}


pub fn validate_flow_limits(limits: &FlowLimits) -> Result<(), ConfigError> {
    (1..=MAX_FLOW_RECORDS)
        .contains(&limits.max_records_per_datagram)
        .then_some(())
        .ok_or(ConfigError::BadMaxFlowRecords)?;
    let within = [
        (1..=MAX_TEMPLATES_PER_EXPORTER).contains(&limits.max_templates_per_exporter),
        (1..=MAX_TEMPLATE_EXPORTERS).contains(&limits.max_template_exporters),
        (1..=MAX_FIELDS_PER_TEMPLATE).contains(&limits.max_fields_per_template),
        (1..=MAX_RECORD_BYTES).contains(&limits.max_record_bytes),
        (1..=MAX_TEMPLATE_AGE_SECONDS).contains(&limits.max_template_age_seconds),
        (1..=MAX_TEMPLATE_RECORDS).contains(&limits.max_template_records_per_datagram),
    ];
    within.iter().all(|ok| *ok).then_some(()).ok_or(ConfigError::BadFlowTemplateLimit)
}


pub fn export_time_ms(unix_secs: u32, unix_nsecs: u32) -> i64 {
    let millis = i64::from(unix_nsecs / NANOS_PER_MILLI).min(MILLIS_PER_SECOND - 1);
    i64::from(unix_secs) * MILLIS_PER_SECOND + millis
}


pub fn absolute_ms(export_ms: i64, uptime_ms: u32, stamp_ms: u32) -> i64 {
    export_ms - i64::from(uptime_ms.wrapping_sub(stamp_ms))
}


pub fn read_record(rest: &mut &[u8], export_ms: i64, uptime_ms: u32) -> Result<FlowRecord, FlowDrop> {
    let source = IpAddr::V4(read_ipv4(rest)?);
    let destination = IpAddr::V4(read_ipv4(rest)?);
    let next_hop = IpAddr::V4(read_ipv4(rest)?);
    let input_interface = u32::from(read_u16(rest)?);
    let output_interface = u32::from(read_u16(rest)?);
    let packets = u64::from(read_u32(rest)?);
    let octets = u64::from(read_u32(rest)?);
    let first = read_u32(rest)?;
    let last = read_u32(rest)?;
    let source_port = read_u16(rest)?;
    let destination_port = read_u16(rest)?;
    skip(rest, PAD_BYTE)?;
    let tcp_flags = read_u8(rest)?;
    let protocol = read_u8(rest)?;
    let tos = read_u8(rest)?;
    let source_as = u32::from(read_u16(rest)?);
    let destination_as = u32::from(read_u16(rest)?);
    skip(rest, MASK_BYTES)?;
    skip(rest, PAD_WORD)?;
    Ok(FlowRecord {
        source,
        destination,
        next_hop,
        input_interface,
        output_interface,
        packets,
        octets,
        start_unix_ms: absolute_ms(export_ms, uptime_ms, first),
        end_unix_ms: absolute_ms(export_ms, uptime_ms, last),
        source_port,
        destination_port,
        tcp_flags,
        protocol,
        tos,
        source_as,
        destination_as,
    })
}


pub fn read_records(rest: &mut &[u8], count: usize, export_ms: i64, uptime_ms: u32) -> Result<Vec<FlowRecord>, FlowDrop> {
    (0..count).map(|_| read_record(rest, export_ms, uptime_ms)).collect()
}


pub fn parse_netflow_v5(datagram: &[u8], limits: &FlowLimits) -> Result<FlowBatch, FlowDrop> {
    (datagram.len() <= MAX_FLOW_DATAGRAM_BYTES).then_some(()).ok_or(FlowDrop::TooLarge)?;
    let mut rest = datagram;
    (read_u16(&mut rest)? == NETFLOW_VERSION).then_some(()).ok_or(FlowDrop::Unsupported)?;
    let count = usize::from(read_u16(&mut rest)?);
    let uptime_ms = read_u32(&mut rest)?;
    let unix_secs = read_u32(&mut rest)?;
    let unix_nsecs = read_u32(&mut rest)?;
    let sequence = read_u32(&mut rest)?;
    let engine_type = read_u8(&mut rest)?;
    let engine_id = read_u8(&mut rest)?;
    let sampling = read_u16(&mut rest)?;
    (1..=MAX_FLOW_RECORDS).contains(&count).then_some(()).ok_or(FlowDrop::Malformed)?;
    (datagram.len() == FLOW_HEADER_BYTES + FLOW_RECORD_BYTES * count)
        .then_some(())
        .ok_or(FlowDrop::Malformed)?;
    (count <= limits.max_records_per_datagram).then_some(()).ok_or(FlowDrop::TooLarge)?;
    let export_ms = export_time_ms(unix_secs, unix_nsecs);
    read_records(&mut rest, count, export_ms, uptime_ms).map(|records| FlowBatch {
        export_unix_ms: export_ms,
        exporter_uptime_ms: uptime_ms,
        sequence,
        engine_type,
        engine_id,
        sampling_mode: sampling >> SAMPLING_MODE_SHIFT,
        sampling_interval: sampling & SAMPLING_INTERVAL_MASK,
        records,
    })
}

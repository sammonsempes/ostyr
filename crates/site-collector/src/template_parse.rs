//! NetFlow v9 and IPFIX parsing over the bounded template cache (spec section 22).

use crate::flow::{absolute_ms, export_time_ms, read_u16, read_u32, read_u8, skip};
use crate::flow_model::{FlowBatch, FlowDrop, FlowLimits, FlowRecord, MAX_TEMPLATE_DATAGRAM_BYTES};
use crate::template::{age_limit_ms, expire_exporter, lookup_template, refuse, store_template, withdraw_scope, withdraw_template};
use crate::template_model::{
    DecodeContext, Progress, Protocol, Session, SetKind, Template, TemplateCache, TemplateDef, TemplateField, TemplateKey, BITS_PER_BYTE,
    ELEMENT_DESTINATION_AS, ELEMENT_DESTINATION_IPV4, ELEMENT_DESTINATION_IPV6, ELEMENT_DESTINATION_PORT, ELEMENT_END_MILLIS, ELEMENT_END_SECONDS,
    ELEMENT_FIRST_SWITCHED, ELEMENT_INPUT_INTERFACE, ELEMENT_LAST_SWITCHED, ELEMENT_NEXT_HOP_IPV4, ELEMENT_NEXT_HOP_IPV6, ELEMENT_OCTET_DELTA,
    ELEMENT_OCTET_TOTAL, ELEMENT_OUTPUT_INTERFACE, ELEMENT_PACKET_DELTA, ELEMENT_PACKET_TOTAL, ELEMENT_PROTOCOL, ELEMENT_SOURCE_AS,
    ELEMENT_SOURCE_IPV4, ELEMENT_SOURCE_IPV6, ELEMENT_SOURCE_PORT, ELEMENT_START_MILLIS, ELEMENT_START_SECONDS, ELEMENT_TCP_FLAGS, ELEMENT_TOS,
    ENTERPRISE_BIT, ENTERPRISE_NUMBER_BYTES, IPFIX_TEMPLATE_SET, IPFIX_VERSION, LONG_VARIABLE_MARKER, MAX_PADDING_BYTES, MIN_DATA_SET_ID,
    SET_HEADER_BYTES, TEMPLATE_HEADER_BYTES, V9_TEMPLATE_SET, V9_VERSION, VARIABLE_LENGTH, WITHDRAW_ALL_TEMPLATE_ID,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;


const U16_BYTES: usize = 2;


const BYTE_MASK: u64 = 0xff;


const IPV4_BYTES: usize = 4;


const IPV6_BYTES: usize = 16;


const MILLIS_PER_SECOND_SIGNED: i64 = 1000;


pub fn split_sets(rest: &[u8]) -> Result<Vec<(u16, &[u8])>, FlowDrop> {
    let mut cursor = rest;
    let sets = std::iter::from_fn(|| (cursor.len() >= SET_HEADER_BYTES).then(|| read_set(&mut cursor)))
        .take(MAX_TEMPLATE_DATAGRAM_BYTES / SET_HEADER_BYTES + 1)
        .collect::<Result<Vec<_>, _>>()?;
    cursor.is_empty().then_some(sets).ok_or(FlowDrop::Malformed)
}


pub fn read_set<'a>(cursor: &mut &'a [u8]) -> Result<(u16, &'a [u8]), FlowDrop> {
    let set_id = read_u16(cursor)?;
    let length = usize::from(read_u16(cursor)?);
    let body_length = length.checked_sub(SET_HEADER_BYTES).ok_or(FlowDrop::Malformed)?;
    let (body, tail) = cursor.split_at_checked(body_length).ok_or(FlowDrop::Malformed)?;
    *cursor = tail;
    Ok((set_id, body))
}


pub fn set_kind(protocol: Protocol, set_id: u16) -> SetKind {
    let template_set = match protocol {
        Protocol::V9 => V9_TEMPLATE_SET,
        Protocol::Ipfix => IPFIX_TEMPLATE_SET,
    };
    if set_id == template_set {
        SetKind::Template
    } else if set_id >= MIN_DATA_SET_ID {
        SetKind::Data
    } else {
        SetKind::Skipped
    }
}


pub fn read_field_spec(rest: &mut &[u8], protocol: Protocol) -> Result<TemplateField, FlowDrop> {
    let element = read_u16(rest)?;
    let length = read_u16(rest)?;
    let enterprise = protocol == Protocol::Ipfix && element & ENTERPRISE_BIT != 0;
    if enterprise {
        skip(rest, ENTERPRISE_NUMBER_BYTES)?;
    }
    Ok(TemplateField {
        element: if enterprise { u16::MIN } else { element },
        length,
        variable: protocol == Protocol::Ipfix && length == VARIABLE_LENGTH,
    })
}


pub fn read_template_def(rest: &mut &[u8], protocol: Protocol, limits: &FlowLimits) -> Result<TemplateDef, FlowDrop> {
    let template_id = read_u16(rest)?;
    let count = usize::from(read_u16(rest)?);
    let withdraw_all = protocol == Protocol::Ipfix && template_id == WITHDRAW_ALL_TEMPLATE_ID && count == 0;
    (template_id >= MIN_DATA_SET_ID || withdraw_all)
        .then_some(())
        .ok_or(FlowDrop::Malformed)?;
    (count <= limits.max_fields_per_template).then_some(()).ok_or(FlowDrop::TemplateRefused)?;
    let fields = (0..count).map(|_| read_field_spec(rest, protocol)).collect::<Result<Vec<_>, _>>()?;
    Ok(TemplateDef { template_id, fields })
}


pub fn read_template_defs(body: &[u8], protocol: Protocol, limits: &FlowLimits) -> Result<Vec<TemplateDef>, FlowDrop> {
    let mut rest = body;
    let defs = std::iter::from_fn(|| (rest.len() >= TEMPLATE_HEADER_BYTES).then(|| read_template_def(&mut rest, protocol, limits)))
        .take(limits.max_templates_per_exporter.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()?;
    (defs.len() <= limits.max_templates_per_exporter)
        .then_some(defs)
        .ok_or(FlowDrop::TemplateRefused)
}


pub fn build_template(fields: Vec<TemplateField>, now_ms: u64) -> Template {
    let min_record_bytes = fields
        .iter()
        .map(|field| if field.variable { 1 } else { usize::from(field.length) })
        .sum();
    Template {
        fields,
        min_record_bytes,
        refreshed_ms: now_ms,
    }
}


pub fn apply_template(cache: &mut TemplateCache, mut progress: Progress, def: TemplateDef, session: &Session) -> Progress {
    let key = TemplateKey {
        exporter: session.exporter,
        domain: session.domain,
        template_id: def.template_id,
    };
    if def.fields.is_empty() {
        if def.template_id == WITHDRAW_ALL_TEMPLATE_ID {
            withdraw_scope(cache, session.exporter, session.domain);
        } else {
            withdraw_template(cache, &key);
        }
    } else if progress.exporter_refused {
        refuse(cache);
        progress.refused = progress.refused.saturating_add(1);
    } else {
        let template = build_template(def.fields, session.now_ms);
        let allowed = (1..=session.limits.max_record_bytes).contains(&template.min_record_bytes);
        let stored = if allowed {
            store_template(cache, key, template, session.limits)
        } else {
            Err(refuse(cache))
        };
        progress.exporter_refused = allowed && stored.is_err() && !cache.exporters.contains_key(&session.exporter);
        progress.refused = progress.refused.saturating_add(usize::from(stored.is_err()));
    }
    progress
}


pub fn count_refusal(cache: &mut TemplateCache, reason: FlowDrop) -> FlowDrop {
    if reason == FlowDrop::TemplateRefused {
        refuse(cache);
    }
    reason
}


pub fn apply_template_set(cache: &mut TemplateCache, progress: Progress, body: &[u8], session: &Session) -> Result<Progress, FlowDrop> {
    let defs = read_template_defs(body, session.protocol, session.limits).map_err(|reason| count_refusal(cache, reason))?;
    Ok(defs
        .into_iter()
        .fold(progress, |current, def| apply_template(cache, current, def, session)))
}


pub fn read_variable_length(rest: &mut &[u8]) -> Result<usize, FlowDrop> {
    let first = read_u8(rest)?;
    if first == LONG_VARIABLE_MARKER {
        read_u16(rest).map(usize::from)
    } else {
        Ok(usize::from(first))
    }
}


pub fn take_value<'a>(rest: &mut &'a [u8], field: &TemplateField, limits: &FlowLimits) -> Result<&'a [u8], FlowDrop> {
    let length = if field.variable {
        let declared = read_variable_length(rest)?;
        (declared <= limits.max_record_bytes).then_some(declared).ok_or(FlowDrop::Malformed)?
    } else {
        usize::from(field.length)
    };
    let (value, tail) = rest.split_at_checked(length).ok_or(FlowDrop::Malformed)?;
    *rest = tail;
    Ok(value)
}


pub fn unsigned(value: &[u8]) -> u64 {
    value
        .iter()
        .fold(0, |accumulated, byte| (accumulated << BITS_PER_BYTE) | u64::from(*byte))
}


pub fn address(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        IPV4_BYTES => <[u8; IPV4_BYTES]>::try_from(value).ok().map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        IPV6_BYTES => <[u8; IPV6_BYTES]>::try_from(value).ok().map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
        _ => None,
    }
}


pub fn seconds_to_ms(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX).saturating_mul(MILLIS_PER_SECOND_SIGNED)
}


pub fn apply_field(record: &mut FlowRecord, element: u16, value: &[u8], context: DecodeContext) {
    let number = unsigned(value);
    let narrow_32 = u32::try_from(number).unwrap_or(u32::MAX);
    let narrow_16 = u16::try_from(number).unwrap_or(u16::MAX);
    let narrow_8 = u8::try_from(number).unwrap_or(u8::MAX);
    match element {
        ELEMENT_OCTET_DELTA | ELEMENT_OCTET_TOTAL => record.octets = number,
        ELEMENT_PACKET_DELTA | ELEMENT_PACKET_TOTAL => record.packets = number,
        ELEMENT_PROTOCOL => record.protocol = narrow_8,
        ELEMENT_TOS => record.tos = narrow_8,
        ELEMENT_TCP_FLAGS => record.tcp_flags = u8::try_from(number & BYTE_MASK).unwrap_or(u8::MAX),
        ELEMENT_SOURCE_PORT => record.source_port = narrow_16,
        ELEMENT_DESTINATION_PORT => record.destination_port = narrow_16,
        ELEMENT_SOURCE_IPV4 | ELEMENT_SOURCE_IPV6 => record.source = address(value).unwrap_or(record.source),
        ELEMENT_DESTINATION_IPV4 | ELEMENT_DESTINATION_IPV6 => record.destination = address(value).unwrap_or(record.destination),
        ELEMENT_NEXT_HOP_IPV4 | ELEMENT_NEXT_HOP_IPV6 => record.next_hop = address(value).unwrap_or(record.next_hop),
        ELEMENT_INPUT_INTERFACE => record.input_interface = narrow_32,
        ELEMENT_OUTPUT_INTERFACE => record.output_interface = narrow_32,
        ELEMENT_SOURCE_AS => record.source_as = narrow_32,
        ELEMENT_DESTINATION_AS => record.destination_as = narrow_32,
        ELEMENT_LAST_SWITCHED => record.end_unix_ms = absolute_ms(context.export_ms, context.uptime_ms, narrow_32),
        ELEMENT_FIRST_SWITCHED => record.start_unix_ms = absolute_ms(context.export_ms, context.uptime_ms, narrow_32),
        ELEMENT_START_SECONDS => record.start_unix_ms = seconds_to_ms(number),
        ELEMENT_END_SECONDS => record.end_unix_ms = seconds_to_ms(number),
        ELEMENT_START_MILLIS => record.start_unix_ms = i64::try_from(number).unwrap_or(i64::MAX),
        ELEMENT_END_MILLIS => record.end_unix_ms = i64::try_from(number).unwrap_or(i64::MAX),
        _ => {}
    }
}


pub fn blank_record(export_ms: i64) -> FlowRecord {
    FlowRecord {
        source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        input_interface: 0,
        output_interface: 0,
        packets: 0,
        octets: 0,
        start_unix_ms: export_ms,
        end_unix_ms: export_ms,
        source_port: 0,
        destination_port: 0,
        tcp_flags: 0,
        protocol: 0,
        tos: 0,
        source_as: 0,
        destination_as: 0,
    }
}


pub fn decode_record(rest: &mut &[u8], template: &Template, session: &Session) -> Result<FlowRecord, FlowDrop> {
    let mut record = blank_record(session.context.export_ms);
    template.fields.iter().try_for_each(|field| {
        let value = take_value(rest, field, session.limits)?;
        apply_field(&mut record, field.element, value, session.context);
        Ok::<(), FlowDrop>(())
    })?;
    Ok(record)
}


pub fn decode_data_set(body: &[u8], template: &Template, session: &Session, remaining: usize) -> Result<Vec<FlowRecord>, FlowDrop> {
    let mut rest = body;
    let records = std::iter::from_fn(|| (rest.len() >= template.min_record_bytes).then(|| decode_record(&mut rest, template, session)))
        .take(remaining.saturating_add(1))
        .collect::<Result<Vec<_>, _>>()?;
    (records.len() <= remaining).then_some(()).ok_or(FlowDrop::TooLarge)?;
    (rest.len() <= MAX_PADDING_BYTES).then_some(records).ok_or(FlowDrop::Malformed)
}


pub fn apply_data_set(cache: &mut TemplateCache, mut progress: Progress, set_id: u16, body: &[u8], session: &Session) -> Result<Progress, FlowDrop> {
    let key = TemplateKey {
        exporter: session.exporter,
        domain: session.domain,
        template_id: set_id,
    };
    let found: Option<Arc<Template>> = lookup_template(cache, &key, session.now_ms, session.age_ms);
    match found {
        None => {
            cache.stats.no_template_sets = cache.stats.no_template_sets.saturating_add(1);
            progress.no_template = progress.no_template.saturating_add(1);
        }
        Some(template) => {
            let remaining = session.limits.max_template_records_per_datagram.saturating_sub(progress.records.len());
            progress.records.extend(decode_data_set(body, &template, session, remaining)?);
        }
    }
    Ok(progress)
}


pub fn process_sets(cache: &mut TemplateCache, sets: Vec<(u16, &[u8])>, session: &Session) -> Result<Progress, FlowDrop> {
    expire_exporter(cache, session.exporter, session.now_ms, session.age_ms);
    sets.into_iter()
        .try_fold(Progress::default(), |progress, (set_id, body)| match set_kind(session.protocol, set_id) {
            SetKind::Template => apply_template_set(cache, progress, body, session),
            SetKind::Data => apply_data_set(cache, progress, set_id, body, session),
            SetKind::Skipped => Ok(progress),
        })
}


pub fn finish_batch(progress: Progress, session: &Session) -> Result<FlowBatch, FlowDrop> {
    match (progress.records.is_empty(), progress.no_template > 0, progress.refused > 0) {
        (true, true, _) => Err(FlowDrop::NoTemplate),
        (true, false, true) => Err(FlowDrop::TemplateRefused),
        _ => Ok(FlowBatch {
            export_unix_ms: session.context.export_ms,
            exporter_uptime_ms: session.context.uptime_ms,
            sequence: session.sequence,
            engine_type: 0,
            engine_id: 0,
            sampling_mode: 0,
            sampling_interval: 0,
            records: progress.records,
        }),
    }
}


pub fn run_session(cache: &mut TemplateCache, sets: Vec<(u16, &[u8])>, session: &Session) -> Result<FlowBatch, FlowDrop> {
    let progress = process_sets(cache, sets, session)?;
    finish_batch(progress, session)
}


pub fn check_size(datagram: &[u8]) -> Result<(), FlowDrop> {
    (datagram.len() <= MAX_TEMPLATE_DATAGRAM_BYTES).then_some(()).ok_or(FlowDrop::TooLarge)
}


pub fn parse_netflow_v9(
    datagram: &[u8],
    exporter: IpAddr,
    cache: &mut TemplateCache,
    now_ms: u64,
    limits: &FlowLimits,
) -> Result<FlowBatch, FlowDrop> {
    check_size(datagram)?;
    let mut rest = datagram;
    (read_u16(&mut rest)? == V9_VERSION).then_some(()).ok_or(FlowDrop::Unsupported)?;
    skip(&mut rest, U16_BYTES)?;
    let uptime_ms = read_u32(&mut rest)?;
    let unix_secs = read_u32(&mut rest)?;
    let sequence = read_u32(&mut rest)?;
    let domain = read_u32(&mut rest)?;
    let session = Session {
        protocol: Protocol::V9,
        exporter,
        domain,
        sequence,
        context: DecodeContext {
            export_ms: export_time_ms(unix_secs, 0),
            uptime_ms,
        },
        now_ms,
        age_ms: age_limit_ms(limits),
        limits,
    };
    run_session(cache, split_sets(rest)?, &session)
}


pub fn parse_ipfix(datagram: &[u8], exporter: IpAddr, cache: &mut TemplateCache, now_ms: u64, limits: &FlowLimits) -> Result<FlowBatch, FlowDrop> {
    check_size(datagram)?;
    let mut rest = datagram;
    (read_u16(&mut rest)? == IPFIX_VERSION).then_some(()).ok_or(FlowDrop::Unsupported)?;
    let length = usize::from(read_u16(&mut rest)?);
    let unix_secs = read_u32(&mut rest)?;
    let sequence = read_u32(&mut rest)?;
    let domain = read_u32(&mut rest)?;
    (length == datagram.len()).then_some(()).ok_or(FlowDrop::Malformed)?;
    let session = Session {
        protocol: Protocol::Ipfix,
        exporter,
        domain,
        sequence,
        context: DecodeContext {
            export_ms: export_time_ms(unix_secs, 0),
            uptime_ms: 0,
        },
        now_ms,
        age_ms: age_limit_ms(limits),
        limits,
    };
    run_session(cache, split_sets(rest)?, &session)
}

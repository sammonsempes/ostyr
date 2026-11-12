use crate::error::DiscoveryError;
use crate::model::{Counters, EdgeKey, EdgeStats, Observation, Scope, ServiceMap, LOWEST_KEY, PROTOCOL_SCTP, TCP_SYN, WELL_KNOWN_PORT_LIMIT};
use crate::scope::in_scope;
use crate::types::Millis;
use core_pg::scope::{tenant_of, tenant_scope};
use site_collector::event::clamp_flow_ms;
use site_collector::event_model::{PROTOCOL_TCP, PROTOCOL_UDP};
use site_collector::flow_model::FlowRecord;
use std::collections::{BTreeMap, BTreeSet};


/// An empty map of one tenant (the core-pg grammar) over a checked scope.
pub fn new_service_map(tenant: &str, scope: Scope) -> Result<ServiceMap, DiscoveryError> {
    Ok(ServiceMap {
        tenant: tenant_scope(tenant)?,
        scope,
        edges: BTreeMap::new(),
        by_last_seen: BTreeSet::new(),
        counters: Counters::default(),
    })
}


pub fn edge_count(map: &ServiceMap) -> usize {
    map.edges.len()
}


pub fn counters(map: &ServiceMap) -> Counters {
    map.counters
}


pub fn tenant_name(map: &ServiceMap) -> &str {
    tenant_of(&map.tenant)
}


pub fn scope_of(map: &ServiceMap) -> &Scope {
    &map.scope
}


pub fn edge<'a>(map: &'a ServiceMap, key: &EdgeKey) -> Option<&'a EdgeStats> {
    map.edges.get(key)
}


pub fn edges(map: &ServiceMap) -> impl Iterator<Item = (&EdgeKey, &EdgeStats)> {
    map.edges.iter()
}


/// A TCP record carrying SYN from a higher to a lower port: the client's side of a connection, so the destination serves.
pub fn is_client_syn(record: &FlowRecord) -> bool {
    record.protocol == PROTOCOL_TCP && record.tcp_flags & TCP_SYN != 0 && record.source_port > record.destination_port
}


/// The edge of one record: client, service side and service port (rule in the crate notes).
pub fn edge_key(record: &FlowRecord) -> EdgeKey {
    let source = record.source.to_canonical();
    let destination = record.destination.to_canonical();
    let has_ports = matches!(record.protocol, PROTOCOL_TCP | PROTOCOL_UDP | PROTOCOL_SCTP);
    let source_serves = !is_client_syn(record) && record.source_port < WELL_KNOWN_PORT_LIMIT && record.source_port < record.destination_port;
    match (has_ports, source_serves) {
        (false, _) => EdgeKey {
            source,
            destination,
            port: 0,
            protocol: record.protocol,
        },
        (true, true) => EdgeKey {
            source: destination,
            destination: source,
            port: record.source_port,
            protocol: record.protocol,
        },
        (true, false) => EdgeKey {
            source,
            destination,
            port: record.destination_port,
            protocol: record.protocol,
        },
    }
}


/// The edge a record is recorded on: the reply of a service on a port of 1024 or above joins the edge its connection already has.
pub fn resolve_key(map: &ServiceMap, record: &FlowRecord) -> EdgeKey {
    let key = edge_key(record);
    let service_is_source = EdgeKey {
        source: record.destination.to_canonical(),
        destination: record.source.to_canonical(),
        port: record.source_port,
        protocol: record.protocol,
    };
    let has_ports = matches!(record.protocol, PROTOCOL_TCP | PROTOCOL_UDP | PROTOCOL_SCTP);
    let joins = has_ports && !is_client_syn(record) && !map.edges.contains_key(&key) && map.edges.contains_key(&service_is_source);
    if joins {
        service_is_source
    } else {
        key
    }
}


/// First and last seen of a record, as `flow_events` clamps them: an out-of-range time makes both the receive time; never beyond `now_ms`.
pub fn seen_times(record: &FlowRecord, now_ms: Millis) -> (Millis, Millis, bool) {
    let (start, start_clamped) = clamp_flow_ms(record.start_unix_ms, now_ms);
    let (end, end_clamped) = clamp_flow_ms(record.end_unix_ms, now_ms);
    let clamped = start_clamped || end_clamped;
    let (first_raw, last_raw) = if clamped { (now_ms, now_ms) } else { (start, end) };
    (first_raw.min(last_raw).min(now_ms), first_raw.max(last_raw).min(now_ms), clamped)
}


fn evict_oldest(map: &mut ServiceMap) {
    map.by_last_seen.pop_first().iter().for_each(|(_, key)| {
        map.edges.remove(key);
        map.counters.evicted += 1;
    });
}


fn record_edge(map: &mut ServiceMap, key: EdgeKey, record: &FlowRecord, first_ms: Millis, last_ms: Millis) {
    let previous = map.edges.get(&key).map(|stats| stats.last_seen_ms);
    previous.iter().for_each(|seen| {
        map.by_last_seen.remove(&(*seen, key));
    });
    if previous.is_none() && map.edges.len() >= map.scope.max_edges {
        evict_oldest(map);
    }
    let stats = map.edges.entry(key).or_insert(EdgeStats {
        first_seen_ms: first_ms,
        last_seen_ms: last_ms,
        bytes: 0,
        packets: 0,
        flows: 0,
    });
    stats.first_seen_ms = stats.first_seen_ms.min(first_ms);
    stats.last_seen_ms = stats.last_seen_ms.max(last_ms);
    stats.bytes = stats.bytes.saturating_add(record.octets);
    stats.packets = stats.packets.saturating_add(record.packets);
    stats.flows = stats.flows.saturating_add(1);
    map.by_last_seen.insert((stats.last_seen_ms, key));
    map.counters.recorded += 1;
}


fn observe_in_tenant(map: &mut ServiceMap, record: &FlowRecord, now_ms: Millis) -> Observation {
    let owned = in_scope(&map.scope, record.source.to_canonical()) || in_scope(&map.scope, record.destination.to_canonical());
    if owned {
        let (first_ms, last_ms, clamped) = seen_times(record, now_ms);
        map.counters.clamped_times += u64::from(clamped);
        record_edge(map, resolve_key(map, record), record, first_ms, last_ms);
        Observation::Recorded
    } else {
        map.counters.out_of_scope += 1;
        Observation::OutOfScope
    }
}


/// Adds a record of the batch stamped `batch_tenant`; a foreign tenant or foreign addresses only bump a counter.
pub fn observe(map: &mut ServiceMap, batch_tenant: &str, record: &FlowRecord, now_ms: Millis) -> Observation {
    if tenant_of(&map.tenant) == batch_tenant {
        observe_in_tenant(map, record, now_ms)
    } else {
        map.counters.wrong_tenant += 1;
        Observation::WrongTenant
    }
}


/// Drops every edge last seen more than the retention before `now_ms`; returns how many.
pub fn expire(map: &mut ServiceMap, now_ms: Millis) -> usize {
    let cutoff = now_ms.saturating_sub(map.scope.retention_ms);
    let kept = map.by_last_seen.split_off(&(cutoff, LOWEST_KEY));
    let expired = std::mem::replace(&mut map.by_last_seen, kept);
    expired.iter().for_each(|(_, key)| {
        map.edges.remove(key);
    });
    map.counters.expired = expired.iter().fold(map.counters.expired, |count, _| count.saturating_add(1));
    expired.len()
}

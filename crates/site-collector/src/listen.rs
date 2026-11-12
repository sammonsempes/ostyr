use crate::admission::{new_collector, prune_idle, reconfigure};
use crate::error::ListenError;
use crate::flow_listen::handle_flow_datagram;
use crate::flow_model::MAX_TEMPLATE_DATAGRAM_BYTES;
use crate::listen_model::{
    ListenerKind, ListenerSettings, ListenerStats, Runtime, SharedSocket, ERROR_BACKOFF_MS, HIGH_SEVERITY_MAX, IDLE_SOURCE_MS, MAX_CYCLES,
    PRUNE_INTERVAL_MS, SEVERITY_MASK,
};
use crate::listen_settings::{collector_config_of, declared_keys, source_key};
use crate::model::{DropReason, Outcome, MAX_MESSAGE_BYTES};
use crate::process::process_datagram;
use crate::spool::append;
use crate::spool_model::{Priority, Spool};
use crate::template::set_declared;
use crate::template::{age_limit_ms, prune_expired};
use crate::template_model::TemplateCache;
use crate::types::{Millis, NowFn, RecvFn, YearFn};
use core_config::reload::{current_config, ReloadEngine};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;


pub fn open_runtime(settings: Arc<ListenerSettings>, spool: Spool) -> Result<Runtime, ListenError> {
    Ok(Runtime {
        collector: new_collector(collector_config_of(&settings))?,
        spool,
        stats: ListenerStats::default(),
        templates: TemplateCache {
            declared: declared_keys(&settings),
            ..TemplateCache::default()
        },
        applied: settings,
        last_prune_ms: 0,
    })
}


/// The tenant of every record of this collector: it comes from the settings, a datagram never chooses it.
pub fn listener_tenant(runtime: &Runtime) -> &str {
    &runtime.applied.tenant
}


pub fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}


pub fn priority_of(syslog_priority: u8) -> Priority {
    if syslog_priority & SEVERITY_MASK <= HIGH_SEVERITY_MAX {
        Priority::High
    } else {
        Priority::Low
    }
}


pub fn count_reason(stats: &mut ListenerStats, reason: DropReason) {
    match reason {
        DropReason::UnknownSource => bump(&mut stats.dropped_unknown),
        DropReason::TooLarge | DropReason::TrapTooLarge | DropReason::FlowTooLarge => bump(&mut stats.dropped_too_long),
        DropReason::TrapMalformed
        | DropReason::TrapUnsupported
        | DropReason::FlowMalformed
        | DropReason::FlowUnsupported
        | DropReason::FlowNoTemplate
        | DropReason::FlowTemplateRefused => bump(&mut stats.dropped_parse),
        DropReason::SourceRate | DropReason::UnknownRate | DropReason::GlobalRate => bump(&mut stats.dropped_rate),
        DropReason::SourceTableFull => bump(&mut stats.dropped_table_full),
    }
}


/// Applies the settings snapshot of the engine to the collector when it changed since the last cycle.
pub fn sync_settings(runtime: &mut Runtime, engine: &ReloadEngine<ListenerSettings>) {
    let snapshot = current_config(engine);
    if !Arc::ptr_eq(&snapshot, &runtime.applied) {
        let outcome = reconfigure(&mut runtime.collector, collector_config_of(&snapshot));
        if let Err(error) = &outcome {
            tracing::error!(%error, "collector limits refused, previous limits kept");
        }
        set_declared(&mut runtime.templates, declared_keys(&snapshot));
        runtime.applied = snapshot;
    }
}


/// The receive buffer holds one byte more than the largest datagram of the listener kind, so a longer datagram is seen as too large.
pub fn receive_buffer_len(kind: ListenerKind) -> usize {
    match kind {
        ListenerKind::Syslog => MAX_MESSAGE_BYTES + 1,
        ListenerKind::Netflow => MAX_TEMPLATE_DATAGRAM_BYTES + 1,
    }
}


/// One datagram of a listener: a syslog one is stored as received, a flow one is parsed first and stored as one frame per record.
pub fn handle_datagram(runtime: &mut Runtime, source: SocketAddr, payload: &[u8], now: Millis, year: i32) {
    match runtime.applied.kind {
        ListenerKind::Syslog => handle_syslog_datagram(runtime, source, payload, now, year),
        ListenerKind::Netflow => handle_flow_datagram(runtime, source, payload, now),
    }
}


/// Admission, parsing, then the spool: only an admitted and well-formed message is stored, as received.
pub fn handle_syslog_datagram(runtime: &mut Runtime, source: SocketAddr, payload: &[u8], now: Millis, year: i32) {
    bump(&mut runtime.stats.received);
    match process_datagram(&mut runtime.collector, source_key(source.ip()), payload, now, year) {
        Outcome::Accepted(record) => match append(&mut runtime.spool, priority_of(record.priority), payload) {
            Ok(_) => bump(&mut runtime.stats.accepted),
            Err(error) => {
                bump(&mut runtime.stats.spool_errors);
                tracing::error!(%error, %source, "cannot append an admitted record to the spool");
            }
        },
        Outcome::Dropped(reason) => count_reason(&mut runtime.stats, reason),
        Outcome::Malformed(_) => bump(&mut runtime.stats.dropped_parse),
    }
}


pub fn prune_if_due(runtime: &mut Runtime, now: Millis) {
    if now.saturating_sub(runtime.last_prune_ms) >= PRUNE_INTERVAL_MS {
        prune_idle(&mut runtime.collector, now, IDLE_SOURCE_MS);
        if runtime.applied.kind == ListenerKind::Netflow {
            prune_expired(&mut runtime.templates, now, age_limit_ms(&runtime.applied.flow));
        }
        runtime.last_prune_ms = now;
    }
}


/// One receive: a read timeout is an idle cycle, any other error is counted, logged and followed by a short pause.
pub fn receive_cycle(
    runtime: &mut Runtime,
    engine: &ReloadEngine<ListenerSettings>,
    buffer: &mut [u8],
    recv: &mut RecvFn,
    now: &NowFn,
    year: &YearFn,
) {
    sync_settings(runtime, engine);
    let received = recv(buffer);
    let now_ms = now();
    match received {
        Ok((length, source)) => {
            let (payload, _rest) = buffer.split_at(length.min(buffer.len()));
            handle_datagram(runtime, source, payload, now_ms, year());
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        Err(error) => {
            bump(&mut runtime.stats.receive_errors);
            tracing::error!(%error, "receive on the syslog socket failed");
            std::thread::sleep(Duration::from_millis(ERROR_BACKOFF_MS));
        }
    }
    prune_if_due(runtime, now_ms);
}


/// Receives until `shutdown` is raised; the flag is read once per cycle and a cycle lasts at most the socket read timeout.
pub fn run(runtime: &mut Runtime, engine: &ReloadEngine<ListenerSettings>, shared: &SharedSocket, shutdown: &AtomicBool, now: &NowFn, year: &YearFn) {
    let mut buffer = vec![0u8; receive_buffer_len(runtime.applied.kind)];
    let mut recv = |target: &mut [u8]| shared.bound.load().socket.recv_from(target);
    (0..MAX_CYCLES)
        .take_while(|_| !shutdown.load(Ordering::Relaxed))
        .for_each(|_| receive_cycle(runtime, engine, &mut buffer, &mut recv, now, year));
}

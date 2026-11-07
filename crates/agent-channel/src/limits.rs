use crate::model::{AgentLoad, ChannelSettings, Counters, Identity, ServerState, SlotKind, SlotPermit, MAX_LOGGED_TEXT_CHARS, TRUNCATION_MARKER};
use crate::types::SharedState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tonic::{Code, Status};


pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}


/// No code holding the lock can panic, so a poisoned lock still guards consistent data.
pub fn lock_load(state: &ServerState) -> MutexGuard<'_, HashMap<Identity, AgentLoad>> {
    state.load.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn fresh_load(now: Instant) -> AgentLoad {
    AgentLoad {
        connections: 0,
        streams: 0,
        inflight: 0,
        window_started: now,
        window_count: 0,
    }
}


/// Counts one request in the current window, opening a new window once `window` has elapsed; false when `maximum` is exceeded.
pub fn count_request(load: &mut AgentLoad, now: Instant, window: Duration, maximum: u32) -> bool {
    if now.saturating_duration_since(load.window_started) >= window {
        load.window_started = now;
        load.window_count = 0;
    }
    load.window_count = load.window_count.saturating_add(1);
    load.window_count <= maximum
}


/// Refuses with `ResourceExhausted`, counted and logged, an agent above its request rate.
pub fn admit_request(state: &ServerState, identity: &Identity) -> Result<(), Status> {
    let now = Instant::now();
    let window = Duration::from_secs(state.settings.rate_window_seconds);
    let admitted = {
        let mut loads = lock_load(state);
        let load = loads.entry(identity.clone()).or_insert_with(|| fresh_load(now));
        count_request(load, now, window, state.settings.max_requests_per_window)
    };
    if admitted {
        Ok(())
    } else {
        bump(&state.counters.rate_limited);
        tracing::warn!(tenant = %identity.tenant, agent = %identity.agent_id, "agent request rate exceeded, request refused");
        Err(Status::resource_exhausted("request rate exceeded"))
    }
}


pub fn slot_count(load: &mut AgentLoad, kind: SlotKind) -> &mut usize {
    match kind {
        SlotKind::Connection => &mut load.connections,
        SlotKind::Stream => &mut load.streams,
        SlotKind::Inflight => &mut load.inflight,
    }
}


pub fn slot_limit(settings: &ChannelSettings, kind: SlotKind) -> usize {
    match kind {
        SlotKind::Connection => settings.max_connections_per_agent,
        SlotKind::Stream => settings.max_streams_per_agent,
        SlotKind::Inflight => settings.max_inflight_per_agent,
    }
}


pub fn slot_refusals(counters: &Counters, kind: SlotKind) -> &AtomicU64 {
    match kind {
        SlotKind::Connection => &counters.connection_limited,
        SlotKind::Stream => &counters.stream_limited,
        SlotKind::Inflight => &counters.inflight_limited,
    }
}


/// Takes one slot of `kind` for the agent, or refuses with `ResourceExhausted`, counted and logged.
pub fn open_slot(state: &SharedState, identity: &Identity, kind: SlotKind) -> Result<SlotPermit, Status> {
    let opened = {
        let mut loads = lock_load(state);
        let load = loads.entry(identity.clone()).or_insert_with(|| fresh_load(Instant::now()));
        let limit = slot_limit(&state.settings, kind);
        let held = slot_count(load, kind);
        let free = *held < limit;
        *held = held.saturating_add(usize::from(free));
        free
    };
    if opened {
        Ok(SlotPermit {
            state: Arc::clone(state),
            identity: identity.clone(),
            kind,
        })
    } else {
        bump(slot_refusals(&state.counters, kind));
        tracing::warn!(tenant = %identity.tenant, agent = %identity.agent_id, ?kind, "agent concurrent slots exceeded, refused");
        Err(Status::resource_exhausted("too many concurrent connections, streams or requests"))
    }
}


/// Takes one of the agent stream slots.
pub fn open_stream(state: &SharedState, identity: &Identity) -> Result<SlotPermit, Status> {
    open_slot(state, identity, SlotKind::Stream)
}


impl Drop for SlotPermit {
    fn drop(&mut self) {
        let kind = self.kind;
        lock_load(&self.state)
            .entry(self.identity.clone())
            .and_modify(|load| *slot_count(load, kind) = slot_count(load, kind).saturating_sub(1));
    }
}


/// Agent text cut to `MAX_LOGGED_TEXT_CHARS` characters with a marker; log it with `?` so control characters are escaped.
pub fn bounded_text(text: &str) -> String {
    let kept: String = text.chars().take(MAX_LOGGED_TEXT_CHARS).collect();
    if kept.len() < text.len() {
        kept + TRUNCATION_MARKER
    } else {
        kept
    }
}


pub fn claim_matches(claim: &str, actual: &str) -> bool {
    claim.is_empty() || claim == actual
}


/// A payload may name its agent and tenant, but only to be checked: a name other than the certificate's is refused, counted and logged.
pub fn check_claim(state: &ServerState, identity: &Identity, tenant: &str, agent_id: &str) -> Result<(), Status> {
    if claim_matches(tenant, &identity.tenant) && claim_matches(agent_id, &identity.agent_id) {
        Ok(())
    } else {
        bump(&state.counters.identity_mismatch);
        let claimed_tenant = bounded_text(tenant);
        let claimed_agent = bounded_text(agent_id);
        tracing::warn!(agent = %identity.agent_id, ?claimed_tenant, ?claimed_agent, "payload names another agent or tenant");
        Err(Status::permission_denied("payload names another agent or tenant than the certificate"))
    }
}


/// A message above the decoding bound is refused by the codec with `OutOfRange`; this counts and logs it.
pub fn count_oversized(state: &ServerState, status: &Status) {
    if status.code() == Code::OutOfRange {
        bump(&state.counters.oversized);
        tracing::warn!(limit = state.settings.max_message_bytes, "message above the size bound refused");
    }
}

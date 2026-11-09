use crate::types::Stored;
use agent_channel::limits::system_now;
use agent_channel::model::{ChannelSettings, Counters, Identity, ServerState};
use agent_channel::proto::EventBatch;
use agent_channel::settings::shared_settings;
use agent_channel::types::{AuditSink, CommandSource, EventSink, SharedSettings, SharedState};
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use futures_util::stream;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};


pub fn new_stored() -> Stored {
    Arc::new(Mutex::new(Vec::new()))
}


pub fn recording_sink(stored: Stored) -> EventSink {
    Box::new(move |identity: Identity, batch: EventBatch| {
        let sink_stored = Arc::clone(&stored);
        Box::pin(async move {
            sink_stored.lock().map_err(|_| "poisoned")?.push((identity, batch.sequence));
            Ok(())
        })
    })
}


pub fn failing_sink() -> EventSink {
    Box::new(|_identity: Identity, _batch: EventBatch| Box::pin(async { Err("disk full".into()) }))
}


pub fn envelope_source(envelopes: Vec<Vec<u8>>) -> CommandSource {
    Box::new(move |_identity: Identity| Box::pin(stream::iter(envelopes.clone())))
}


pub fn discarding_audit() -> AuditSink {
    let log = genesis_log(io::sink());
    Box::new(move |entry| append(&log, entry))
}


pub fn recording_audit(recorded: Arc<Mutex<Vec<NewEntry>>>) -> AuditSink {
    let log = genesis_log(io::sink());
    Box::new(move |entry| {
        recorded.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    })
}


pub fn make_state(settings: ChannelSettings, events: EventSink, commands: CommandSource) -> SharedState {
    make_audited_state(settings, events, commands, discarding_audit())
}


pub fn make_audited_state(settings: ChannelSettings, events: EventSink, commands: CommandSource, audit: AuditSink) -> SharedState {
    Arc::new(ServerState {
        settings: shared_settings(settings),
        counters: Counters::default(),
        load: Mutex::new(HashMap::new()),
        events,
        commands,
        presence: Mutex::new(HashMap::new()),
        audit,
        now: Box::new(system_now),
    })
}


pub fn default_state() -> SharedState {
    make_state(ChannelSettings::default(), recording_sink(new_stored()), envelope_source(Vec::new()))
}


pub fn make_live_state(settings: SharedSettings) -> SharedState {
    Arc::new(ServerState {
        settings,
        counters: Counters::default(),
        load: Mutex::new(HashMap::new()),
        events: recording_sink(new_stored()),
        commands: envelope_source(Vec::new()),
        presence: Mutex::new(HashMap::new()),
        audit: discarding_audit(),
        now: Box::new(system_now),
    })
}

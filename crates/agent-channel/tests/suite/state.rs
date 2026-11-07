use crate::types::Stored;
use agent_channel::model::{ChannelSettings, Counters, Identity, ServerState};
use agent_channel::proto::EventBatch;
use agent_channel::types::{CommandSource, EventSink, SharedState};
use futures_util::stream;
use std::collections::HashMap;
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


pub fn make_state(settings: ChannelSettings, events: EventSink, commands: CommandSource) -> SharedState {
    Arc::new(ServerState {
        settings,
        counters: Counters::default(),
        load: Mutex::new(HashMap::new()),
        events,
        commands,
    })
}


pub fn default_state() -> SharedState {
    make_state(ChannelSettings::default(), recording_sink(new_stored()), envelope_source(Vec::new()))
}

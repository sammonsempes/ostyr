use crate::limits::lock_presence;
use crate::model::{Identity, Presence, ServerState, AUDIT_ACTOR, AUDIT_MODULE, BACK_ACTION, SILENT_ACTION};
use crate::settings::settings_of;
use crate::types::SharedState;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use futures_util::StreamExt;
use std::future::Future;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;


/// A system audit record about one agent; `silent_seconds` is how long the agent had been quiet.
pub fn presence_entry(identity: &Identity, action: &str, outcome: Outcome, silent_seconds: u64) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: AUDIT_ACTOR.to_owned(),
        },
        tenant: identity.tenant.clone(),
        module: AUDIT_MODULE.to_owned(),
        action: action.to_owned(),
        target: identity.agent_id.clone(),
        outcome,
        request_id: format!("{action}:{}", identity.agent_id),
        justification: None,
        parameters: [("silent_seconds".to_owned(), silent_seconds.to_string())].into(),
    }
}


/// A failing audit log is logged, never silent; the agent state is not rolled back so one failure cannot repeat the record in a loop.
pub fn write_audit(state: &ServerState, entry: NewEntry) {
    if let Err(error) = (state.audit)(entry) {
        tracing::warn!(%error, "agent presence audit record not written");
    }
}


/// Stores the heartbeat time; an agent that was recorded silent gets one `agent.back` record, written under the presence lock so it follows its `agent.silent`.
pub fn record_beat(state: &ServerState, identity: &Identity, now: Instant) {
    let mut presence = lock_presence(state);
    let previous = presence.insert(
        identity.clone(),
        Presence {
            last_beat: now,
            silent: false,
        },
    );
    if previous.is_some_and(|before| before.silent) {
        write_audit(state, presence_entry(identity, BACK_ACTION, Outcome::Success, 0));
    }
}


/// Writes one `agent.silent` record, under the presence lock, per agent quiet for longer than the threshold and not yet recorded; returns how many.
pub fn check_silence(state: &ServerState, now: Instant) -> usize {
    let threshold = Duration::from_secs(settings_of(state).silence_threshold_seconds);
    let mut presence = lock_presence(state);
    let newly_silent: Vec<(Identity, u64)> = presence
        .iter_mut()
        .filter(|(_identity, entry)| !entry.silent && now.saturating_duration_since(entry.last_beat) > threshold)
        .map(|(identity, entry)| {
            entry.silent = true;
            (identity.clone(), now.saturating_duration_since(entry.last_beat).as_secs())
        })
        .collect();
    newly_silent
        .iter()
        .for_each(|(identity, silent_seconds)| write_audit(state, presence_entry(identity, SILENT_ACTION, Outcome::Failure, *silent_seconds)));
    newly_silent.len()
}


/// Checks for silent agents every `silence_check_interval_seconds` (at least one) until `shutdown` completes.
pub async fn watch_silence(state: SharedState, shutdown: impl Future<Output = ()>) {
    let period = Duration::from_secs(settings_of(&state).silence_check_interval_seconds.max(1));
    IntervalStream::new(interval(period))
        .take_until(shutdown)
        .for_each(|_tick| {
            check_silence(&state, Instant::now());
            std::future::ready(())
        })
        .await;
}

use crate::error::GatewayError;
use crate::model::{Gateway, GatewaySettings, RefusalCounts, Refusals, Slot, SummaryTask};
use crate::session::{session_for, settings_of};
use agent_channel::model::Identity;
use agent_channel::proto::EventBatch;
use agent_channel::types::{BoxError, EventSink};
use async_nats::header::NATS_MESSAGE_ID;
use async_nats::jetstream::context::PublishError;
use async_nats::jetstream::Context;
use async_nats::HeaderMap;
use bytes::Bytes;
use futures_util::future::try_join_all;
use futures_util::stream::{self, StreamExt};
use serde_json::{Map, Value};
use siem_ingest::nats::millis;
use siem_ingest::settings::DEFAULT_MAX_TENANT_BYTES;
use siem_ingest::tenant::{is_tenant_char, tenant_from_subject, EVENTS_SUBJECT_PREFIX};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};


/// The top-level field an event may claim a tenant in; the identity tenant always wins.
pub const TENANT_FIELD: &str = "tenant";


/// Bytes a header block adds to a message: the status line, the header name and the line ends.
pub const HEADER_OVERHEAD: usize = 32;


/// One event ready to publish.
pub struct Outgoing {
    pub subject: String,
    pub id: String,
    pub payload: Bytes,
}


/// Takes one in-flight place, or refuses at once: the agent resends after its backoff.
pub fn admit(counter: &Arc<AtomicUsize>, max: usize) -> Result<Slot, GatewayError> {
    let before = counter.fetch_add(1, Ordering::SeqCst);
    let slot = Slot {
        counter: Arc::clone(counter),
    };
    if before >= max {
        Err(GatewayError::Busy { max })
    } else {
        Ok(slot)
    }
}


/// The tenant and agent id go into a NATS subject and a message id, so only the subject token characters pass.
pub fn check_identity(identity: &Identity) -> Result<(), GatewayError> {
    let subject = format!("{EVENTS_SUBJECT_PREFIX}.{}", identity.tenant);
    let tenant_usable = tenant_from_subject(&subject, EVENTS_SUBJECT_PREFIX, DEFAULT_MAX_TENANT_BYTES).is_ok();
    if tenant_usable && !identity.agent_id.is_empty() && identity.agent_id.chars().all(is_tenant_char) {
        Ok(())
    } else {
        Err(GatewayError::Identity)
    }
}


/// The events of a batch: one per non-empty line of `ecs_json`.
pub fn events_of(ecs_json: &[u8]) -> Vec<&[u8]> {
    ecs_json.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).collect()
}


/// Every event is parsed as exactly one JSON object and re-encoded with the identity tenant written over `tenant`; anything else is refused.
pub fn forced_payload(event: &[u8], tenant: &str) -> Result<Bytes, GatewayError> {
    let mut fields = serde_json::from_slice::<Map<String, Value>>(event).map_err(GatewayError::NotAnObject)?;
    fields.insert(TENANT_FIELD.to_owned(), Value::String(tenant.to_owned()));
    serde_json::to_vec(&fields).map(Bytes::from).map_err(GatewayError::Encode)
}


/// `<tenant>:<agent id>:<sequence>:<index>`: a replay of a batch gets the same ids, so the stream's duplicate window drops it.
pub fn message_id(identity: &Identity, sequence: u64, index: usize) -> String {
    format!("{}:{}:{sequence}:{index}", identity.tenant, identity.agent_id)
}


/// Every event of the batch, built and size-checked before anything is published.
pub fn outgoing_events(
    identity: &Identity,
    batch: &EventBatch,
    settings: &GatewaySettings,
    max_payload: usize,
) -> Result<Vec<Outgoing>, GatewayError> {
    check_identity(identity)?;
    let events = events_of(&batch.ecs_json);
    if events.len() > settings.max_events_per_batch {
        Err(GatewayError::TooManyEvents {
            count: events.len(),
            max: settings.max_events_per_batch,
        })
    } else {
        events
            .into_iter()
            .zip(0..)
            .map(|(event, index)| {
                let payload = forced_payload(event, &identity.tenant)?;
                let id = message_id(identity, batch.sequence, index);
                let size = payload.len() + id.len() + HEADER_OVERHEAD;
                if size > max_payload {
                    Err(GatewayError::PayloadTooLarge { size, max: max_payload })
                } else {
                    Ok(Outgoing {
                        subject: format!("{EVENTS_SUBJECT_PREFIX}.{}", identity.tenant),
                        id,
                        payload,
                    })
                }
            })
            .collect()
    }
}


/// Sends one event and waits for the stream's confirmation.
pub async fn publish_one(jetstream: &Context, event: Outgoing) -> Result<(), GatewayError> {
    let mut headers = HeaderMap::new();
    headers.insert(NATS_MESSAGE_ID, event.id.as_str());
    let confirmation = jetstream
        .publish_with_headers(event.subject, headers, event.payload)
        .await
        .map_err(publish_failure)?;
    confirmation.await.map(|_| ()).map_err(publish_failure)
}


/// The cause stays in the source chain; the text of the error is fixed.
pub fn publish_failure(error: PublishError) -> GatewayError {
    GatewayError::Publish(Box::new(error))
}


/// Connect, check, publish every event and wait for every confirmation.
pub async fn deliver(gateway: &Gateway, settings: &Arc<GatewaySettings>, identity: &Identity, batch: &EventBatch) -> Result<(), GatewayError> {
    let (client, jetstream) = session_for(gateway, settings).await?;
    let events = outgoing_events(identity, batch, settings, client.max_payload())?;
    try_join_all(events.into_iter().map(|event| publish_one(&jetstream, event)))
        .await
        .map(|_| ())
}


/// Publishes a whole batch under one deadline and one in-flight place; the batch is acknowledged only when this returns `Ok`.
pub async fn publish_batch(gateway: &Gateway, identity: &Identity, batch: &EventBatch) -> Result<(), GatewayError> {
    let outcome = try_publish(gateway, identity, batch).await;
    if let Err(error) = &outcome {
        count_refusal(&gateway.refusals, error);
    }
    outcome
}


/// The counter of a refusal kind; failures of NATS itself are not refusals.
pub fn counter_for<'a>(refusals: &'a Refusals, error: &GatewayError) -> Option<&'a AtomicU64> {
    match error {
        GatewayError::NotAnObject(_) => Some(&refusals.not_an_object),
        GatewayError::PayloadTooLarge { .. } => Some(&refusals.payload_too_large),
        GatewayError::TooManyEvents { .. } => Some(&refusals.too_many_events),
        GatewayError::Identity => Some(&refusals.invalid_identity),
        GatewayError::Busy { .. } => Some(&refusals.busy),
        GatewayError::BackingOff => Some(&refusals.backing_off),
        _ => None,
    }
}


pub fn count_refusal(refusals: &Refusals, error: &GatewayError) {
    counter_for(refusals, error).iter().for_each(|counter| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
}


pub fn refusal_counts(refusals: &Refusals) -> RefusalCounts {
    RefusalCounts {
        not_an_object: refusals.not_an_object.load(Ordering::SeqCst),
        payload_too_large: refusals.payload_too_large.load(Ordering::SeqCst),
        too_many_events: refusals.too_many_events.load(Ordering::SeqCst),
        invalid_identity: refusals.invalid_identity.load(Ordering::SeqCst),
        busy: refusals.busy.load(Ordering::SeqCst),
        backing_off: refusals.backing_off.load(Ordering::SeqCst),
    }
}


/// Logs the counters and returns what was logged.
pub fn log_summary(refusals: &Refusals) -> RefusalCounts {
    let counts = refusal_counts(refusals);
    info!(?counts, "refused batches since the start");
    counts
}


/// Logs the refusal counters every `period` until the returned task is dropped.
pub fn spawn_summary(refusals: Arc<Refusals>, period: Duration) -> SummaryTask {
    let ticks = stream::unfold((), move |()| async move {
        tokio::time::sleep(period).await;
        Some(((), ()))
    });
    let handle = tokio::spawn(ticks.for_each(move |()| {
        let shared = Arc::clone(&refusals);
        async move {
            log_summary(&shared);
        }
    }));
    SummaryTask { handle }
}


pub async fn try_publish(gateway: &Gateway, identity: &Identity, batch: &EventBatch) -> Result<(), GatewayError> {
    let settings = settings_of(gateway);
    let _slot = admit(&gateway.in_flight, settings.max_in_flight_batches)?;
    let deadline = millis(settings.connect_timeout_ms + settings.publish_timeout_ms);
    tokio::time::timeout(deadline, deliver(gateway, &settings, identity, batch))
        .await
        .map_err(GatewayError::Timeout)
        .and_then(|delivered| delivered)
}


pub fn log_refusal(identity: &Identity, error: &GatewayError) {
    warn!(tenant = %identity.tenant, agent = %identity.agent_id, %error, "a batch was not published");
}


/// The agent channel sink: `Ok` only after JetStream confirmed every event of the batch.
pub fn gateway_sink(shared: Arc<Gateway>) -> EventSink {
    Box::new(move |identity, batch| {
        let gateway = Arc::clone(&shared);
        Box::pin(async move {
            let outcome = publish_batch(&gateway, &identity, &batch).await;
            if let Err(error) = &outcome {
                log_refusal(&identity, error);
            } else {
                info!(tenant = %identity.tenant, sequence = batch.sequence, "a batch was published");
            }
            outcome.map_err(BoxError::from)
        })
    })
}

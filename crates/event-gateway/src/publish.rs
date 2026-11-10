use crate::error::GatewayError;
use crate::model::{Gateway, GatewaySettings, Slot};
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
use serde_json::{Map, Value};
use siem_ingest::nats::millis;
use siem_ingest::tenant::{is_tenant_char, EVENTS_SUBJECT_PREFIX};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
    let usable = |text: &str| !text.is_empty() && text.chars().all(is_tenant_char);
    if usable(&identity.tenant) && usable(&identity.agent_id) {
        Ok(())
    } else {
        Err(GatewayError::Identity)
    }
}


/// The events of a batch: one per non-empty line of `ecs_json`.
pub fn events_of(ecs_json: &[u8]) -> Vec<&[u8]> {
    ecs_json.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).collect()
}


/// An event whose `tenant` field differs from the identity gets the identity tenant written over it; anything else is published as it is.
pub fn forced_payload(event: &[u8], tenant: &str) -> Result<Bytes, GatewayError> {
    match serde_json::from_slice::<Map<String, Value>>(event) {
        Ok(mut fields) if fields.get(TENANT_FIELD).is_some_and(|claimed| claimed != tenant) => {
            fields.insert(TENANT_FIELD.to_owned(), Value::String(tenant.to_owned()));
            serde_json::to_vec(&fields).map(Bytes::from).map_err(GatewayError::Encode)
        }
        _ => Ok(Bytes::copy_from_slice(event)),
    }
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

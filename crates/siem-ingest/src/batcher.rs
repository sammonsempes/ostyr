use crate::error::PushError;
use crate::model::{Batch, Batcher, DeadLetter, Document, FlushReport, Message};
use crate::parse::{check_message, truncate_reason};
use crate::settings::{IngestSettings, MODULE};
use crate::types::{ClockFn, SinkFn, SleepFn};
use core_config::reload::{current_config, ReloadEngine};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{debug, warn};


const BACKOFF_FACTOR: u64 = 2;


const NO_TENANT: &str = "";


const NO_ATTEMPT: &str = "no delivery attempt was made";


pub fn system_clock() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}


pub fn real_sleep(delay: Duration) {
    std::thread::sleep(delay);
}


pub fn new_batcher(settings: Arc<ReloadEngine<IngestSettings>>, sink: Box<SinkFn>, clock: Box<ClockFn>, sleep: Box<SleepFn>) -> Batcher {
    Batcher {
        settings,
        batch: Batch::default(),
        sink,
        clock,
        sleep,
    }
}


pub fn buffered_messages(batch: &Batch) -> usize {
    batch.documents.len() + batch.dead.len()
}


/// A batch is due on its message count, its payload bytes, or the age of its first message.
pub fn is_due(batch: &Batch, settings: &IngestSettings, now: OffsetDateTime) -> bool {
    let max_age = time::Duration::seconds(i64::from(settings.max_batch_age_seconds));
    buffered_messages(batch) >= settings.max_batch_messages
        || batch.bytes >= settings.max_batch_bytes
        || batch.opened_at.is_some_and(|opened| now - opened >= max_age)
}


/// Exponential delay `initial * 2^attempt`, capped at `backoff_max_ms`.
pub fn backoff_delay(settings: &IngestSettings, attempt: u32) -> Duration {
    Duration::from_millis(
        settings
            .backoff_initial_ms
            .saturating_mul(BACKOFF_FACTOR.saturating_pow(attempt))
            .min(settings.backoff_max_ms),
    )
}


pub fn admit(batch: &mut Batch, message: &Message, verdict: Result<OffsetDateTime, String>, now: OffsetDateTime) {
    batch.opened_at = batch.opened_at.or(Some(now));
    batch.tenant = batch.tenant.take().or_else(|| Some(message.tenant.clone()));
    match verdict {
        Ok(timestamp) => {
            batch.bytes += message.payload.len();
            batch.documents.push((
                message.token,
                Document {
                    payload: message.payload.clone(),
                    timestamp,
                },
            ));
        }
        Err(reason) => batch.dead.push(DeadLetter {
            token: message.token,
            reason: truncate_reason(&reason),
        }),
    }
}


/// Oversize and unparsable messages become dead letters; a valid one is refused when the buffer cap would be exceeded.
pub fn push(batcher: &mut Batcher, message: &Message) -> Result<Option<FlushReport>, PushError> {
    let settings = current_config(&batcher.settings);
    let now = (batcher.clock)();
    let verdict = check_message(&message.payload, settings.max_message_bytes);
    let other_tenant = batcher.batch.tenant.as_ref().filter(|open| **open != message.tenant);
    if let Some(open) = other_tenant {
        Err(PushError::OtherTenant {
            open: open.clone(),
            incoming: message.tenant.clone(),
        })
    } else if verdict.is_ok() && batcher.batch.bytes + message.payload.len() > settings.max_buffered_bytes {
        Err(PushError::BufferFull {
            buffered: batcher.batch.bytes,
            cap: settings.max_buffered_bytes,
        })
    } else {
        admit(&mut batcher.batch, message, verdict, now);
        Ok(is_due(&batcher.batch, &settings, now).then(|| flush_with(batcher, &settings)))
    }
}


/// Flushes when the oldest buffered message has reached the age limit; the caller runs it on a timer.
pub fn tick(batcher: &mut Batcher) -> Option<FlushReport> {
    let settings = current_config(&batcher.settings);
    let now = (batcher.clock)();
    is_due(&batcher.batch, &settings, now).then(|| flush_with(batcher, &settings))
}


/// Retries the sink with exponential backoff; `None` once it accepted the batch, else the last error.
pub fn deliver(batcher: &Batcher, settings: &IngestSettings, tenant: &str, documents: &[Document]) -> Option<String> {
    let mut failure = Some(NO_ATTEMPT.to_owned());
    (0..settings.retry_attempts).any(|attempt| match (batcher.sink)(tenant, documents) {
        Ok(()) => {
            failure = None;
            true
        }
        Err(error) => {
            let bounded = truncate_reason(&error.to_string());
            warn!(attempt, error = %bounded, "sink refused the batch");
            failure = Some(bounded);
            if attempt + 1 < settings.retry_attempts {
                (batcher.sleep)(backoff_delay(settings, attempt));
            }
            false
        }
    });
    failure
}


/// Empties the buffer. Tokens are acknowledged only after the sink returned `Ok`; dead letters are acknowledged either way.
pub fn flush(batcher: &mut Batcher) -> FlushReport {
    let settings = current_config(&batcher.settings);
    flush_with(batcher, &settings)
}


/// `flush` on a settings snapshot the caller already took.
pub fn flush_with(batcher: &mut Batcher, settings: &IngestSettings) -> FlushReport {
    let batch = std::mem::take(&mut batcher.batch);
    let tenant = batch.tenant.unwrap_or_else(|| NO_TENANT.to_owned());
    let (tokens, documents): (Vec<_>, Vec<_>) = batch.documents.into_iter().unzip();
    let dead_tokens: Vec<_> = batch.dead.iter().map(|dead| dead.token).collect();
    let failure = if documents.is_empty() {
        None
    } else {
        deliver(batcher, settings, &tenant, &documents)
    };
    if !batch.dead.is_empty() {
        warn!(module = MODULE, dead_letters = batch.dead.len(), "dead-lettered messages in this batch");
    }
    match failure {
        None => {
            debug!(delivered = documents.len(), "batch delivered");
            FlushReport {
                tenant,
                acknowledge: tokens.into_iter().chain(dead_tokens).collect(),
                unacknowledged: Vec::new(),
                dead_letters: batch.dead,
                delivered: documents.len(),
                sink_error: None,
            }
        }
        Some(error) => {
            warn!(messages = tokens.len(), %error, "batch handed back unacknowledged");
            FlushReport {
                tenant,
                acknowledge: dead_tokens,
                unacknowledged: tokens,
                dead_letters: batch.dead,
                delivered: 0,
                sink_error: Some(error),
            }
        }
    }
}

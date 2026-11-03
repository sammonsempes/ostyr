use crate::buffer::{create_file, drain, enqueue, sync_path, Enqueued};
use crate::config::WebhookConfig;
use crate::ecs::{blank_event, to_json, EcsEvent, EventFields, HostFields};
use crate::error::ExportError;
use crate::types::{DeliverFn, PostFn, SleepFn};
use crate::webhook::{batches, deliver, RetryPolicy};
use std::path::Path;
use time::OffsetDateTime;


pub const ALERT_SEVERITY: u32 = 73;


pub const ALERT_ACTION: &str = "export-buffer-saturated";


pub const ALERT_DATASET: &str = "ostyr.export";


pub const ALERT_MODULE: &str = "core-export";


pub const LABEL_DROPPED: &str = "dropped_events";


pub const LABEL_BUFFER_MAX: &str = "buffer_max_bytes";


const NO_BATCHES: usize = 0;


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportReport {
    pub sent_batches: usize,
    pub buffered_batches: usize,
    pub drained_batches: usize,
    pub dropped_events: usize,
    pub alert: Option<EcsEvent>,
}


/// The event the SIEM receives when the buffer is full and events are lost (spec section 3, "Event loss").
pub fn saturation_alert(host: &str, dropped: usize, max_bytes: u64, now: OffsetDateTime) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            kind: Some("alert".to_string()),
            category: vec!["host".to_string()],
            action: Some(ALERT_ACTION.to_string()),
            outcome: Some("failure".to_string()),
            dataset: Some(ALERT_DATASET.to_string()),
            module: Some(ALERT_MODULE.to_string()),
            severity: Some(ALERT_SEVERITY),
            sequence: None,
        },
        message: Some(format!("export buffer saturated, {dropped} event(s) dropped")),
        host: Some(HostFields {
            name: Some(host.to_string()),
            ..HostFields::default()
        }),
        labels: [
            (LABEL_DROPPED.to_string(), dropped.to_string()),
            (LABEL_BUFFER_MAX.to_string(), max_bytes.to_string()),
        ]
        .into_iter()
        .collect(),
        ..blank_event(now)
    }
}


/// Delivers one batch unless the target is already known to be down; otherwise buffers it. Returns the updated report and the down flag.
pub fn route_batch(
    state: (ExportReport, bool),
    batch: &(usize, String),
    send: &mut DeliverFn,
    config: &WebhookConfig,
) -> Result<(ExportReport, bool), ExportError> {
    let (mut report, was_down) = state;
    let (count, body) = batch;
    let delivered = !was_down && send(body).is_ok();
    if delivered {
        report.sent_batches += 1;
    } else {
        match enqueue(
            Path::new(&config.buffer_dir),
            body,
            config.buffer_max_bytes,
            &mut create_file,
            &mut sync_path,
        )? {
            Enqueued::Stored(_path) => report.buffered_batches += 1,
            Enqueued::Saturated => report.dropped_events += count,
        }
    }
    Ok((report, !delivered))
}


/// Buffered batches go first, then the new ones; a batch the target refuses is buffered, or dropped with an alert when the buffer is full.
pub fn export_webhook(
    events: &[EcsEvent],
    config: &WebhookConfig,
    policy: &RetryPolicy,
    post: &mut PostFn,
    sleep: &mut SleepFn,
    host: &str,
    now: OffsetDateTime,
) -> Result<ExportReport, ExportError> {
    let serialised = events.iter().map(to_json).collect::<Result<Vec<_>, _>>()?;
    let dir = Path::new(&config.buffer_dir);
    let mut send = |body: &str| deliver(policy, post, sleep, body).map(|_attempts| ());
    let mut drained_batches = NO_BATCHES;
    let drained = drain(dir, &mut |body: &str| send(body).inspect(|_delivered| drained_batches += 1));
    let still_down = match drained {
        Ok(_count) => Ok(false),
        Err(ExportError::Exhausted { .. }) => Ok(true),
        Err(other) => Err(other),
    }?;
    let (mut report, _down) = batches(&serialised, config.batch_size)
        .iter()
        .try_fold((ExportReport::default(), still_down), |state, batch| {
            route_batch(state, batch, &mut send, config)
        })?;
    report.drained_batches = drained_batches;
    if report.dropped_events > 0 {
        tracing::error!(dropped = report.dropped_events, "export buffer saturated");
        report.alert = Some(saturation_alert(host, report.dropped_events, config.buffer_max_bytes, now));
    }
    Ok(report)
}

use crate::buffer::{create_file, drain, enqueue, sync_path, Enqueued};
use crate::config::{OtlpConfig, WebhookConfig};
use crate::ecs::{blank_event, to_json, EcsEvent, EventFields, HostFields};
use crate::error::ExportError;
use crate::otlp::otlp_batches;
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
    pub rejected_batches: usize,
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
            ..EventFields::default()
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
    spool: &Spool,
) -> Result<(ExportReport, bool), ExportError> {
    let (mut report, was_down) = state;
    let (count, body) = batch;
    let sent = if was_down { None } else { Some(send(body)) };
    let still_down = match sent {
        Some(Ok(())) => {
            report.sent_batches += 1;
            false
        }
        Some(Err(ExportError::Rejected { .. })) => {
            report.rejected_batches += 1;
            false
        }
        _ => {
            match enqueue(spool.dir, body, spool.max_bytes, &mut create_file, &mut sync_path)? {
                Enqueued::Stored(_path) => report.buffered_batches += 1,
                Enqueued::Saturated => report.dropped_events += count,
            }
            true
        }
    };
    Ok((report, still_down))
}


/// Where batches wait while the target is down, and the limit past which they are dropped with an alert.
pub struct Spool<'a> {
    pub dir: &'a Path,
    pub max_bytes: u64,
}


/// Shared by webhook and OTLP: buffered batches go first, then `prepared` (count, body); a refused batch is buffered or dropped with an alert.
pub fn export_prepared(
    prepared: &[(usize, String)],
    spool: &Spool,
    policy: &RetryPolicy,
    post: &mut PostFn,
    sleep: &mut SleepFn,
    context: (&str, OffsetDateTime),
) -> Result<ExportReport, ExportError> {
    let (host, now) = context;
    let dir = spool.dir;
    let mut send = |body: &str| deliver(policy, post, sleep, body).map(|_attempts| ());
    let mut drained_batches = NO_BATCHES;
    let mut rejected_buffered = NO_BATCHES;
    let drained = drain(dir, &mut |body: &str| match send(body) {
        Err(ExportError::Rejected { .. }) => {
            rejected_buffered += 1;
            Ok(())
        }
        other => other.inspect(|_delivered| drained_batches += 1),
    });
    let still_down = match drained {
        Ok(_count) => Ok(false),
        Err(ExportError::Exhausted { .. }) => Ok(true),
        Err(other) => Err(other),
    }?;
    let (mut report, _down) = prepared.iter().try_fold((ExportReport::default(), still_down), |state, batch| {
        route_batch(state, batch, &mut send, spool)
    })?;
    report.drained_batches = drained_batches;
    report.rejected_batches += rejected_buffered;
    if report.dropped_events > 0 {
        tracing::error!(dropped = report.dropped_events, "export buffer saturated");
        report.alert = Some(saturation_alert(host, report.dropped_events, spool.max_bytes, now));
    }
    Ok(report)
}


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
    let spool = Spool {
        dir: Path::new(&config.buffer_dir),
        max_bytes: config.buffer_max_bytes,
    };
    export_prepared(&batches(&serialised, config.batch_size), &spool, policy, post, sleep, (host, now))
}


/// The webhook delivery with each batch encoded as an OTLP `ExportLogsServiceRequest`.
pub fn export_otlp(
    events: &[EcsEvent],
    config: &OtlpConfig,
    policy: &RetryPolicy,
    post: &mut PostFn,
    sleep: &mut SleepFn,
    host: &str,
    now: OffsetDateTime,
) -> Result<ExportReport, ExportError> {
    let spool = Spool {
        dir: Path::new(&config.buffer_dir),
        max_bytes: config.buffer_max_bytes,
    };
    export_prepared(&otlp_batches(events, config)?, &spool, policy, post, sleep, (host, now))
}

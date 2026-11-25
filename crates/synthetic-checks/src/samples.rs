//! Probe results as `ostyr.synthetic.check.up` samples of the metrics store (T888); one snapshot of the metrics-ingest settings per round.

use crate::alerting::{identity_of, kind_name};
use crate::model::CheckKind;
use crate::types::{Clock, SendBatches, WallNanos};
use core_pg::scope::{tenant_of, TenantScope};
use metrics_ingest::insert::{encode_rows, insert_batches, Batch, RefusedRow};
use metrics_ingest::model::{MetricKind, SampleRow};
use metrics_ingest::send::clickhouse_sender;
use metrics_ingest::settings::{load_settings, MetricsSettings};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use tracing::{debug, warn};


pub const METRIC_NAME: &str = "ostyr.synthetic.check.up";


pub const METRIC_UNIT: &str = "1";


pub const LABEL_CHECK: &str = "check";


pub const LABEL_KIND: &str = "kind";


pub const LABEL_LOCATION: &str = "location";


/// The send deadline of one round's samples is the smaller of this and the settings' `timeout_ms`.
pub const MAX_SAMPLE_SEND_MS: u64 = 10_000;


pub const CATEGORY_SETTINGS: &str = "settings";


pub const CATEGORY_SENDER: &str = "sender";


pub const CATEGORY_ENCODE: &str = "encode";


pub const CATEGORY_SEND: &str = "send";


pub const CATEGORY_REFUSED: &str = "refused";


/// One probe the round ran: the check identity (never the target), its kind, the verdict and the wall time the probe returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    pub check: String,
    pub kind: CheckKind,
    pub succeeded: bool,
    pub nanos: Option<u64>,
}


/// What one round's samples came to: rows stored, rows lost to a failure, rows the encoder or the clock refused, and the failure's category.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SampleReport {
    pub sent: u64,
    pub failed: u64,
    pub refused: u64,
    pub category: Option<&'static str>,
}


/// A failed send: the batches that went out before it and a fixed category, never the error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendFailure {
    pub sent: usize,
    pub category: &'static str,
}


/// The sums over the rounds of a run.
#[derive(Debug, Default)]
pub struct SampleTotals {
    pub sent: AtomicU64,
    pub failed: AtomicU64,
    pub refused: AtomicU64,
}


/// Nanoseconds since the epoch, or `None` (logged) when the clock reads before it.
pub fn nanos_of(reading: Result<Duration, SystemTimeError>) -> Option<u64> {
    match reading {
        Ok(elapsed) => u64::try_from(elapsed.as_nanos()).ok(),
        Err(failure) => {
            let reason = failure.to_string();
            warn!(reason, "the wall clock is before the epoch, samples refused");
            None
        }
    }
}


pub fn wall_nanos() -> Option<u64> {
    nanos_of(SystemTime::now().duration_since(UNIX_EPOCH))
}


/// The record of one probe, taken when it returned.
pub fn probed_of(check_name: &str, kind: CheckKind, succeeded: bool, wall: &WallNanos) -> Probed {
    Probed {
        check: identity_of(check_name),
        kind,
        succeeded,
        nanos: wall(),
    }
}


/// One gauge row per probe that has a wall time; the tenant is the start scope's, the labels are the identity, the kind and the runner's location.
pub fn sample_rows(scope: &TenantScope, location: &str, probed: &[Probed]) -> Vec<SampleRow> {
    probed
        .iter()
        .filter_map(|result| {
            result.nanos.map(|nanos| SampleRow {
                tenant: tenant_of(scope).to_owned(),
                name: METRIC_NAME.to_owned(),
                unit: METRIC_UNIT.to_owned(),
                kind: MetricKind::Gauge,
                monotonic: false,
                labels: vec![
                    (LABEL_CHECK.to_owned(), result.check.clone()),
                    (LABEL_KIND.to_owned(), kind_name(result.kind).to_owned()),
                    (LABEL_LOCATION.to_owned(), location.to_owned()),
                ],
                timestamp_nanos: nanos,
                value: f64::from(u8::from(result.succeeded)),
                buckets: Vec::new(),
            })
        })
        .collect()
}


pub fn rows_in(batches: &[Batch]) -> u64 {
    batches.iter().map(|batch| batch.rows as u64).sum()
}


/// Every row lost to one category.
pub fn lost(rows: u64, category: &'static str) -> SampleReport {
    SampleReport {
        failed: rows,
        category: Some(category),
        ..SampleReport::default()
    }
}


/// Logs rows the encoder refused by the reason's name and their count.
pub fn log_refused(reason: RefusedRow, count: u64) {
    let name = format!("{reason:?}");
    warn!(name, count, "metric samples refused by the encoder");
}


/// Encodes under the snapshot's limits and sends the batches in order; the first failure stops the round and the rows of the unsent batches are lost, never resent.
pub fn deliver(settings: &MetricsSettings, rows: &[SampleRow], now: u64, elapsed: &Clock, send: &SendBatches) -> SampleReport {
    match encode_rows(rows, &settings.limits, now) {
        Err(_failure) => lost(rows.len() as u64, CATEGORY_ENCODE),
        Ok(encoded) => {
            let refused = encoded.refused.values().sum();
            encoded.refused.iter().for_each(|(reason, count)| log_refused(*reason, *count));
            let total = rows_in(&encoded.batches);
            let outcome = if encoded.batches.is_empty() {
                Ok(0)
            } else {
                send(settings, elapsed, &encoded.batches)
            };
            match outcome {
                Ok(_sent) => SampleReport {
                    sent: total,
                    refused,
                    ..SampleReport::default()
                },
                Err(failure) => {
                    let unsent = encoded.batches.get(failure.sent..).map_or(0, rows_in);
                    SampleReport {
                        sent: total - unsent,
                        refused,
                        ..lost(unsent, failure.category)
                    }
                }
            }
        }
    }
}


/// One round's rows: one read of the settings file, the send deadline capped, one wall reading for the encoder's window; `timeless` rows had no wall time.
pub fn send_round(file: &Path, rows: &[SampleRow], timeless: u64, wall: &WallNanos, elapsed: &Clock, send: &SendBatches) -> SampleReport {
    let report = match load_settings(file) {
        Err(failure) => {
            let reason = failure.to_string();
            warn!(reason, "the metrics settings were refused, samples lost");
            lost(rows.len() as u64, CATEGORY_SETTINGS)
        }
        Ok(loaded) => {
            let settings = MetricsSettings {
                timeout_ms: loaded.timeout_ms.min(MAX_SAMPLE_SEND_MS),
                ..loaded
            };
            match wall() {
                Some(now) => deliver(&settings, rows, now, elapsed, send),
                None => SampleReport {
                    refused: rows.len() as u64,
                    ..SampleReport::default()
                },
            }
        }
    };
    SampleReport {
        refused: report.refused + timeless,
        ..report
    }
}


/// The real send: the sender is built from the snapshot (password and CA read through checked handles) and each batch is one request.
pub fn post_batches(settings: &MetricsSettings, elapsed: &Clock, batches: &[Batch]) -> Result<usize, SendFailure> {
    let mut sender = clickhouse_sender(settings, elapsed).map_err(|_failure| SendFailure {
        sent: 0,
        category: CATEGORY_SENDER,
    })?;
    insert_batches(batches, |body| sender(body).map_err(|failure| failure.to_string())).map_err(|failure| SendFailure {
        sent: failure.sent,
        category: CATEGORY_SEND,
    })
}


/// Adds the round to the totals and logs a lost or refused row by its counts and category only.
pub fn record(totals: &SampleTotals, report: &SampleReport) {
    totals.sent.fetch_add(report.sent, Ordering::Relaxed);
    totals.failed.fetch_add(report.failed, Ordering::Relaxed);
    totals.refused.fetch_add(report.refused, Ordering::Relaxed);
    let (sent, failed, refused) = (report.sent, report.failed, report.refused);
    let category = report.category.unwrap_or(CATEGORY_REFUSED);
    if failed + refused > 0 {
        warn!(sent, failed, refused, category, "samples_failed: metric samples lost this round");
    } else {
        debug!(sent, "samples sent");
    }
}

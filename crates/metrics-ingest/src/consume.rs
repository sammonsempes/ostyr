use crate::cardinality::CardinalityState;
use crate::consumer_settings::{metrics_view, Engines, MAX_METRICS_BATCH_MESSAGES};
use crate::host::{classify_event, host_rows};
use crate::identity::{agent_from_ids, stored_time, IdentityRefusal};
use crate::insert::{encode_rows, insert_batches, Batch, EncodeError, InsertError, RefusedRow};
use crate::model::{HostCaller, Refusal};
use crate::send::clickhouse_sender;
use crate::settings::MetricsSettings;
use crate::types::{Dropped, NowFn, StoreFn, Tally};
use core_config::reload::current_config;
use core_config::types::BoxError;
use siem_ingest::batcher::backoff_delay;
use siem_ingest::dead::{log_dead_groups, record_dead_letter};
use siem_ingest::model::{AckAction, DeadGroups, DeadLetterClass, Delivery, Wiring};
use siem_ingest::parse::truncate_reason;
use siem_ingest::settings::IngestSettings;
use siem_ingest::tenant::{tenant_from_subject, EVENTS_SUBJECT_PREFIX};
use siem_ingest::types::{AckToken, SleepFn, StopFn};
use std::collections::BTreeMap;
use std::time::Instant;
use thiserror::Error;
use tracing::{info, warn};


pub const MAX_BATCH_ROW_BYTES: usize = 16_777_216;


pub const MAX_LOOP_CYCLES: u64 = 100_000;


#[derive(Debug, Error)]
pub enum ConsumeError {
    #[error("the bus fetch failed")]
    Fetch(#[source] BoxError),
    #[error("the rows could not be encoded")]
    Encode(#[from] EncodeError),
    #[error("the insert failed after {} batches", .0.sent)]
    Insert(#[from] InsertError),
}


#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConsumeReport {
    pub fetched: usize,
    pub rows: usize,
    pub tally: Tally,
    pub dropped: Dropped,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoopSummary {
    pub cycles: u64,
    pub failures: u64,
}


/// What one fetch has produced so far: the rows, the messages waiting for the insert, the counts and the bytes the rows own.
#[derive(Default)]
pub struct Gather {
    pub rows: Vec<crate::model::SampleRow>,
    pub waiting: Vec<AckToken>,
    pub row_bytes: usize,
    pub tally: Tally,
    pub dropped: Dropped,
    pub dead: DeadGroups,
}


pub struct Scope<'a> {
    pub wiring: &'a Wiring,
    pub ingest: &'a IngestSettings,
    pub metrics: &'a MetricsSettings,
}


pub struct Hooks<'a> {
    pub now: &'a NowFn,
    pub sleep: &'a SleepFn,
    pub send: &'a StoreFn,
    pub max_cycles: u64,
}


pub fn count(tally: &mut Tally, name: &str, amount: u64) {
    *tally.entry(name.to_owned()).or_insert(0) += amount;
}


/// The fixed name of a refusal of the event itself; none of them carries payload text.
pub fn refusal_name(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::TooLarge { .. } => "too_large",
        Refusal::BadEvent => "bad_event",
        Refusal::NotHostMetrics => "not_host_metrics",
        Refusal::BadHost => "bad_host",
        _ => "refused",
    }
}


/// An acknowledgement the bus refuses is logged and counted; the bus redelivers the message.
pub fn settle(wiring: &Wiring, token: AckToken, action: AckAction, tally: &mut Tally) {
    if let Err(error) = (wiring.ack)(token, action) {
        let text = truncate_reason(&error.to_string());
        warn!(token, ?action, error = %text, "the bus refused an acknowledgement");
        count(tally, "ack_failed", 1);
    }
}


/// Acknowledged only after the dead letter was confirmed; otherwise the message goes back to the bus.
pub fn refuse_identity(scope: &Scope, gather: &mut Gather, delivery: &Delivery, (tenant, refusal): (&str, IdentityRefusal)) {
    let reason = format!("identity_unusable: {refusal}");
    count(&mut gather.tally, "identity_unusable", 1);
    match (scope.wiring.dead_letter)(tenant, &delivery.payload, &reason) {
        Ok(()) => {
            record_dead_letter(&mut gather.dead, tenant, &DeadLetterClass::Identity(refusal.to_string()));
            settle(scope.wiring, delivery.token, AckAction::Ack, &mut gather.tally);
        }
        Err(error) => {
            let text = truncate_reason(&error.to_string());
            warn!(token = delivery.token, error = %text, "dead-letter publish failed, message left for redelivery");
            count(&mut gather.tally, "dead_letter_failed", 1);
            settle(scope.wiring, delivery.token, AckAction::Nak, &mut gather.tally);
        }
    }
}


pub fn add_dropped(total: &mut Dropped, more: &Dropped) {
    more.iter().for_each(|(reason, amount)| *total.entry(*reason).or_insert(0) += *amount);
}


/// The agent id from the message id and the receive time from the stream's stored time: nothing of the identity comes from the payload.
pub fn identify<'a>(delivery: &'a Delivery, tenant: &str, max_agent_bytes: usize) -> Result<(&'a str, u64), IdentityRefusal> {
    let agent = agent_from_ids(&delivery.message_ids, tenant, max_agent_bytes)?;
    stored_time(delivery.stored_nanos).map(|stored| (agent, stored))
}


pub fn build_rows(scope: &Scope, state: &mut CardinalityState, gather: &mut Gather, (delivery, tenant, agent, stored): (&Delivery, &str, &str, u64)) {
    let caller = HostCaller {
        tenant,
        agent_id: agent,
        received_nanos: stored,
    };
    let outcome = host_rows(&delivery.payload, &caller, &scope.metrics.limits, state);
    add_dropped(&mut gather.dropped, &outcome.dropped);
    match outcome.refusal {
        Some(refusal) => {
            count(&mut gather.tally, refusal_name(&refusal), 1);
            settle(scope.wiring, delivery.token, AckAction::Ack, &mut gather.tally);
        }
        None if outcome.rows.is_empty() => {
            count(&mut gather.tally, "no_rows", 1);
            settle(scope.wiring, delivery.token, AckAction::Ack, &mut gather.tally);
        }
        None => {
            gather.row_bytes = gather.row_bytes.saturating_add(outcome.row_bytes);
            gather.rows.extend(outcome.rows);
            gather.waiting.push(delivery.token);
        }
    }
}


/// The dataset check comes first, so a foreign event with any header is only acknowledged; only a host event needs an identity.
pub fn admit_event(scope: &Scope, state: &mut CardinalityState, gather: &mut Gather, delivery: &Delivery, tenant: &str) {
    match classify_event(&delivery.payload) {
        Err(refusal) => {
            count(&mut gather.tally, refusal_name(&refusal), 1);
            settle(scope.wiring, delivery.token, AckAction::Ack, &mut gather.tally);
        }
        Ok(()) => match identify(delivery, tenant, scope.metrics.limits.max_label_value_bytes) {
            Err(refusal) => refuse_identity(scope, gather, delivery, (tenant, refusal)),
            Ok((agent, stored)) => build_rows(scope, state, gather, (delivery, tenant, agent, stored)),
        },
    }
}


/// The tenant comes from the subject; an unusable subject is acknowledged, a message past the row budget goes back to the bus untouched.
pub fn triage(scope: &Scope, state: &mut CardinalityState, gather: &mut Gather, delivery: Delivery) {
    match tenant_from_subject(&delivery.subject, EVENTS_SUBJECT_PREFIX, scope.ingest.max_tenant_bytes) {
        Err(error) => {
            warn!(%error, token = delivery.token, "message refused before any parsing");
            count(&mut gather.tally, "bad_subject", 1);
            settle(scope.wiring, delivery.token, AckAction::Ack, &mut gather.tally);
        }
        Ok(_) if gather.row_bytes >= MAX_BATCH_ROW_BYTES => {
            count(&mut gather.tally, "deferred_by_row_budget", 1);
            settle(scope.wiring, delivery.token, AckAction::Nak, &mut gather.tally);
        }
        Ok(tenant) => admit_event(scope, state, gather, &delivery, tenant),
    }
}


/// Encodes and sends every row of the fetch; the refused rows are returned for counting.
pub fn store(scope: &Scope, gather: &Gather, now_nanos: u64, send: &StoreFn) -> Result<BTreeMap<RefusedRow, u64>, ConsumeError> {
    let encoded = encode_rows(&gather.rows, &scope.metrics.limits, now_nanos)?;
    if !encoded.batches.is_empty() {
        send(scope.metrics, &encoded.batches)?;
    }
    Ok(encoded.refused)
}


pub fn tally_text(tally: &Tally) -> String {
    tally
        .iter()
        .map(|(name, amount)| format!("{name}={amount}"))
        .collect::<Vec<_>>()
        .join(" ")
}


pub fn log_report(report: &ConsumeReport) {
    if report.fetched > 0 {
        let fetched = report.fetched;
        let rows = report.rows;
        let tally = tally_text(&report.tally);
        let dropped: Vec<String> = report.dropped.iter().map(|(reason, amount)| format!("{reason}={amount}")).collect();
        let dropped_text = dropped.join(" ");
        info!(fetched, rows, %tally, dropped = %dropped_text, "metrics consumer cycle");
    }
}


/// One fetch: refusals settle as found, host events wait for every batch to be accepted, and on any failure all of them go back to the bus.
pub fn run_cycle(
    wiring: &mut Wiring,
    (ingest, metrics): (&IngestSettings, &MetricsSettings),
    state: &mut CardinalityState,
    (now_nanos, send): (u64, &StoreFn),
) -> Result<ConsumeReport, ConsumeError> {
    let max = ingest.max_batch_messages.min(MAX_METRICS_BATCH_MESSAGES);
    let deliveries = (wiring.fetch)(max).map_err(ConsumeError::Fetch)?;
    let fetched = deliveries.len();
    let scope = Scope {
        wiring: &*wiring,
        ingest,
        metrics,
    };
    let mut gather = Gather::default();
    deliveries.into_iter().for_each(|delivery| triage(&scope, state, &mut gather, delivery));
    log_dead_groups(&mut gather.dead);
    if gather.row_bytes >= MAX_BATCH_ROW_BYTES {
        let row_bytes = gather.row_bytes;
        warn!(row_bytes, "batch_row_budget reached");
        count(&mut gather.tally, "batch_row_budget", 1);
    }
    let stored = store(&scope, &gather, now_nanos, send);
    let action = if stored.is_ok() { AckAction::Ack } else { AckAction::Nak };
    let waiting = std::mem::take(&mut gather.waiting);
    waiting.iter().for_each(|token| settle(scope.wiring, *token, action, &mut gather.tally));
    let refused = stored?;
    refused
        .iter()
        .for_each(|(reason, amount)| count(&mut gather.tally, &format!("row_refused_{reason}"), *amount));
    Ok(ConsumeReport {
        fetched,
        rows: gather.rows.len(),
        tally: gather.tally,
        dropped: gather.dropped,
    })
}


/// Sends the batches in order under the one `timeout_ms` deadline of the settings; the sender's cause is logged as a fixed text.
pub fn clickhouse_store(settings: &MetricsSettings, batches: &[Batch]) -> Result<usize, InsertError> {
    let started = Instant::now();
    let elapsed = || started.elapsed();
    let mut send = clickhouse_sender(settings, &elapsed).map_err(|error| {
        warn!(%error, "the ClickHouse sender could not be built");
        InsertError { sent: 0 }
    })?;
    insert_batches(batches, |body| send(body).map_err(|error| error.to_string()))
}


/// Cycles until `stop` (settings are reloaded by the watcher and the signal, never here); a failed fetch or insert backs off with the ingest delay and restarts from the first one after a success.
pub fn run_loop(wiring: &mut Wiring, engines: &Engines, state: &mut CardinalityState, (hooks, stop): (&Hooks, &StopFn)) -> LoopSummary {
    let mut summary = LoopSummary::default();
    let mut streak: u32 = 0;
    while !stop() && summary.cycles < hooks.max_cycles.min(MAX_LOOP_CYCLES) {
        summary.cycles += 1;
        let ingest = current_config(&engines.ingest);
        let metrics = metrics_view(&ingest, &current_config(&engines.limits));
        match run_cycle(wiring, (&ingest, &metrics), state, ((hooks.now)(), hooks.send)) {
            Ok(report) => {
                log_report(&report);
                streak = 0;
            }
            Err(error) => {
                let text = truncate_reason(&error.to_string());
                warn!(error = %text, streak, "metrics consumer cycle failed, backing off");
                (hooks.sleep)(backoff_delay(&ingest, streak));
                streak = streak.saturating_add(1);
                summary.failures += 1;
            }
        }
    }
    summary
}

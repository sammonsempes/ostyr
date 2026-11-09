use crate::batcher::{backoff_delay, flush, push, tick};
use crate::error::{InsertClass, InsertError, PipelineError, PushError};
use crate::model::{AckAction, Batcher, CycleReport, Delivery, FlushReport, LoopReport, Message, Pipeline, Wiring};
use crate::parse::truncate_reason;
use crate::settings::IngestSettings;
use crate::tenant::{tenant_from_subject, EVENTS_SUBJECT_PREFIX};
use crate::types::{AckToken, StopFn};
use core_config::reload::current_config;
use std::collections::HashSet;
use tracing::{debug, warn};


pub const MAX_LOOP_CYCLES: u64 = 100_000;


pub const POISON_REASON: &str = "ClickHouse refused the rows of this batch as unparsable";


pub fn new_pipeline(batcher: Batcher, wiring: Wiring) -> Pipeline {
    Pipeline {
        batcher,
        wiring,
        pending: Default::default(),
        carry: Vec::new(),
    }
}


/// The sink error text of a batch ClickHouse refused as unparsable: retrying it can never succeed.
pub fn poison_text() -> String {
    InsertError::Class(InsertClass::ParseError).to_string()
}


/// Acknowledges or negatively acknowledges one token; a bus failure is logged and counted, the bus redelivers.
pub fn answer(pipeline: &Pipeline, token: AckToken, action: AckAction, report: &mut CycleReport) {
    match (pipeline.wiring.ack)(token, action) {
        Ok(()) if action == AckAction::Ack => report.acknowledged += 1,
        Ok(()) => report.redelivered += 1,
        Err(error) => {
            warn!(token, ?action, error = %truncate_reason(&error.to_string()), "the bus refused an acknowledgement");
            report.ack_failures += 1;
        }
    }
}


/// Publishes to the dead-letter subject first and acknowledges only after that succeeded; otherwise the message is redelivered.
pub fn dead_letter(pipeline: &mut Pipeline, token: AckToken, reason: &str, report: &mut CycleReport) {
    let message = pipeline.pending.remove(&token);
    message
        .into_iter()
        .for_each(|held| match (pipeline.wiring.dead_letter)(&held.tenant, &held.payload, reason) {
            Ok(()) => {
                report.dead_lettered += 1;
                answer(pipeline, token, AckAction::Ack, report);
            }
            Err(error) => {
                warn!(token, error = %truncate_reason(&error.to_string()), "dead-letter publish failed, message left for redelivery");
                answer(pipeline, token, AckAction::Nak, report);
            }
        });
}


/// Acts on a flush: dead letters are published then acknowledged, a refused batch is redelivered, or dead-lettered if unparsable.
pub fn settle_flat(pipeline: &mut Pipeline, flushed: FlushReport, report: &mut CycleReport) {
    let dead_tokens: HashSet<AckToken> = flushed.dead_letters.iter().map(|dead| dead.token).collect();
    let poison = flushed.sink_error.as_deref() == Some(poison_text().as_str());
    for dead in &flushed.dead_letters {
        dead_letter(pipeline, dead.token, &dead.reason, report);
    }
    for token in flushed.acknowledge.iter().filter(|token| !dead_tokens.contains(token)) {
        pipeline.pending.remove(token);
        answer(pipeline, *token, AckAction::Ack, report);
    }
    for token in &flushed.unacknowledged {
        if poison {
            dead_letter(pipeline, *token, POISON_REASON, report);
        } else {
            pipeline.pending.remove(token);
            answer(pipeline, *token, AckAction::Nak, report);
        }
    }
}


/// Retries each message of a batch ClickHouse found unparsable on its own: the valid rows land, only the malformed ones are dead-lettered.
pub fn isolate(pipeline: &mut Pipeline, tokens: &[AckToken], report: &mut CycleReport) {
    for token in tokens {
        let held = pipeline.pending.get(token).cloned();
        held.into_iter().for_each(|message| {
            let early = push(&mut pipeline.batcher, &message).ok().flatten();
            let last = flush(&mut pipeline.batcher);
            early.into_iter().chain(Some(last)).for_each(|done| settle_flat(pipeline, done, report));
        });
    }
}


/// A batch refused as unparsable is split into one-message batches; any other flush is acted on as it is.
pub fn settle(pipeline: &mut Pipeline, flushed: FlushReport, report: &mut CycleReport) {
    let split = flushed.sink_error.as_deref() == Some(poison_text().as_str()) && flushed.unacknowledged.len() > 1;
    let isolated: Vec<AckToken> = if split { flushed.unacknowledged.clone() } else { Vec::new() };
    let rest = if split {
        FlushReport {
            unacknowledged: Vec::new(),
            sink_error: None,
            ..flushed
        }
    } else {
        flushed
    };
    settle_flat(pipeline, rest, report);
    isolate(pipeline, &isolated, report);
}


/// Payload bytes held for a possible dead-letter publish, dead letters included: they count against `max_buffered_bytes` too.
pub fn pending_bytes(pipeline: &Pipeline) -> usize {
    pipeline.pending.values().map(|held| held.payload.len()).sum()
}


/// The batcher's own refusal, or one for the pending total; an empty pending set always admits, so a lone large message cannot wedge the loop.
pub fn admit_message(pipeline: &mut Pipeline, message: &Message) -> Result<Option<FlushReport>, PushError> {
    let held = pending_bytes(pipeline);
    let cap = current_config(&pipeline.batcher.settings).max_buffered_bytes;
    if held > 0 && held + message.payload.len() > cap {
        Err(PushError::BufferFull { buffered: held, cap })
    } else {
        push(&mut pipeline.batcher, message)
    }
}


/// A message the batcher refuses (other tenant, full buffer) waits in `carry` while the open batch is flushed.
pub fn offer(pipeline: &mut Pipeline, message: Message, report: &mut CycleReport) {
    match admit_message(pipeline, &message) {
        Ok(flushed) => {
            pipeline.pending.insert(message.token, message);
            flushed.into_iter().for_each(|done| settle(pipeline, done, report));
        }
        Err(refusal) => {
            debug!(%refusal, "message carried over until the open batch is flushed");
            pipeline.carry.push(message);
            let done = flush(&mut pipeline.batcher);
            settle(pipeline, done, report);
        }
    }
}


/// The tenant comes from the subject; an unusable one is refused before the batcher and acknowledged, so it is not redelivered forever.
pub fn accept(pipeline: &mut Pipeline, settings: &IngestSettings, delivery: Delivery, report: &mut CycleReport) {
    match tenant_from_subject(&delivery.subject, EVENTS_SUBJECT_PREFIX, settings.max_tenant_bytes) {
        Ok(tenant) => {
            let message = Message {
                tenant: tenant.to_owned(),
                payload: delivery.payload,
                token: delivery.token,
            };
            offer(pipeline, message, report);
        }
        Err(error) => {
            warn!(%error, token = delivery.token, "message refused before the batcher");
            report.refused += 1;
            answer(pipeline, delivery.token, AckAction::Ack, report);
        }
    }
}


/// One pass: carried messages, then a fetch, then the age check. A fetch error is returned and nothing is lost.
pub fn run_cycle(pipeline: &mut Pipeline) -> Result<CycleReport, PipelineError> {
    let settings = current_config(&pipeline.batcher.settings);
    let mut report = CycleReport::default();
    let carried = std::mem::take(&mut pipeline.carry);
    carried.into_iter().for_each(|message| offer(pipeline, message, &mut report));
    let deliveries = (pipeline.wiring.fetch)(settings.max_batch_messages).map_err(PipelineError::Fetch)?;
    report.fetched = deliveries.len();
    deliveries
        .into_iter()
        .for_each(|delivery| accept(pipeline, &settings, delivery, &mut report));
    let aged = tick(&mut pipeline.batcher);
    aged.into_iter().for_each(|done| settle(pipeline, done, &mut report));
    Ok(report)
}


/// Runs cycles until `stop`; a failing fetch backs off with the batcher delay, restarting from the first one after a success.
pub fn run_loop(pipeline: &mut Pipeline, stop: &StopFn) -> LoopReport {
    let mut summary = LoopReport::default();
    let mut streak: u32 = 0;
    while !stop() && summary.cycles < MAX_LOOP_CYCLES {
        summary.cycles += 1;
        match run_cycle(pipeline) {
            Ok(_) => streak = 0,
            Err(error) => {
                let settings = current_config(&pipeline.batcher.settings);
                warn!(error = %truncate_reason(&error.to_string()), streak, "bus fetch failed, backing off");
                (pipeline.batcher.sleep)(backoff_delay(&settings, streak));
                streak = streak.saturating_add(1);
                summary.fetch_failures += 1;
            }
        }
    }
    summary
}

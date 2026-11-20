use crate::cursor::{read_cursor, write_cursor};
use crate::cut::cut_data_values;
use crate::error::PollError;
use crate::lines::{gap_line, refused_line};
use crate::model::{
    Batch, Channel, ChannelState, CursorState, Drained, GapReason, Item, ItemContext, Outcome, Plan, PollEnv, PollTotals, Refusal, RunEnd,
    RunRequest, Source, Splitter, SystemInfo, CHANNEL_NOT_FOUND_EXIT, MAX_EVENTS_PER_POLL, UNKNOWN_SYSMON_DATASET,
};
use crate::split::{feed, take_partial};
use crate::system::scan_system;
use agent_channel::spool::{append_locked, pause_between_lock_attempts};
use ecs_normalise::error::WinSecError;
use ecs_normalise::sysmon::normalise_sysmon;
use ecs_normalise::sysmon_input::MAX_EVENT_BYTES;
use ecs_normalise::types::SeenIds;
use ecs_normalise::winsec::normalise_security;
use tracing::warn;


const BATCH_FACTOR: u32 = 2;


const NO_TIME: &str = "-";


pub fn query_args(channel: &Channel, after: u64, count: u32) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.name.to_string(),
        format!("/q:*[System[(EventRecordID>{after})]]"),
        format!("/c:{count}"),
        "/rd:false".to_string(),
        "/f:xml".to_string(),
    ]
}


pub fn plan(cursor: &CursorState, channel: &Channel) -> Plan {
    match cursor {
        CursorState::Missing => Plan {
            after: 0,
            prev: None,
            lines: Vec::new(),
            totals: PollTotals::default(),
        },
        CursorState::Invalid => Plan {
            after: 0,
            prev: None,
            lines: vec![gap_line(channel, GapReason::CursorInvalid, None)],
            totals: PollTotals {
                cursor_invalid: 1,
                ..PollTotals::default()
            },
        },
        CursorState::Valid { record_id, .. } => Plan {
            after: *record_id,
            prev: Some(*record_id),
            lines: Vec::new(),
            totals: PollTotals::default(),
        },
    }
}


pub fn check_order(prev: Option<u64>, id: u64) -> Result<Option<(u64, u64)>, PollError> {
    match prev {
        Some(previous) if id <= previous => Err(PollError::OutOfOrder { previous, found: id }),
        Some(previous) if id > previous + 1 => Ok(Some((previous + 1, id - 1))),
        _ => Ok(None),
    }
}


pub fn encode_event(event: &core_export::ecs::EcsEvent, context: &ItemContext<'_>) -> Outcome {
    let unknown = event.event.dataset.as_deref() == Some(UNKNOWN_SYSMON_DATASET);
    match (context.encode)(event) {
        Ok(line) if line.len() > context.line_limit => Outcome::Refused(Refusal::Oversized),
        Ok(line) if unknown => Outcome::UnknownLine(line),
        Ok(line) => Outcome::Line(line),
        Err(_) => Outcome::Refused(Refusal::Malformed),
    }
}


pub fn normalise(text: &str, context: &ItemContext<'_>, seen: &mut SeenIds) -> Outcome {
    match context.channel.source {
        Source::Sysmon => match normalise_sysmon(text, seen) {
            Ok(event) => encode_event(&event, context),
            Err(_) => Outcome::Refused(Refusal::Malformed),
        },
        Source::Security => match normalise_security(text) {
            Ok(event) => encode_event(&event, context),
            Err(WinSecError::Unknown(_)) => Outcome::Skipped,
            Err(_) => Outcome::Refused(Refusal::Malformed),
        },
    }
}


pub fn convert_text(text: &str, context: &ItemContext<'_>, seen: &mut SeenIds) -> Outcome {
    let cut = cut_data_values(text);
    if cut.len() > MAX_EVENT_BYTES {
        Outcome::Refused(Refusal::Oversized)
    } else {
        normalise(&cut, context, seen)
    }
}


pub fn convert(item: &Item, context: &ItemContext<'_>, seen: &mut SeenIds) -> Outcome {
    match item {
        Item::Oversized { .. } => Outcome::Refused(Refusal::Oversized),
        Item::Nested { .. } => Outcome::Refused(Refusal::Malformed),
        Item::Complete(bytes) => convert_text(&String::from_utf8_lossy(bytes), context, seen),
    }
}


pub fn describe(item: &Item) -> (SystemInfo, usize) {
    match item {
        Item::Complete(bytes) => (scan_system(bytes), bytes.len()),
        Item::Oversized { head, size } | Item::Nested { head, size } => (scan_system(head), *size),
    }
}


pub fn apply(batch: &mut Batch, context: &ItemContext<'_>, outcome: Outcome, info: &SystemInfo, size: usize) {
    match outcome {
        Outcome::Line(line) => {
            batch.lines.push(line);
            batch.totals.spooled += 1;
        }
        Outcome::UnknownLine(line) => {
            batch.lines.push(line);
            batch.totals.spooled += 1;
            batch.totals.unknown += 1;
        }
        Outcome::Skipped => batch.totals.unknown += 1,
        Outcome::Refused(reason) => {
            batch.lines.push(refused_line(context.channel, info, reason, size));
            match reason {
                Refusal::Oversized => batch.totals.oversized += 1,
                Refusal::Malformed => batch.totals.malformed += 1,
            }
        }
    }
}


pub fn place(batch: &mut Batch, context: &ItemContext<'_>, seen: &mut SeenIds, item: &Item, found: (&SystemInfo, usize, u64)) {
    let (info, size, id) = found;
    match check_order(batch.prev, id) {
        Err(fault) => batch.fault = Some(fault),
        Ok(hole) => {
            hole.iter().for_each(|range| {
                batch.lines.push(gap_line(context.channel, GapReason::Hole, Some(*range)));
                batch.totals.holes += 1;
            });
            apply(batch, context, convert(item, context, seen), info, size);
            batch.prev = Some(id);
            batch.last = Some((id, info.time.clone().unwrap_or_else(|| NO_TIME.to_string())));
            batch.handled += 1;
        }
    }
}


pub fn handle_item(batch: &mut Batch, context: &ItemContext<'_>, seen: &mut SeenIds, item: &Item) {
    if batch.fault.is_none() {
        let (info, size) = describe(item);
        match info.record_id {
            None => batch.fault = Some(PollError::MissingRecordId),
            Some(id) => place(batch, context, seen, item, (&info, size, id)),
        }
    }
}


pub fn settle_end(end: RunEnd, batch: &mut Batch, splitter: &mut Splitter, state: &mut ChannelState) -> Option<Item> {
    let drained = match end {
        RunEnd::Done => None,
        RunEnd::Failed(code) => {
            batch.totals.channel_absent += u64::from(code == Some(CHANNEL_NOT_FOUND_EXIT));
            batch.totals.query_failed += u64::from(code != Some(CHANNEL_NOT_FOUND_EXIT));
            batch.lines.clear();
            batch.last = None;
            None
        }
        RunEnd::Capped => Some(Drained::Capped),
        RunEnd::Deadline => Some(Drained::Deadline),
    };
    match drained {
        Some(Drained::Capped) => batch.totals.output_capped += 1,
        Some(Drained::Deadline) => batch.totals.deadline += 1,
        _ => state.batch = state.batch.saturating_mul(BATCH_FACTOR).min(MAX_EVENTS_PER_POLL),
    }
    let stalled = drained.is_some() && batch.handled == 0;
    let single = stalled && state.batch == 1;
    if stalled && !single {
        state.batch = (state.batch / BATCH_FACTOR).max(1);
        batch.totals.batch_halved += 1;
    }
    take_partial(splitter).filter(|_| single)
}


pub fn log_totals(channel: &Channel, totals: &PollTotals) {
    let quiet = PollTotals {
        spooled: 0,
        ..totals.clone()
    } == PollTotals::default();
    let name = channel.name;
    let counts = format!("{totals:?}");
    if !quiet {
        warn!(channel = name, counts = %counts, "windows event poll skipped or refused events");
    }
}


pub fn finalize(env: &PollEnv<'_>, channel: &Channel, batch: Batch) -> Result<PollTotals, PollError> {
    append_locked(
        batch.lines.into_iter().map(Ok),
        env.spool,
        env.lock_attempts,
        &mut pause_between_lock_attempts,
    )
    .map_err(PollError::Spool)?;
    if let Some((record_id, time)) = &batch.last {
        write_cursor(env.state_dir, channel, *record_id, time).map_err(PollError::Cursor)?;
    }
    log_totals(channel, &batch.totals);
    match batch.fault {
        Some(fault) => Err(fault),
        None => Ok(batch.totals),
    }
}


pub fn announce_absent(channel: &Channel, state: &mut ChannelState, totals: &PollTotals) {
    let absent = totals.channel_absent > 0;
    let name = channel.name;
    if absent && !state.absent_logged {
        warn!(channel = name, "windows event channel is absent");
    }
    state.absent_logged = absent;
}


pub fn poll_channel(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState) -> Result<PollTotals, PollError> {
    let cursor = read_cursor(env.state_dir, channel).map_err(PollError::CursorRead)?;
    let planned = plan(&cursor, channel);
    let args = query_args(channel, planned.after, state.batch);
    let request = RunRequest {
        program: env.program,
        args: &args,
        max_bytes: env.max_output_bytes,
        deadline_seconds: env.deadline_seconds,
    };
    let context = ItemContext {
        channel,
        encode: env.encode,
        line_limit: env.line_limit,
    };
    let mut splitter = Splitter::default();
    let mut batch = Batch {
        lines: planned.lines,
        prev: planned.prev,
        totals: planned.totals,
        ..Batch::default()
    };
    let end = (env.run)(&request, &mut |chunk| {
        feed(&mut splitter, chunk, &mut |item| handle_item(&mut batch, &context, env.seen, &item));
    })?;
    let partial = settle_end(end, &mut batch, &mut splitter, state);
    partial.iter().for_each(|item| handle_item(&mut batch, &context, env.seen, item));
    announce_absent(channel, state, &batch.totals);
    finalize(env, channel, batch)
}

use crate::created::query_created;
use crate::cursor::{read_cursor, write_cursor};
use crate::error::PollError;
use crate::item::{handle_item, settle};
use crate::lines::gap_line;
use crate::model::{
    Batch, Channel, ChannelState, CursorState, Drained, GapReason, Item, ItemContext, Newest, Plan, PollEnv, PollTotals, RunEnd, RunRequest, Settled,
    Stream, CHANNEL_NOT_FOUND_EXIT, MAX_EVENTS_PER_POLL,
};
use crate::newest::query_newest;
use crate::recreated::{check_cursor, creation_to_store};
use crate::room::{fits, note_pause, pending_bytes, refused_bytes};
use crate::stream::{feed_bytes, flawed, partial_item};
use crate::types::Found;
use agent_channel::spool::{append_locked, pause_between_lock_attempts};
use tracing::warn;


const BATCH_FACTOR: u32 = 2;


pub fn query_args(channel: &Channel, after: u64, newest: u64, count: u32) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.name.to_string(),
        format!("/q:*[System[(EventRecordID>{after} and EventRecordID<={newest})]]"),
        format!("/c:{count}"),
        "/rd:false".to_string(),
        "/f:xml".to_string(),
        "/uni:true".to_string(),
    ]
}


pub fn plan(cursor: &CursorState, channel: &Channel, newest: u64, totals: &mut PollTotals) -> Plan {
    match cursor {
        CursorState::Valid { record_id, .. } if *record_id <= newest => Plan {
            after: *record_id,
            cursor: Some(*record_id),
            lines: Vec::new(),
        },
        CursorState::Valid { .. } => {
            totals.cursor_ahead += 1;
            let name = channel.name;
            warn!(channel = name, "windows event cursor is ahead of the log, replaying");
            Plan {
                after: 0,
                cursor: None,
                lines: vec![gap_line(channel, GapReason::CursorAhead, None)],
            }
        }
        CursorState::Recreated => {
            totals.log_recreated += 1;
            let name = channel.name;
            warn!(channel = name, "windows event log was recreated, replaying");
            Plan {
                after: 0,
                cursor: None,
                lines: vec![gap_line(channel, GapReason::LogRecreated, None)],
            }
        }
        CursorState::Invalid => {
            totals.cursor_invalid += 1;
            let name = channel.name;
            warn!(channel = name, "windows event cursor is invalid, replaying");
            Plan {
                after: 0,
                cursor: None,
                lines: vec![gap_line(channel, GapReason::CursorInvalid, None)],
            }
        }
        CursorState::Missing => Plan {
            after: 0,
            cursor: None,
            lines: Vec::new(),
        },
    }
}


pub fn note_end(end: RunEnd, batch: &mut Batch, stream: &Stream, channel: &Channel) {
    match end {
        RunEnd::Done if flawed(stream) => {
            batch.lead.push(gap_line(channel, GapReason::Utf16, None));
            batch.totals.utf16 += 1;
        }
        RunEnd::Failed(code) => {
            batch.totals.channel_absent += u64::from(code == Some(CHANNEL_NOT_FOUND_EXIT));
            batch.totals.query_failed += u64::from(code != Some(CHANNEL_NOT_FOUND_EXIT));
            batch.lead.clear();
            batch.pending.clear();
            batch.forged = None;
        }
        _ => {}
    }
}


pub fn settle_end(end: RunEnd, batch: &mut Batch, stream: &mut Stream, target: (&mut ChannelState, &Channel)) -> Option<Item> {
    let (state, channel) = target;
    note_end(end, batch, stream, channel);
    let drained = match end {
        RunEnd::Capped => Some(Drained::Capped),
        RunEnd::Deadline => Some(Drained::Deadline),
        _ => None,
    };
    match drained {
        Some(Drained::Capped) => batch.totals.output_capped += 1,
        Some(Drained::Deadline) => batch.totals.deadline += 1,
        _ => state.batch = state.batch.saturating_mul(BATCH_FACTOR).min(MAX_EVENTS_PER_POLL),
    }
    let stalled = drained.is_some() && batch.seen == 0;
    let single = stalled && state.batch == 1;
    if stalled && !single {
        state.batch = (state.batch / BATCH_FACTOR).max(1);
        batch.totals.batch_halved += 1;
    }
    partial_item(stream).filter(|_| single)
}


pub fn log_totals(channel: &Channel, totals: &PollTotals) {
    let quiet = PollTotals {
        spooled: 0,
        spool_full: 0,
        full_batches: 0,
        ..totals.clone()
    } == PollTotals::default();
    let name = channel.name;
    let counts = format!("{totals:?}");
    if !quiet {
        warn!(channel = name, counts = %counts, "windows event poll skipped or refused events");
    }
}


pub fn finalize(env: &PollEnv<'_>, channel: &Channel, settled: &Settled, created: Option<&str>) -> Result<(), PollError> {
    append_locked(
        settled.lines.iter().cloned().map(Ok),
        env.spool,
        env.lock_attempts,
        &mut pause_between_lock_attempts,
    )
    .map_err(PollError::Spool)?;
    if let Some((record_id, time)) = &settled.last {
        write_cursor(env.state_dir, channel, *record_id, time, created).map_err(PollError::Cursor)?;
    }
    Ok(())
}


pub fn announce_absent(channel: &Channel, state: &mut ChannelState, absent: bool) {
    let name = channel.name;
    if absent && !state.absent_logged {
        warn!(channel = name, "windows event channel is absent");
    }
    state.absent_logged = absent;
}


pub fn run_main(
    env: &mut PollEnv<'_>,
    channel: &Channel,
    state: &mut ChannelState,
    totals: &mut PollTotals,
    found: Found<'_>,
) -> Result<bool, PollError> {
    let (cursor, newest, created) = found;
    let before = totals.clone();
    let planned = plan(cursor, channel, newest, totals);
    let caught_up = planned.after >= newest;
    let args = query_args(channel, planned.after, newest, state.batch);
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
    let mut stream = Stream::default();
    let mut batch = Batch {
        lead: planned.lines,
        after: planned.after,
        newest,
        limit: state.batch,
        cursor: planned.cursor,
        totals: std::mem::take(totals),
        ..Batch::default()
    };
    let end = if caught_up {
        RunEnd::Done
    } else {
        (env.run)(&request, &mut |chunk| {
            feed_bytes(&mut stream, chunk, &mut |item| handle_item(&mut batch, &context, env.seen, &item));
        })?
    };
    let full = batch.forged.is_none() && u32::try_from(batch.pending.len()) == Ok(batch.limit);
    batch.totals.full_batches += u64::from(full);
    let partial = settle_end(end, &mut batch, &mut stream, (state, channel));
    partial.iter().for_each(|item| handle_item(&mut batch, &context, env.seen, item));
    let settled = settle(&mut batch, channel);
    let pending = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
    let room = fits(pending, &settled.lines, env.max_spool_bytes);
    let refused = refused_bytes(&settled.lines);
    let first_refusal = !room && state.paused_polls == 0;
    let limit = env.max_spool_bytes;
    if first_refusal {
        warn!(pending, refused, limit, "spool batch does not fit, reading paused");
    }
    *totals = if room { std::mem::take(&mut batch.totals) } else { before };
    totals.spool_full += u64::from(!room);
    state.batch = if room { state.batch } else { (batch.limit / BATCH_FACTOR).max(1) };
    if room {
        finalize(env, channel, &settled, created).map(|()| settled.refetch)
    } else {
        Ok(false)
    }
}


pub fn poll_once(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState, totals: &mut PollTotals) -> Result<bool, PollError> {
    let cursor = read_cursor(env.state_dir, channel).map_err(PollError::CursorRead)?;
    let newest = query_newest(env, channel, totals)?;
    totals.channel_absent += u64::from(newest == Newest::Absent);
    totals.query_failed += u64::from(newest == Newest::Failed);
    let refetch = match newest {
        Newest::Id(id) => {
            let created = query_created(env, channel, totals)?;
            match check_cursor(env, channel, cursor, (id, created.as_deref()), totals)? {
                Some(checked) => {
                    let stored = creation_to_store(&checked, id, created.as_deref());
                    run_main(env, channel, state, totals, (&checked, id, stored.as_deref()))?
                }
                None => false,
            }
        }
        _ => false,
    };
    announce_absent(channel, state, totals.channel_absent > 0);
    Ok(refetch)
}


pub fn poll_unless_full(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState, totals: &mut PollTotals) -> Result<(), PollError> {
    if poll_once(env, channel, state, totals)? {
        state.batch = 1;
        poll_once(env, channel, state, totals)?;
    }
    Ok(())
}


pub fn poll_channel(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState) -> Result<PollTotals, PollError> {
    let mut totals = PollTotals::default();
    let pending = pending_bytes(env.spool).map_err(PollError::SpoolSize)?;
    if pending >= env.max_spool_bytes {
        totals.spool_full += 1;
    } else {
        poll_unless_full(env, channel, state, &mut totals)?;
    }
    note_pause(state, totals.spool_full > 0, pending, env.max_spool_bytes);
    log_totals(channel, &totals);
    Ok(totals)
}

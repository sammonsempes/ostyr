use crate::cursor::{read_cursor, write_cursor};
use crate::error::PollError;
use crate::item::{handle_item, settle};
use crate::lines::gap_line;
use crate::model::{
    Batch, Channel, ChannelState, CursorState, Drained, GapReason, Item, ItemContext, Newest, Plan, PollEnv, PollTotals, RunEnd, RunRequest, Settled,
    Stream, CHANNEL_NOT_FOUND_EXIT, MAX_EVENTS_PER_POLL,
};
use crate::newest::query_newest;
use crate::stream::{feed_bytes, flawed, partial_item};
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
        ..totals.clone()
    } == PollTotals::default();
    let name = channel.name;
    let counts = format!("{totals:?}");
    if !quiet {
        warn!(channel = name, counts = %counts, "windows event poll skipped or refused events");
    }
}


pub fn finalize(env: &PollEnv<'_>, channel: &Channel, settled: &Settled) -> Result<(), PollError> {
    append_locked(
        settled.lines.iter().cloned().map(Ok),
        env.spool,
        env.lock_attempts,
        &mut pause_between_lock_attempts,
    )
    .map_err(PollError::Spool)?;
    if let Some((record_id, time)) = &settled.last {
        write_cursor(env.state_dir, channel, *record_id, time).map_err(PollError::Cursor)?;
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
    found: (&CursorState, u64),
) -> Result<bool, PollError> {
    let (cursor, newest) = found;
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
    let partial = settle_end(end, &mut batch, &mut stream, (state, channel));
    partial.iter().for_each(|item| handle_item(&mut batch, &context, env.seen, item));
    let settled = settle(&mut batch, channel);
    *totals = std::mem::take(&mut batch.totals);
    finalize(env, channel, &settled).map(|()| settled.refetch)
}


pub fn poll_once(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState, totals: &mut PollTotals) -> Result<bool, PollError> {
    let cursor = read_cursor(env.state_dir, channel).map_err(PollError::CursorRead)?;
    let newest = query_newest(env, channel, totals)?;
    totals.channel_absent += u64::from(newest == Newest::Absent);
    totals.query_failed += u64::from(newest == Newest::Failed);
    let refetch = match newest {
        Newest::Id(id) => run_main(env, channel, state, totals, (&cursor, id))?,
        _ => false,
    };
    announce_absent(channel, state, totals.channel_absent > 0);
    Ok(refetch)
}


pub fn poll_channel(env: &mut PollEnv<'_>, channel: &Channel, state: &mut ChannelState) -> Result<PollTotals, PollError> {
    let mut totals = PollTotals::default();
    if poll_once(env, channel, state, &mut totals)? {
        state.batch = 1;
        poll_once(env, channel, state, &mut totals)?;
    }
    log_totals(channel, &totals);
    Ok(totals)
}

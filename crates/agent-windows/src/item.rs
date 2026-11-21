use crate::cut::cut_data_values;
use crate::lines::{forged_line, gap_line, refused_line};
use crate::model::{
    Batch, Channel, ForgedAt, GapReason, Item, ItemContext, ItemKind, Outcome, Pending, PollTotals, Refusal, Settled, Source, SystemInfo,
    REPLACED_LABEL, UNKNOWN_SYSMON_DATASET,
};
use crate::system::scan_system;
use core_export::ecs::EcsEvent;
use ecs_normalise::error::WinSecError;
use ecs_normalise::sysmon::normalise_sysmon;
use ecs_normalise::sysmon_input::MAX_EVENT_BYTES;
use ecs_normalise::types::SeenIds;
use ecs_normalise::winsec::normalise_security;


const NO_TIME: &str = "-";


pub fn encode_event(mut event: EcsEvent, context: &ItemContext<'_>, replaced: u32) -> Outcome {
    let unknown = event.event.dataset.as_deref() == Some(UNKNOWN_SYSMON_DATASET);
    if replaced > 0 {
        event.labels.insert(REPLACED_LABEL.to_string(), replaced.to_string());
    }
    match (context.encode)(&event) {
        Ok(line) if line.len() > context.line_limit => Outcome::Refused(Refusal::Oversized),
        Ok(line) if unknown => Outcome::UnknownLine(line),
        Ok(line) => Outcome::Line(line),
        Err(_) => Outcome::Refused(Refusal::Malformed),
    }
}


pub fn normalise(text: &str, context: &ItemContext<'_>, seen: &mut SeenIds, replaced: u32) -> Outcome {
    match context.channel.source {
        Source::Sysmon => match normalise_sysmon(text, seen) {
            Ok(event) => encode_event(event, context, replaced),
            Err(_) => Outcome::Refused(Refusal::Malformed),
        },
        Source::Security => match normalise_security(text) {
            Ok(event) => encode_event(event, context, replaced),
            Err(WinSecError::Unknown(_)) => Outcome::Skipped,
            Err(_) => Outcome::Refused(Refusal::Malformed),
        },
    }
}


pub fn convert(item: &Item, context: &ItemContext<'_>, seen: &mut SeenIds) -> Outcome {
    match item.kind {
        ItemKind::Oversized => Outcome::Refused(Refusal::Oversized),
        ItemKind::Nested => Outcome::Refused(Refusal::Malformed),
        ItemKind::Complete => {
            let cut = cut_data_values(&item.text);
            if cut.len() > MAX_EVENT_BYTES {
                Outcome::Refused(Refusal::Oversized)
            } else {
                normalise(&cut, context, seen, item.replaced)
            }
        }
    }
}


pub fn check_item(batch: &Batch, id: Option<u64>) -> Result<u64, ForgedAt> {
    let overflow = batch.seen >= u64::from(batch.limit);
    let in_sequence = |found: u64| match batch.pending.last() {
        Some(last) => last.id.checked_add(1) == Some(found),
        None => found > batch.after,
    };
    let accepted = id.filter(|found| !overflow && *found <= batch.newest && in_sequence(*found));
    accepted.ok_or(ForgedAt {
        first: batch.pending.first().map(|first| first.id).or(id),
        breaking: id,
        count_only: overflow,
    })
}


pub fn handle_item(batch: &mut Batch, context: &ItemContext<'_>, seen: &mut SeenIds, item: &Item) {
    if batch.forged.is_none() {
        let info = scan_system(item.text.as_bytes());
        match check_item(batch, info.record_id) {
            Ok(id) => {
                let outcome = convert(item, context, seen);
                batch.pending.push(Pending {
                    id,
                    info,
                    size: item.size,
                    outcome,
                });
                batch.totals.utf16_replaced += u64::from(item.replaced);
            }
            Err(forged) => batch.forged = Some(forged),
        }
    }
    batch.seen += 1;
}


pub fn apply(lines: &mut Vec<String>, totals: &mut PollTotals, channel: &Channel, pending: Pending) {
    match pending.outcome {
        Outcome::Line(line) => {
            lines.push(line);
            totals.spooled += 1;
        }
        Outcome::UnknownLine(line) => {
            lines.push(line);
            totals.spooled += 1;
            totals.unknown += 1;
        }
        Outcome::Skipped => totals.unknown += 1,
        Outcome::Refused(reason) => {
            lines.push(refused_line(channel, &pending.info, reason, pending.size));
            match reason {
                Refusal::Oversized => totals.oversized += 1,
                Refusal::Malformed => totals.malformed += 1,
                Refusal::Forged => totals.forged += 1,
            }
        }
    }
}


pub fn hole_range(cursor: Option<u64>, first: u64) -> Option<(u64, u64)> {
    cursor.filter(|found| first > found.saturating_add(1)).map(|found| (found + 1, first - 1))
}


pub fn cursor_of(info: &SystemInfo, id: u64) -> (u64, String) {
    (id, info.time.clone().unwrap_or_else(|| NO_TIME.to_string()))
}


pub fn accept_all(settled: &mut Settled, batch: &mut Batch, channel: &Channel, pending: Vec<Pending>) {
    settled.last = pending.last().map(|last| cursor_of(&last.info, last.id));
    pending
        .first()
        .and_then(|first| hole_range(batch.cursor, first.id))
        .iter()
        .for_each(|range| {
            settled.lines.push(gap_line(channel, GapReason::Hole, Some(*range)));
            batch.totals.holes += 1;
        });
    pending
        .into_iter()
        .for_each(|entry| apply(&mut settled.lines, &mut batch.totals, channel, entry));
}


pub fn refuse_forged(settled: &mut Settled, batch: &mut Batch, channel: &Channel, found: ForgedAt, pending: Vec<Pending>) {
    let extra = batch.seen.saturating_sub(u64::try_from(pending.len()).unwrap_or(0));
    batch.totals.forged += extra;
    match (batch.limit > 1, found.count_only, pending.into_iter().next()) {
        (false, true, Some(mut first)) => {
            first.outcome = Outcome::Refused(Refusal::Forged);
            settled.last = Some(cursor_of(&first.info, first.id));
            hole_range(batch.cursor, first.id).iter().for_each(|range| {
                settled.lines.push(gap_line(channel, GapReason::Hole, Some(*range)));
                batch.totals.holes += 1;
            });
            apply(&mut settled.lines, &mut batch.totals, channel, first);
        }
        (multiple, _, _) => {
            settled.lines.push(forged_line(channel, found.first, found.breaking));
            settled.refetch = multiple;
        }
    }
}


pub fn settle(batch: &mut Batch, channel: &Channel) -> Settled {
    let mut settled = Settled {
        lines: std::mem::take(&mut batch.lead),
        ..Settled::default()
    };
    let pending = std::mem::take(&mut batch.pending);
    match batch.forged {
        None => accept_all(&mut settled, batch, channel, pending),
        Some(found) => refuse_forged(&mut settled, batch, channel, found, pending),
    }
    settled
}

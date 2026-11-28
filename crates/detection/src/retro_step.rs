//! One retro step of one rule for one tenant: plan the window, read, store the alerts in chunks, then save the cursor.

use crate::error::{RetroError, StepError};
use crate::model::{AlertRecord, HOST_FIELD, USER_FIELD};
use crate::retro::{RetroEvent, RetroIds, RetroOutcome, RetroQuery, MAX_RETRO_DAYS, SECONDS_PER_DAY};
use crate::retro_cursor::{find_entry, upsert_entry, CursorEntry, RetroCursors};
use crate::retro_rules::RetroRule;
use crate::types::{RetroInsertFn, RetroReadFn, RetroSaveFn};
use alerts::id::alert_id;
use alerts::store::MAX_ALERTS_PER_INSERT;
use siem_ingest::error::InsertClass;
use std::collections::BTreeMap;
use stream_correlation::level::Level;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const RETRO_STEP_SECONDS: i64 = 3_600;


pub const RETRO_SETTLE_SECONDS: i64 = 60;


pub const MIN_STEP_SECONDS: i64 = 60;


pub const STEP_FACTOR: i64 = 2;


pub const MILLIS_PER_SECOND: i64 = 1_000;


pub const WINDOW_ID_PREFIX: &str = "window:";


pub const LOSS_TITLE_PREFIX: &str = "Retro window not read: ";


pub const LOSS_LEVEL: Level = Level::Medium;


/// The window `[start, end)` in epoch seconds and the step it was planned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: i64,
    pub end: i64,
    pub step: i64,
}


/// What one step reads: the rule, the tenant and the clock.
#[derive(Debug, Clone, Copy)]
pub struct StepInput<'a> {
    pub rule: &'a RetroRule,
    pub tenant: &'a str,
    pub now: OffsetDateTime,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Idle,
    Complete,
    RowCap,
    Halved,
    Lost,
    RuleRefused,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepReport {
    pub outcome: StepOutcome,
    pub start: i64,
    pub end: i64,
    pub found: usize,
    pub refused_ids: usize,
    pub stored: usize,
    pub losses: usize,
}


/// What the read decided: the cursor to save and the alerts to store first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub outcome: StepOutcome,
    pub next: i64,
    pub step: i64,
    pub records: Vec<AlertRecord>,
    pub losses: usize,
    pub found: usize,
    pub refused_ids: usize,
}


/// The first step starts `MAX_RETRO_DAYS` back, the step is clamped to its bounds, and the end stops short of now by the settle time.
pub fn plan_window(entry: Option<&CursorEntry>, now_epoch: i64) -> Window {
    let start = entry.map_or(now_epoch - MAX_RETRO_DAYS * SECONDS_PER_DAY, |found| found.next);
    let step = entry
        .map_or(RETRO_STEP_SECONDS, |found| found.step)
        .clamp(MIN_STEP_SECONDS, RETRO_STEP_SECONDS);
    let end = start.saturating_add(step).min(now_epoch - RETRO_SETTLE_SECONDS);
    Window { start, end, step }
}


/// The alert of one matching event: its id derives from the rule and the event identity only, never from the window, so a reread adds nothing.
pub fn event_record(rule: &RetroRule, tenant: &str, event: &RetroEvent) -> AlertRecord {
    let group: BTreeMap<String, String> = [(HOST_FIELD, event.host_name.as_ref()), (USER_FIELD, event.user_name.as_ref())]
        .into_iter()
        .filter_map(|(field, value)| value.map(|text| (field.to_owned(), text.clone())))
        .collect();
    AlertRecord {
        id: alert_id(tenant, &rule.rule_id, std::slice::from_ref(&event.identity)),
        tenant: tenant.to_owned(),
        rule_id: rule.rule_id.clone(),
        rule_title: rule.title.clone(),
        level: rule.level,
        group,
        first_ms: event.event_ms,
        last_ms: event.event_ms,
        event_ids: vec![event.identity.clone()],
    }
}


/// The named loss of a window: its own rule id, the window as the event id, so the same loss is stored once.
pub fn loss_record(rule: &RetroRule, tenant: &str, start: i64, end: i64) -> AlertRecord {
    let window_id = format!("{WINDOW_ID_PREFIX}{start}-{end}");
    AlertRecord {
        id: alert_id(tenant, &rule.loss_id, std::slice::from_ref(&window_id)),
        tenant: tenant.to_owned(),
        rule_id: rule.loss_id.clone(),
        rule_title: format!("{LOSS_TITLE_PREFIX}{}", rule.title),
        level: LOSS_LEVEL,
        group: BTreeMap::new(),
        first_ms: start.saturating_mul(MILLIS_PER_SECOND),
        last_ms: end.saturating_mul(MILLIS_PER_SECOND),
        event_ids: vec![window_id],
    }
}


fn event_records(input: &StepInput<'_>, found: &RetroIds) -> Vec<AlertRecord> {
    found.events.iter().map(|event| event_record(input.rule, input.tenant, event)).collect()
}


fn lost(input: &StepInput<'_>, window: &Window, start: i64, end: i64) -> Decision {
    let window_epochs = format!("{start}-{end}");
    warn!(window_epochs, "retro window lost");
    Decision {
        outcome: StepOutcome::Lost,
        next: end,
        step: window.step,
        records: vec![loss_record(input.rule, input.tenant, start, end)],
        losses: 1,
        found: 0,
        refused_ids: 0,
    }
}


/// `Complete` moves to the window end and grows the step back; `RowCap` stores the rows found and moves to the second of the last one, so that second is read again.
pub fn decide_outcome(input: &StepInput<'_>, window: &Window, outcome: &RetroOutcome) -> Decision {
    match outcome {
        RetroOutcome::Complete(found) => Decision {
            outcome: StepOutcome::Complete,
            next: window.end,
            step: window.step.saturating_mul(STEP_FACTOR),
            records: event_records(input, found),
            losses: 0,
            found: found.events.len(),
            refused_ids: found.refused,
        },
        RetroOutcome::RowCap { found, .. } => {
            let last_second = found.events.last().map(|event| event.event_ms.div_euclid(MILLIS_PER_SECOND));
            let mut decision = match last_second {
                Some(second) if second > window.start => Decision {
                    outcome: StepOutcome::RowCap,
                    next: second,
                    step: window.step,
                    records: Vec::new(),
                    losses: 0,
                    found: 0,
                    refused_ids: 0,
                },
                _ => lost(input, window, window.start, window.start + 1),
            };
            decision.outcome = StepOutcome::RowCap;
            decision.records = event_records(input, found).into_iter().chain(decision.records).collect();
            decision.found = found.events.len();
            decision.refused_ids = found.refused;
            decision
        }
    }
}


/// A timeout or read limit halves the step; at the minimum the window is a named loss. A refused rule changes nothing; any other error is returned.
pub fn decide_error(input: &StepInput<'_>, window: &Window, error: RetroError) -> Result<Decision, RetroError> {
    match error {
        RetroError::Timeout | RetroError::ReadLimit if window.step > MIN_STEP_SECONDS => Ok(Decision {
            outcome: StepOutcome::Halved,
            next: window.start,
            step: (window.step / STEP_FACTOR).max(MIN_STEP_SECONDS),
            records: Vec::new(),
            losses: 0,
            found: 0,
            refused_ids: 0,
        }),
        RetroError::Timeout | RetroError::ReadLimit => Ok(lost(input, window, window.start, window.end)),
        RetroError::Rule(_) | RetroError::Refused(InsertClass::ParseError | InsertClass::Rejected) => Ok(Decision {
            outcome: StepOutcome::RuleRefused,
            next: window.start,
            step: window.step,
            records: Vec::new(),
            losses: 0,
            found: 0,
            refused_ids: 0,
        }),
        other => Err(other),
    }
}


pub fn query_of(input: &StepInput<'_>, window: &Window) -> Result<RetroQuery, RetroError> {
    let start = OffsetDateTime::from_unix_timestamp(window.start).map_err(|_| RetroError::Window)?;
    let end = OffsetDateTime::from_unix_timestamp(window.end).map_err(|_| RetroError::Window)?;
    Ok(RetroQuery {
        rule_text: input.rule.source.clone(),
        tenant: input.tenant.to_owned(),
        start,
        end,
    })
}


fn report_of(decision: &Decision, window: &Window, stored: usize) -> StepReport {
    StepReport {
        outcome: decision.outcome,
        start: window.start,
        end: window.end,
        found: decision.found,
        refused_ids: decision.refused_ids,
        stored,
        losses: decision.losses,
    }
}


/// Stores every chunk of 500 alerts, and only when all answered saves the cursor: a failure or a crash keeps the old cursor and the rerun adds nothing.
pub fn commit_decision(
    input: &StepInput<'_>,
    cursors: &RetroCursors,
    window: &Window,
    decision: &Decision,
    insert: &RetroInsertFn<'_>,
    save: &RetroSaveFn<'_>,
) -> Result<(RetroCursors, StepReport), StepError> {
    let stored = decision.records.chunks(MAX_ALERTS_PER_INSERT).try_fold(0, |total, chunk| {
        insert(input.tenant, chunk).map(|fresh| total + fresh).map_err(StepError::Insert)
    })?;
    let updated = upsert_entry(
        cursors,
        CursorEntry {
            tenant: input.tenant.to_owned(),
            fingerprint: input.rule.fingerprint.clone(),
            next: decision.next,
            step: decision.step,
        },
    );
    save(&updated).map_err(StepError::Save)?;
    Ok((updated, report_of(decision, window, stored)))
}


/// One step. An idle step (nothing settled yet) and a refused rule save and store nothing. The reply is the new cursors and the report.
pub fn retro_step(
    input: &StepInput<'_>,
    cursors: &RetroCursors,
    read: &RetroReadFn<'_>,
    insert: &RetroInsertFn<'_>,
    save: &RetroSaveFn<'_>,
) -> Result<(RetroCursors, StepReport), StepError> {
    let window = plan_window(find_entry(cursors, input.tenant, &input.rule.fingerprint), input.now.unix_timestamp());
    if window.end <= window.start {
        let idle = Decision {
            outcome: StepOutcome::Idle,
            next: window.start,
            step: window.step,
            records: Vec::new(),
            losses: 0,
            found: 0,
            refused_ids: 0,
        };
        Ok((cursors.clone(), report_of(&idle, &window, 0)))
    } else {
        let query = query_of(input, &window).map_err(StepError::Read)?;
        let decision = match read(&query) {
            Ok(outcome) => decide_outcome(input, &window, &outcome),
            Err(error) => decide_error(input, &window, error).map_err(StepError::Read)?,
        };
        let result = if decision.outcome == StepOutcome::RuleRefused {
            Ok((cursors.clone(), report_of(&decision, &window, 0)))
        } else {
            commit_decision(input, cursors, &window, &decision, insert, save)
        };
        let outcome = decision.outcome;
        let losses = decision.losses;
        let summary = format!("{outcome:?} losses={losses}");
        info!(summary, "retro step done");
        result
    }
}

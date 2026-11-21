use crate::error::PollError;
use crate::item::cursor_of;
use crate::model::{Channel, CursorState, First, PollEnv, PollTotals, Probe, RunEnd, Verdict, NEWEST_COUNT};
use crate::newest::query_first;


pub fn record_args(channel: &Channel, record_id: u64) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.name.to_string(),
        format!("/q:*[System[(EventRecordID={record_id})]]"),
        format!("/c:{NEWEST_COUNT}"),
        "/rd:false".to_string(),
        "/f:xml".to_string(),
        "/uni:true".to_string(),
    ]
}


pub fn oldest_args(channel: &Channel) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.name.to_string(),
        "/q:*[System[(EventRecordID>0)]]".to_string(),
        format!("/c:{NEWEST_COUNT}"),
        "/rd:false".to_string(),
        "/f:xml".to_string(),
        "/uni:true".to_string(),
    ]
}


pub fn classify_probe(first: First) -> Probe {
    match (first.end, first.info) {
        (RunEnd::Done, None) if !first.torn => Probe::Empty,
        (RunEnd::Done, Some(info)) => Probe::Item(info),
        _ => Probe::Failed,
    }
}


pub fn oldest_verdict(env: &mut PollEnv<'_>, channel: &Channel, record_id: u64, totals: &mut PollTotals) -> Result<Verdict, PollError> {
    let oldest = classify_probe(query_first(env, &oldest_args(channel), totals)?);
    Ok(match oldest {
        Probe::Item(info) => match info.record_id {
            Some(first) if record_id >= first => Verdict::Recreated,
            Some(_) => Verdict::Intact,
            None => Verdict::Failed,
        },
        _ => Verdict::Failed,
    })
}


pub fn verify(env: &mut PollEnv<'_>, channel: &Channel, cursor: (u64, &str), totals: &mut PollTotals) -> Result<Verdict, PollError> {
    let (record_id, time) = cursor;
    let record = classify_probe(query_first(env, &record_args(channel, record_id), totals)?);
    match record {
        Probe::Item(info) if info.record_id == Some(record_id) => Ok(if cursor_of(&info, record_id).1 == time {
            Verdict::Intact
        } else {
            Verdict::Recreated
        }),
        Probe::Empty => oldest_verdict(env, channel, record_id, totals),
        _ => Ok(Verdict::Failed),
    }
}


pub fn check_cursor(
    env: &mut PollEnv<'_>,
    channel: &Channel,
    cursor: CursorState,
    found: (u64, Option<&str>),
    totals: &mut PollTotals,
) -> Result<Option<CursorState>, PollError> {
    let (newest, created) = found;
    let verdict = match &cursor {
        CursorState::Valid {
            created: Some(stored),
            record_id,
            ..
        } if *record_id <= newest && created.is_some_and(|now| now != stored) => Verdict::Recreated,
        CursorState::Valid { record_id, time, .. } if *record_id <= newest => verify(env, channel, (*record_id, time), totals)?,
        _ => Verdict::Intact,
    };
    totals.query_failed += u64::from(verdict == Verdict::Failed);
    Ok(match verdict {
        Verdict::Intact => Some(cursor),
        Verdict::Recreated => Some(CursorState::Recreated),
        Verdict::Failed => None,
    })
}


pub fn creation_to_store(checked: &CursorState, newest: u64, created: Option<&str>) -> Option<String> {
    match checked {
        CursorState::Valid {
            created: stored, record_id, ..
        } if *record_id <= newest => created.map(str::to_string).or_else(|| stored.clone()),
        _ => created.map(str::to_string),
    }
}

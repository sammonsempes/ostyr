use crate::alerting::{is_grammar, is_id, ASSET_PUNCTUATION, MAX_ASSET_CHARS};
use crate::error::StateError;
use crate::model::{FailedAt, RecordOutcome, Verdict};
use crate::types::{PlannedEntry, RunEntry, StateKey};
use alerts::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use serde_json::{json, Value};
use std::collections::BTreeMap;


pub const MIGRATION_NAMESPACE: &str = "compliance";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "compliance_0001",
    sql: include_str!("../migrations/compliance_0001.sql"),
}];


/// Rows of one tenant; a run that would pass it stores nothing new and reports the refusal.
pub const MAX_STATE_ROWS_PER_TENANT: i64 = 1_000_000;


/// Entries of one run; a longer run is refused before any I/O.
pub const MAX_RUN_ENTRIES: usize = 10_000;


pub const OUTCOME_STORED: &str = "stored";


pub const OUTCOME_REFUSED: &str = "refused";


pub const VERDICT_FAIL: &str = "fail";


/// Params: `$2` JSON array of entries, `$3` now, `$4` row cap. The advisory lock, the count and the upsert run inside one function call.
pub const RECORD_SQL: &str =
    "SELECT entry_index::text, outcome, first_failed FROM compliance_record($1, $2::text::jsonb, $3::text::bigint, $4::text::bigint)";


pub fn verdict_name(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "pass",
        Verdict::Fail { .. } => VERDICT_FAIL,
        Verdict::Error { .. } => "error",
        Verdict::Excepted { .. } => "excepted",
    }
}


pub fn is_valid_entry(entry: &RunEntry<'_>) -> bool {
    let (baseline, control, asset, _verdict) = *entry;
    is_id(baseline) && is_id(control) && is_grammar(asset, MAX_ASSET_CHARS, ASSET_PUNCTUATION)
}


/// Entries outside the grammar are skipped and counted; a key given twice keeps its last verdict; the result is sorted by key.
pub fn plan_run(run: &[RunEntry<'_>]) -> Result<(Vec<PlannedEntry>, usize), StateError> {
    if run.len() > MAX_RUN_ENTRIES {
        Err(StateError::RunTooLarge {
            entries: run.len(),
            max: MAX_RUN_ENTRIES,
        })
    } else {
        let valid: Vec<&RunEntry<'_>> = run.iter().filter(|entry| is_valid_entry(entry)).collect();
        let skipped = run.len() - valid.len();
        let keyed: BTreeMap<StateKey, &'static str> = valid
            .iter()
            .map(|(baseline, control, asset, verdict)| {
                (
                    ((*baseline).to_owned(), (*control).to_owned(), (*asset).to_owned()),
                    verdict_name(verdict),
                )
            })
            .collect();
        Ok((keyed.into_iter().collect(), skipped))
    }
}


pub fn entries_json(entries: &[PlannedEntry]) -> String {
    let items: Vec<Value> = entries
        .iter()
        .map(|((baseline, control, asset), verdict)| json!({ "baseline": baseline, "control": control, "asset": asset, "verdict": verdict }))
        .collect();
    Value::Array(items).to_string()
}


pub fn row_cells(row: &Row) -> Option<(&String, &String, &String)> {
    match row.as_slice() {
        [index, answer, first_failed] => Some((index, answer, first_failed)),
        _ => None,
    }
}


pub fn apply_row(entries: &[PlannedEntry], outcome: RecordOutcome, row: &Row) -> Result<RecordOutcome, StateError> {
    let (index, answer, first_failed) = row_cells(row).ok_or(StateError::BadRow)?;
    let position = index
        .parse::<usize>()
        .ok()
        .and_then(|ordinal| ordinal.checked_sub(1))
        .ok_or(StateError::BadRow)?;
    let ((baseline, control, asset), verdict) = entries.get(position).ok_or(StateError::BadRow)?;
    match answer.as_str() {
        OUTCOME_REFUSED => Ok(RecordOutcome {
            refused_no_room: outcome.refused_no_room + 1,
            ..outcome
        }),
        OUTCOME_STORED if *verdict == VERDICT_FAIL => {
            let first_failed_micros = first_failed.parse::<u64>().map_err(|_error| StateError::BadRow)?;
            let mut failed = outcome.failed;
            failed.push(FailedAt {
                baseline: baseline.clone(),
                control: control.clone(),
                asset: asset.clone(),
                first_failed_micros,
            });
            Ok(RecordOutcome { failed, ..outcome })
        }
        OUTCOME_STORED => Ok(outcome),
        _ => Err(StateError::BadRow),
    }
}


pub fn decode_rows(entries: &[PlannedEntry], rows: &[Row]) -> Result<RecordOutcome, StateError> {
    rows.iter()
        .try_fold(RecordOutcome::default(), |outcome, row| apply_row(entries, outcome, row))
}


/// `record_verdicts` with an explicit row cap (the example lowers it for the live proof).
pub async fn record_verdicts_with_cap(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    run: &[RunEntry<'_>],
    now_micros: u64,
    cap: i64,
) -> Result<RecordOutcome, StateError> {
    let (entries, skipped_invalid) = plan_run(run)?;
    let now = i64::try_from(now_micros).map_err(|_error| StateError::TimeOutOfRange)?;
    let decoded = if entries.is_empty() {
        RecordOutcome::default()
    } else {
        let params = vec![entries_json(&entries), now.to_string(), cap.to_string()];
        let rows = exec(scope.clone(), RECORD_SQL, params).await.map_err(StateError::Store)?;
        decode_rows(&entries, &rows)?
    };
    let refused = decoded.refused_no_room;
    if skipped_invalid > 0 || refused > 0 {
        tracing::warn!(skipped_invalid, refused, "verdicts were not recorded");
    }
    Ok(RecordOutcome { skipped_invalid, ..decoded })
}


/// Stores one run for the tenant; answers the first-failed time of every failed entry that was stored.
pub async fn record_verdicts(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    run: &[RunEntry<'_>],
    now_micros: u64,
) -> Result<RecordOutcome, StateError> {
    record_verdicts_with_cap(exec, scope, run, now_micros, MAX_STATE_ROWS_PER_TENANT).await
}

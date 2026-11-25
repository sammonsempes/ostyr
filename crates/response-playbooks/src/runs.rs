//! The run store: one tenant-scoped `playbook_runs` row per matched playbook, written with the outbox delete in one transaction.

use crate::batch::DryRunReport;
use crate::catalogue::{find_entry, APPROVAL_ACTION};
use crate::error::RoundError;
use crate::model::{Catalogue, ConditionOutcome, Trace, TraceEvent};
use crate::service::{MAX_MATCHES, MAX_NAME_BYTES};
use crate::types::ParamMap;
use alerts::model::FeedRow;
use alerts::store::MAX_PAGE_SIZE;
use alerts::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};


pub const MIGRATION_NAMESPACE: &str = "playbooks";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "001_playbook_runs",
    sql: include_str!("../migrations/001_playbook_runs.sql"),
}];


pub const MAX_TRACE_BYTES: usize = 32_768;


pub const OMITTED_RESERVE: usize = 64;


pub const ARRAY_BRACKETS: usize = 2;


pub const RUN_CAP_ROUNDS: usize = 2;


pub const MAX_PLAYBOOK_RUNS: usize = MAX_PAGE_SIZE * MAX_MATCHES * RUN_CAP_ROUNDS;


pub const CUT_MARKER: &str = "…";


pub const REPLACEMENT: char = '\u{FFFD}';


pub const UNKNOWN_KIND: &str = "unknown";


pub const BOUND_NAME: &str = "max_playbook_runs";


pub const OUTCOME_COMPLETED: &str = "completed";


pub const OUTCOME_HALTED: &str = "halted";


pub const OUTCOME_NEEDS_APPROVAL: &str = "needs_approval";


pub const LOCK_SQL: &str = "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('playbook_runs/' OPERATOR(pg_catalog.||) $1::pg_catalog.text, 0::pg_catalog.int8))::pg_catalog.text";


pub const INSERT_SQL: &str = "WITH incoming AS (\
    SELECT * FROM jsonb_to_recordset($2::text::jsonb) AS doc(id text, alert_id text, playbook text, outcome text, steps bigint, trace jsonb)\
), written AS (\
    INSERT INTO playbook_runs (tenant, id, created, alert_id, playbook, mode, outcome, steps, trace) \
    SELECT $1::text, id, $3::text::bigint, alert_id, playbook, 'dry_run', outcome, steps, trace FROM incoming \
    ON CONFLICT (tenant, id) DO NOTHING RETURNING id\
) SELECT count(*)::text FROM written";


pub const COUNT_SQL: &str = "SELECT count(*)::text FROM playbook_runs WHERE tenant = $1::text";


pub const PRUNE_SQL: &str = "WITH gone AS (\
    DELETE FROM playbook_runs WHERE tenant = $1::text AND run_seq IN (\
        SELECT run_seq FROM playbook_runs WHERE tenant = $1::text ORDER BY run_seq LIMIT $2::text::bigint\
    ) RETURNING run_seq\
) SELECT count(*)::text FROM gone";


/// The text fields of one trace element; every one is cut before it is stored.
#[derive(Debug, Default)]
pub struct Fields<'a> {
    pub path: Option<&'a str>,
    pub action: Option<&'a str>,
    pub connector: Option<&'a str>,
    pub step: Option<&'a str>,
    pub params: Option<Value>,
}


/// One row of `playbook_runs`, before `tenant`, `created` and `mode` are added.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRow {
    pub id: String,
    pub alert_id: String,
    pub playbook: String,
    pub outcome: &'static str,
    pub steps: usize,
    pub trace: Value,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounts {
    pub written: usize,
    pub replayed: usize,
    pub pruned: usize,
}


pub fn absorb(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}


/// SHA-256 over the length-prefixed tenant, alert id, outbox `seq` (decimal) and playbook file path, as lowercase hex.
pub fn playbook_run_id(tenant: &str, alert_id: &str, seq: u64, file: &str) -> String {
    let seq_text = seq.to_string();
    let mut hasher = Sha256::new();
    [tenant, alert_id, seq_text.as_str(), file]
        .iter()
        .for_each(|part| absorb(&mut hasher, part.as_bytes()));
    format!("{:x}", hasher.finalize())
}


/// Operator text cut at `MAX_NAME_BYTES` on a character boundary, ending with `CUT_MARKER`; control characters (NUL included) become U+FFFD.
pub fn cut_text(text: &str) -> String {
    let clean: String = text
        .chars()
        .map(|character| if character.is_control() { REPLACEMENT } else { character })
        .collect();
    if clean.len() <= MAX_NAME_BYTES {
        clean
    } else {
        let room = MAX_NAME_BYTES.saturating_sub(CUT_MARKER.len());
        let kept: String = clean
            .chars()
            .scan(0, |bytes, character| {
                *bytes += character.len_utf8();
                (*bytes <= room).then_some(character)
            })
            .collect();
        format!("{kept}{CUT_MARKER}")
    }
}


pub fn element(kind: &str, outcome: Option<&str>, fields: Fields<'_>) -> Value {
    let texts = [
        ("path", fields.path),
        ("action", fields.action),
        ("connector", fields.connector),
        ("step", fields.step),
    ];
    let cut = texts
        .into_iter()
        .filter_map(|(key, text)| text.map(|found| (key.to_owned(), Value::String(cut_text(found)))));
    let fixed = [("kind", Some(kind)), ("outcome", outcome)]
        .into_iter()
        .filter_map(|(key, word)| word.map(|found| (key.to_owned(), Value::String(found.to_owned()))));
    let params = fields.params.map(|found| ("params".to_owned(), found));
    Value::Object(fixed.chain(cut).chain(params).collect::<Map<String, Value>>())
}


/// Parameter names with their catalogue kinds; the values never enter.
pub fn params_json(catalogue: &Catalogue, connector: Option<&str>, action: &str, params: &ParamMap) -> Value {
    let entry = find_entry(catalogue, connector, action);
    Value::Object(
        params
            .keys()
            .map(|name| {
                let kind = entry
                    .and_then(|found| found.params.get(name))
                    .map_or_else(|| json!(UNKNOWN_KIND), |spec| json!(spec.kind));
                (cut_text(name), kind)
            })
            .collect::<Map<String, Value>>(),
    )
}


pub fn flag_word(flag: bool) -> &'static str {
    if flag {
        "true"
    } else {
        "false"
    }
}


/// A verdict is `allowed` only when its text says so, so any other text fails closed.
pub fn verdict_word(verdict: Option<&str>) -> &'static str {
    match verdict {
        None => "allowed",
        Some(text) if text.starts_with("allowed") => "allowed",
        Some(_other) => OUTCOME_NEEDS_APPROVAL,
    }
}


pub fn condition_word(outcome: &ConditionOutcome) -> &'static str {
    match outcome {
        ConditionOutcome::True => "true",
        ConditionOutcome::False => "false",
        ConditionOutcome::Failed(_text) => "failed",
    }
}


fn at(path: &str) -> Fields<'_> {
    Fields {
        path: Some(path),
        ..Fields::default()
    }
}


/// One element from a fixed schema: fixed words, operator text cut, parameter names and kinds; reasons, failure text, asset ids and values never enter.
pub fn event_json(catalogue: &Catalogue, event: &TraceEvent) -> Value {
    match event {
        TraceEvent::Trigger { matched, .. } => element("trigger", Some(flag_word(*matched)), Fields::default()),
        TraceEvent::Condition { path, outcome, .. } => element("condition", Some(condition_word(outcome)), at(path)),
        TraceEvent::Action {
            path,
            connector,
            action,
            params,
            verdict,
        } => element(
            "action",
            Some(verdict_word(verdict.as_deref())),
            Fields {
                action: Some(action),
                connector: connector.as_deref(),
                params: Some(params_json(catalogue, connector.as_deref(), action, params)),
                ..at(path)
            },
        ),
        TraceEvent::Rejected { path, action, .. } => element(
            "rejected",
            Some("rejected"),
            Fields {
                action: Some(action),
                ..at(path)
            },
        ),
        TraceEvent::Approval { path, params, granted } => element(
            "approval",
            Some(if *granted { "granted" } else { "denied" }),
            Fields {
                params: Some(params_json(catalogue, None, APPROVAL_ACTION, params)),
                ..at(path)
            },
        ),
        TraceEvent::NotRun { path, step } => element(
            "not_run",
            Some("not_run"),
            Fields {
                step: Some(step),
                ..at(path)
            },
        ),
        TraceEvent::UnknownAsset { path, .. } => element("unknown_asset", Some("unknown_asset"), at(path)),
        TraceEvent::Halted { path } => element("halted", Some("halted"), at(path)),
        TraceEvent::Failure { path, action } => element(
            "failure",
            Some("failure"),
            Fields {
                action: Some(action),
                ..at(path)
            },
        ),
        TraceEvent::ActionFailed { path, action, .. } => element(
            "action_failed",
            Some("failure"),
            Fields {
                action: Some(action),
                ..at(path)
            },
        ),
        TraceEvent::Compensation { action, compensates } => element(
            "compensation",
            None,
            Fields {
                action: Some(action),
                step: Some(compensates),
                ..Fields::default()
            },
        ),
        TraceEvent::ErrorHandler => element("error_handler", None, Fields::default()),
    }
}


/// Elements kept while the array stays within `MAX_TRACE_BYTES` less the room of the closing `omitted` element, which counts the rest.
pub fn bounded_trace(elements: &[Value]) -> Value {
    let budget = MAX_TRACE_BYTES.saturating_sub(OMITTED_RESERVE);
    let kept: Vec<Value> = elements
        .iter()
        .scan(ARRAY_BRACKETS, |bytes, found| {
            *bytes += found.to_string().len() + 1;
            (*bytes <= budget).then(|| found.clone())
        })
        .collect();
    let omitted = elements.len().saturating_sub(kept.len());
    let closing = (omitted > 0).then(|| json!({ "kind": "omitted", "events": omitted }));
    Value::Array(kept.into_iter().chain(closing).collect())
}


pub fn is_halting(event: &TraceEvent) -> bool {
    match event {
        TraceEvent::Rejected { .. }
        | TraceEvent::NotRun { .. }
        | TraceEvent::Halted { .. }
        | TraceEvent::Failure { .. }
        | TraceEvent::ActionFailed { .. } => true,
        TraceEvent::Condition { outcome, .. } => matches!(outcome, ConditionOutcome::Failed(_)),
        TraceEvent::Approval { granted, .. } => !*granted,
        _other => false,
    }
}


pub fn needs_approval(event: &TraceEvent) -> bool {
    matches!(event, TraceEvent::Action { verdict, .. } if verdict_word(verdict.as_deref()) == OUTCOME_NEEDS_APPROVAL)
}


/// `needs_approval` when a breaker stopped the run, else `halted` when any step failed or was refused, else `completed`.
pub fn outcome_word(events: &[TraceEvent]) -> &'static str {
    if events.iter().any(needs_approval) {
        OUTCOME_NEEDS_APPROVAL
    } else if events.iter().any(is_halting) {
        OUTCOME_HALTED
    } else {
        OUTCOME_COMPLETED
    }
}


pub fn row_of(tenant: &str, row: &FeedRow, trace: &Trace, file: &str, catalogue: &Catalogue) -> RunRow {
    let elements: Vec<Value> = trace.events.iter().map(|event| event_json(catalogue, event)).collect();
    RunRow {
        id: playbook_run_id(tenant, &row.alert.id, row.seq, file),
        alert_id: row.alert.id.clone(),
        playbook: cut_text(&trace.playbook),
        outcome: outcome_word(&trace.events),
        steps: trace.events.iter().filter(|event| matches!(event, TraceEvent::Action { .. })).count(),
        trace: bounded_trace(&elements),
    }
}


/// One row per matched playbook of every simulated alert; `runnable` is the page's rows in the order the dry run was given them.
pub fn run_rows(tenant: &str, runnable: &[&FeedRow], report: Option<&DryRunReport>, catalogue: &Catalogue) -> Vec<RunRow> {
    report.map_or_else(Vec::new, |found| {
        found
            .alerts
            .iter()
            .filter_map(|run| runnable.get(run.position).map(|row| (run, *row)))
            .flat_map(|(run, row)| {
                run.traces
                    .iter()
                    .zip(run.files.iter())
                    .map(move |(trace, file)| row_of(tenant, row, trace, file, catalogue))
            })
            .collect()
    })
}


pub fn runs_document(rows: &[RunRow]) -> String {
    Value::Array(
        rows.iter()
            .map(|row| {
                json!({
                    "id": row.id,
                    "alert_id": row.alert_id,
                    "playbook": row.playbook,
                    "outcome": row.outcome,
                    "steps": row.steps,
                    "trace": row.trace,
                })
            })
            .collect(),
    )
    .to_string()
}


/// The one number a counting statement answers.
pub fn answer(rows: &[Row], statement: &'static str) -> Result<usize, RoundError> {
    rows.first()
        .and_then(|row| row.first())
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or(RoundError::Answer { statement })
}


/// Inside the caller's transaction: lock the tenant, insert, count, delete the oldest excess. Nothing is written for an empty list.
pub async fn store_runs(exec: Executor<'_, '_>, scope: &TenantScope, rows: &[RunRow], created: i64) -> Result<RunCounts, RoundError> {
    if rows.is_empty() {
        Ok(RunCounts::default())
    } else {
        exec(scope.clone(), LOCK_SQL, Vec::new()).await?;
        let inserted = exec(scope.clone(), INSERT_SQL, vec![runs_document(rows), created.to_string()]).await?;
        let written = answer(&inserted, INSERT_SQL)?;
        let counted = exec(scope.clone(), COUNT_SQL, Vec::new()).await?;
        let excess = answer(&counted, COUNT_SQL)?.saturating_sub(MAX_PLAYBOOK_RUNS);
        let pruned = if excess == 0 {
            0
        } else {
            answer(&exec(scope.clone(), PRUNE_SQL, vec![excess.to_string()]).await?, PRUNE_SQL)?
        };
        Ok(RunCounts {
            written,
            replayed: rows.len().saturating_sub(written),
            pruned,
        })
    }
}

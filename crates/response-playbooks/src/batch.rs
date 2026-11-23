use crate::bundle::{Bundle, LoadedPlaybook};
use crate::cli::DEFAULT_FLEET_SIZE;
use crate::model::{SimulationInput, Trace};
use crate::simulate::simulate;
use crate::trigger::mismatches;
use core_pg::scope::tenant_scope;
use response_breakers::breakers::Breakers;
use serde_json::Value;
use std::fmt;
use std::io::{self, BufRead, Read};


pub const MAX_ALERT_DEPTH: usize = 16;


pub const MAX_ALERT_NODES: usize = 1_024;


pub const MAX_ALERT_TEXT_BYTES: usize = 65_536;


pub const MAX_TOKEN_BYTES: usize = 64;


pub const MAX_LINE_BYTES: u64 = 1_048_576;


pub const REQUEST_PREFIX: &str = "dry-run";


pub const ID_FIELD: &str = "id";


pub const TENANT_FIELD: &str = "tenant";


/// The three bounds of one batch; each one that is hit is named in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DryRunLimits {
    pub max_alerts: usize,
    pub max_matches_per_alert: usize,
    pub max_trace_events: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NotObject,
    TooDeep,
    TooManyNodes,
    TooMuchText,
    OtherTenant,
}


impl fmt::Display for SkipReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObject => write!(formatter, "not a JSON object"),
            Self::TooDeep => write!(formatter, "nested deeper than {MAX_ALERT_DEPTH} levels"),
            Self::TooManyNodes => write!(formatter, "more than {MAX_ALERT_NODES} values"),
            Self::TooMuchText => write!(formatter, "more than {MAX_ALERT_TEXT_BYTES} bytes of keys and strings"),
            Self::OtherTenant => write!(formatter, "tenant field differs from the batch tenant"),
        }
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct AlertRun {
    pub position: usize,
    pub request_id: String,
    pub skipped: Option<SkipReason>,
    pub traces: Vec<Trace>,
    pub matches_over_bound: usize,
    pub matches_over_budget: usize,
    pub events_omitted: usize,
}


#[derive(Debug, Clone, PartialEq)]
pub struct DryRunReport {
    pub tenant_refused: bool,
    pub alerts: Vec<AlertRun>,
    pub alerts_not_run: usize,
    pub trace_events: usize,
}


pub struct Frontier<'a> {
    pub level: Vec<&'a Value>,
    pub nodes: usize,
    pub text: usize,
}


pub struct Progress {
    pub traces: Vec<Trace>,
    pub used: usize,
    pub omitted: usize,
    pub over_budget: usize,
}


pub struct Spent {
    pub runs: Vec<AlertRun>,
    pub events: usize,
}


pub struct Batch<'a> {
    pub bundle: &'a Bundle,
    pub breakers: &'a Breakers,
    pub tenant: &'a str,
    pub limits: DryRunLimits,
}


pub struct AlertFile {
    pub alerts: Vec<Value>,
    pub truncated: bool,
    pub unreadable: usize,
}


pub fn text_bytes(value: &Value) -> usize {
    match value {
        Value::String(text) => text.len(),
        Value::Object(map) => map.keys().map(String::len).sum(),
        _ => 0,
    }
}


pub fn children(value: &Value) -> Vec<&Value> {
    match value {
        Value::Object(map) => map.values().collect(),
        Value::Array(items) => items.iter().collect(),
        _ => Vec::new(),
    }
}


/// Counts one level of the alert (values, key and string bytes) and refuses before the next level is listed.
pub fn widen(frontier: Frontier<'_>) -> Result<Frontier<'_>, SkipReason> {
    let nodes = frontier.nodes + frontier.level.len();
    let text = frontier.text + frontier.level.iter().map(|value| text_bytes(value)).sum::<usize>();
    if nodes > MAX_ALERT_NODES {
        Err(SkipReason::TooManyNodes)
    } else if text > MAX_ALERT_TEXT_BYTES {
        Err(SkipReason::TooMuchText)
    } else {
        Ok(Frontier {
            level: frontier.level.iter().flat_map(|value| children(value)).collect(),
            nodes,
            text,
        })
    }
}


/// Why an alert is not simulated: not an object, or deeper or larger than the bounds. Walked level by level, never recursively.
pub fn refusal(alert: &Value) -> Option<SkipReason> {
    if alert.is_object() {
        (0..=MAX_ALERT_DEPTH)
            .try_fold(
                Frontier {
                    level: vec![alert],
                    nodes: 0,
                    text: 0,
                },
                |frontier, _| widen(frontier),
            )
            .map_or_else(Some, |end| (!end.level.is_empty()).then_some(SkipReason::TooDeep))
    } else {
        Some(SkipReason::NotObject)
    }
}


/// A `tenant` field that is present and is not exactly the batch tenant.
pub fn foreign_tenant(alert: &Value, tenant: &str) -> bool {
    alert.get(TENANT_FIELD).is_some_and(|field| field.as_str() != Some(tenant))
}


pub fn is_token(text: &str) -> bool {
    text.len() <= MAX_TOKEN_BYTES
        && text.starts_with(|first: char| first.is_ascii_alphanumeric())
        && text.chars().all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


/// The position, plus the alert's `id` when it is a bounded ASCII token that cannot start an option.
pub fn request_id(position: usize, alert: &Value) -> String {
    alert.get(ID_FIELD).and_then(Value::as_str).filter(|id| is_token(id)).map_or_else(
        || format!("{REQUEST_PREFIX}-{position}"),
        |id| format!("{REQUEST_PREFIX}-{position}-{id}"),
    )
}


/// One simulation, its events cut to what is left of the batch budget; the cut is counted.
pub fn simulate_within(batch: &Batch<'_>, loaded: &LoadedPlaybook, input: &SimulationInput, progress: Progress) -> Progress {
    let trace = simulate(&loaded.playbook, &batch.bundle.catalogue, &batch.bundle.inventory, batch.breakers, input);
    let room = batch.limits.max_trace_events.saturating_sub(progress.used);
    let kept = trace.events.len().min(room);
    let omitted = trace.events.len().saturating_sub(kept);
    let mut traces = progress.traces;
    traces.push(Trace {
        events: trace.events.into_iter().take(room).collect(),
        ..trace
    });
    Progress {
        traces,
        used: progress.used + kept,
        omitted: progress.omitted + omitted,
        over_budget: progress.over_budget,
    }
}


pub fn step(batch: &Batch<'_>, loaded: &LoadedPlaybook, input: &SimulationInput, progress: Progress) -> Progress {
    if progress.used >= batch.limits.max_trace_events {
        Progress {
            over_budget: progress.over_budget + 1,
            ..progress
        }
    } else {
        simulate_within(batch, loaded, input, progress)
    }
}


pub fn run_alert(batch: &Batch<'_>, spent: Spent, position: usize, alert: &Value) -> Spent {
    let skipped = refusal(alert).or_else(|| foreign_tenant(alert, batch.tenant).then_some(SkipReason::OtherTenant));
    let matching: Vec<&LoadedPlaybook> = batch
        .bundle
        .playbooks
        .iter()
        .filter(|loaded| skipped.is_none() && mismatches(&loaded.playbook.trigger, alert).is_empty())
        .collect();
    let request = request_id(position, alert);
    let input = SimulationInput {
        tenant: batch.tenant.to_owned(),
        request_id: request.clone(),
        alert: alert.clone(),
        fleet_size: DEFAULT_FLEET_SIZE,
        isolated_now: 0,
        fail_action: None,
        approvals: Vec::new(),
    };
    let start = Progress {
        traces: Vec::new(),
        used: spent.events,
        omitted: 0,
        over_budget: 0,
    };
    let done = matching
        .iter()
        .take(batch.limits.max_matches_per_alert)
        .fold(start, |progress, loaded| step(batch, loaded, &input, progress));
    let mut runs = spent.runs;
    runs.push(AlertRun {
        position,
        request_id: request,
        skipped,
        traces: done.traces,
        matches_over_bound: matching.len().saturating_sub(batch.limits.max_matches_per_alert),
        matches_over_budget: done.over_budget,
        events_omitted: done.omitted,
    });
    Spent { runs, events: done.used }
}


/// Simulates, never executes: every playbook whose trigger matches, for every alert, in input order. One batch is one tenant.
pub fn dry_run_batch(bundle: &Bundle, breakers: &Breakers, tenant: &str, alerts: &[Value], limits: DryRunLimits) -> DryRunReport {
    let tenant_refused = tenant_scope(tenant).is_err();
    let allowed = if tenant_refused { 0 } else { limits.max_alerts };
    let batch = Batch {
        bundle,
        breakers,
        tenant,
        limits,
    };
    let spent = alerts
        .iter()
        .enumerate()
        .take(allowed)
        .fold(Spent { runs: Vec::new(), events: 0 }, |current, (position, alert)| {
            run_alert(&batch, current, position, alert)
        });
    DryRunReport {
        tenant_refused,
        alerts: spent.runs,
        alerts_not_run: alerts.len().saturating_sub(allowed),
        trace_events: spent.events,
    }
}


/// One alert per line; a line that is not JSON, or is over `MAX_LINE_BYTES` (its tail then reads as further lines), is `null`: counted, then skipped.
pub fn next_alert(input: &mut dyn BufRead) -> io::Result<Option<Value>> {
    let mut buffer = Vec::new();
    let read = input.take(MAX_LINE_BYTES).read_until(b'\n', &mut buffer)?;
    Ok((read > 0).then(|| serde_json::from_slice(&buffer).unwrap_or(Value::Null)))
}


/// At most `max_lines` lines are read; the file is `truncated` when more input is left, and `unreadable` counts the lines that are `null`.
pub fn read_alerts(input: &mut dyn BufRead, max_lines: usize) -> io::Result<AlertFile> {
    let alerts = (0..max_lines)
        .map_while(|_| next_alert(&mut *input).transpose())
        .collect::<io::Result<Vec<Value>>>()?;
    let truncated = !input.fill_buf()?.is_empty();
    let unreadable = alerts.iter().filter(|alert| alert.is_null()).count();
    Ok(AlertFile {
        alerts,
        truncated,
        unreadable,
    })
}

use crate::bundle::{Bundle, LoadedPlaybook};
use crate::cli::DEFAULT_FLEET_SIZE;
use crate::error::DryRunError;
use crate::model::{SimulationInput, Trace};
use crate::simulate::simulate;
use crate::trigger::mismatches;
use core_audit::log::{append_declared, genesis_log};
use core_pg::scope::tenant_scope;
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use serde_json::Value;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::Path;
use std::sync::Arc;
use tempfile::{tempdir_in, TempDir};
use time::OffsetDateTime;


pub const MAX_ALERT_DEPTH: usize = 16;


pub const MAX_ALERT_NODES: usize = 1_024;


pub const MAX_ALERT_TEXT_BYTES: usize = 65_536;


pub const MAX_TOKEN_BYTES: usize = 64;


pub const MAX_ALERT_BYTES: usize = 65_536;


pub const REQUEST_PREFIX: &str = "dry-run";


pub const ID_FIELD: &str = "id";


pub const TENANT_FIELD: &str = "tenant";


pub const SCRATCH_LIMITS: &str = "limits.yaml";


pub const SCRATCH_COUNTERS: &str = "counters.json";


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
    TooLong,
    Unreadable,
    DuplicateKey,
}


impl fmt::Display for SkipReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObject => write!(formatter, "not a JSON object"),
            Self::TooDeep => write!(formatter, "nested deeper than {MAX_ALERT_DEPTH} levels"),
            Self::TooManyNodes => write!(formatter, "more than {MAX_ALERT_NODES} values"),
            Self::TooMuchText => write!(formatter, "more than {MAX_ALERT_TEXT_BYTES} bytes of keys and strings"),
            Self::OtherTenant => write!(formatter, "tenant field differs from the batch tenant"),
            Self::TooLong => write!(formatter, "line longer than {MAX_ALERT_BYTES} bytes, discarded unparsed"),
            Self::Unreadable => write!(formatter, "line is not JSON"),
            Self::DuplicateKey => write!(formatter, "duplicate_key: an object repeats a key"),
        }
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct AlertRun {
    pub position: usize,
    pub request_id: String,
    pub skipped: Option<SkipReason>,
    pub traces: Vec<Trace>,
    pub files: Vec<String>,
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


struct Progress {
    traces: Vec<Trace>,
    files: Vec<String>,
    used: usize,
    omitted: usize,
    over_budget: usize,
}


struct Spent {
    runs: Vec<AlertRun>,
    events: usize,
}


struct Batch<'a> {
    bundle: &'a Bundle,
    breakers: &'a Breakers,
    tenant: &'a str,
    limits: DryRunLimits,
}


pub struct AlertFile {
    pub alerts: Vec<Line>,
    pub too_long: usize,
    pub refused: usize,
    pub unreadable: usize,
    pub unread: usize,
    pub unread_more: bool,
}


#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    Alert(Value),
    Skipped(SkipReason),
}


static NO_ALERT: Value = Value::Null;


#[derive(Debug, Default, Clone, Copy)]
pub struct Scan {
    pub in_string: bool,
    pub escaped: bool,
    pub depth: usize,
    pub deepest: usize,
    pub nodes: usize,
    pub text: usize,
    pub keys: usize,
    pub after_string: bool,
}


pub struct Scratch {
    pub dir: TempDir,
    pub breakers: Breakers,
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
fn simulate_within(batch: &Batch<'_>, loaded: &LoadedPlaybook, input: &SimulationInput, progress: Progress) -> Progress {
    let trace = simulate(&loaded.playbook, &batch.bundle.catalogue, &batch.bundle.inventory, batch.breakers, input);
    let room = batch.limits.max_trace_events.saturating_sub(progress.used);
    let kept = trace.events.len().min(room);
    let omitted = trace.events.len().saturating_sub(kept);
    let mut traces = progress.traces;
    let mut files = progress.files;
    files.push(loaded.file.clone());
    traces.push(Trace {
        events: trace.events.into_iter().take(room).collect(),
        ..trace
    });
    Progress {
        traces,
        files,
        used: progress.used + kept,
        omitted: progress.omitted + omitted,
        over_budget: progress.over_budget,
    }
}


fn step(batch: &Batch<'_>, loaded: &LoadedPlaybook, input: &SimulationInput, progress: Progress) -> Progress {
    if progress.used >= batch.limits.max_trace_events {
        Progress {
            over_budget: progress.over_budget + 1,
            ..progress
        }
    } else {
        simulate_within(batch, loaded, input, progress)
    }
}


fn run_alert(batch: &Batch<'_>, spent: Spent, position: usize, line: &Line) -> Spent {
    let (alert, skipped) = match line {
        Line::Alert(alert) => (
            alert,
            refusal(alert).or_else(|| foreign_tenant(alert, batch.tenant).then_some(SkipReason::OtherTenant)),
        ),
        Line::Skipped(reason) => (&NO_ALERT, Some(*reason)),
    };
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
        files: Vec::new(),
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
        files: done.files,
        matches_over_bound: matching.len().saturating_sub(batch.limits.max_matches_per_alert),
        matches_over_budget: done.over_budget,
        events_omitted: done.omitted,
    });
    Spent { runs, events: done.used }
}


/// A scratch breaker state built from a copy of the limits file: the counters are its own, so a dry run never spends a live budget.
pub fn scratch_breakers(limits_file: &Path, scratch_parent: &Path) -> Result<Scratch, DryRunError> {
    let dir = tempdir_in(scratch_parent)?;
    let config_path = dir.path().join(SCRATCH_LIMITS);
    fs::copy(limits_file, &config_path)?;
    let log = Arc::new(genesis_log(io::sink()));
    let breakers = open_breakers(BreakerSettings {
        config_path,
        store_path: dir.path().join(SCRATCH_COUNTERS),
        sync: sync_path,
        audit: Arc::new(move |entry| append_declared(&log, entry, &[])),
        clock: Box::new(OffsetDateTime::now_utc),
    })?;
    Ok(Scratch { dir, breakers })
}


fn run_batch(bundle: &Bundle, breakers: &Breakers, tenant: &str, alerts: &[Line], limits: DryRunLimits) -> DryRunReport {
    let batch = Batch {
        bundle,
        breakers,
        tenant,
        limits,
    };
    let spent = alerts
        .iter()
        .enumerate()
        .take(limits.max_alerts)
        .fold(Spent { runs: Vec::new(), events: 0 }, |current, (position, alert)| {
            run_alert(&batch, current, position, alert)
        });
    DryRunReport {
        tenant_refused: false,
        alerts_not_run: alerts.len().saturating_sub(limits.max_alerts),
        alerts: spent.runs,
        trace_events: spent.events,
    }
}


#[doc = "Simulates, never executes: every playbook whose trigger matches, for every alert, in input order. One batch is one tenant.\n\nIt takes the limits file and a directory for its scratch state, never a live `Breakers`, and no `Executor`:\n\n```compile_fail,E0061\nfn call(bundle: &response_playbooks::bundle::Bundle, limits: response_playbooks::batch::DryRunLimits, executor: response_playbooks::model::Executor) {\n    let _ = response_playbooks::batch::dry_run_batch(bundle, std::path::Path::new(\"limits.yaml\"), std::path::Path::new(\".\"), \"acme\", &[], limits, executor);\n}\n```\n\nThe runner under it is private, so a caller's live `Breakers` has no way in:\n\n```compile_fail,E0603\nfn call(bundle: &response_playbooks::bundle::Bundle, breakers: &response_breakers::breakers::Breakers, limits: response_playbooks::batch::DryRunLimits) {\n    let _ = response_playbooks::batch::run_batch(bundle, breakers, \"acme\", &[], limits);\n}\n```\n"]
pub fn dry_run_batch(
    bundle: &Bundle,
    limits_file: &Path,
    scratch_parent: &Path,
    tenant: &str,
    alerts: &[Line],
    limits: DryRunLimits,
) -> Result<DryRunReport, DryRunError> {
    let tenant_refused = tenant_scope(tenant).is_err();
    let scratch = (!tenant_refused).then(|| scratch_breakers(limits_file, scratch_parent)).transpose()?;
    Ok(scratch.map_or_else(
        || DryRunReport {
            tenant_refused,
            alerts: Vec::new(),
            alerts_not_run: alerts.len(),
            trace_events: 0,
        },
        |held| run_batch(bundle, &held.breakers, tenant, alerts, limits),
    ))
}


fn shape_byte(state: Scan, byte: u8) -> Scan {
    match (state.in_string, state.escaped, byte) {
        (true, true, _) => Scan {
            escaped: false,
            text: state.text + 1,
            ..state
        },
        (true, false, b'\\') => Scan {
            escaped: true,
            text: state.text + 1,
            ..state
        },
        (true, false, b'"') => Scan { in_string: false, ..state },
        (true, false, _) => Scan {
            text: state.text + 1,
            ..state
        },
        (false, _, b'"') => Scan { in_string: true, ..state },
        (false, _, b'{' | b'[') => Scan {
            depth: state.depth + 1,
            deepest: state.deepest.max(state.depth + 1),
            nodes: state.nodes + 1,
            ..state
        },
        (false, _, b'}' | b']') => Scan {
            depth: state.depth.saturating_sub(1),
            ..state
        },
        (false, _, b',') => Scan {
            nodes: state.nodes + 1,
            ..state
        },
        (false, _, _) => state,
    }
}


pub fn scan_byte(state: Scan, byte: u8) -> Scan {
    let closing = state.in_string && !state.escaped && byte == b'"';
    let key = state.after_string && byte == b':';
    let after_string = closing || (state.after_string && byte.is_ascii_whitespace());
    Scan {
        keys: state.keys + usize::from(key),
        after_string,
        ..shape_byte(state, byte)
    }
}


/// Strings followed by a colon on the raw bytes of a valid JSON line: every key, a repeated one counted each time.
pub fn raw_keys(line: &[u8]) -> usize {
    line.iter().fold(Scan::default(), |state, byte| scan_byte(state, *byte)).keys
}


/// Keys of the parsed value, a repeated key counted once: fewer than `raw_keys` means the line repeated a key.
pub fn value_keys(alert: &Value) -> usize {
    (0..=MAX_ALERT_DEPTH)
        .fold((vec![alert], 0), |(level, keys), _| {
            let found = level.iter().map(|value| value.as_object().map_or(0, serde_json::Map::len)).sum::<usize>();
            (level.iter().flat_map(|value| children(value)).collect(), keys + found)
        })
        .1
}


/// The shape bounds on the raw bytes of one line, before any `Value` exists: depth, values (openers and commas, over-counted) and key and string bytes.
pub fn shape_refusal(line: &[u8]) -> Option<SkipReason> {
    let scan = line.iter().fold(Scan::default(), |state, byte| scan_byte(state, *byte));
    if line.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        Some(SkipReason::NotObject)
    } else if scan.deepest > MAX_ALERT_DEPTH {
        Some(SkipReason::TooDeep)
    } else if scan.nodes + 1 > MAX_ALERT_NODES {
        Some(SkipReason::TooManyNodes)
    } else if scan.text > MAX_ALERT_TEXT_BYTES {
        Some(SkipReason::TooMuchText)
    } else {
        None
    }
}


pub fn parsed(buffer: &[u8]) -> Line {
    serde_json::from_slice::<Value>(buffer).map_or(Line::Skipped(SkipReason::Unreadable), |alert| {
        if value_keys(&alert) == raw_keys(buffer) {
            Line::Alert(alert)
        } else {
            Line::Skipped(SkipReason::DuplicateKey)
        }
    })
}


pub fn classify(buffer: &[u8], too_long: bool) -> Line {
    if too_long {
        Line::Skipped(SkipReason::TooLong)
    } else {
        shape_refusal(buffer).map_or_else(|| parsed(buffer), Line::Skipped)
    }
}


/// One line: at most `MAX_ALERT_BYTES` are buffered; a longer line is discarded up to its newline, unparsed, and is `TooLong`.
pub fn next_line(input: &mut dyn BufRead) -> io::Result<Option<Line>> {
    let mut buffer = Vec::new();
    let read = input.take(MAX_ALERT_BYTES as u64 + 1).read_until(b'\n', &mut buffer)?;
    let too_long = buffer.len() > MAX_ALERT_BYTES && buffer.last() != Some(&b'\n');
    if too_long {
        input.skip_until(b'\n')?;
    }
    Ok((read > 0).then(|| classify(&buffer, too_long)))
}


/// Lines left after the cap, counted without being buffered, at most `max_scan` of them.
pub fn count_unread(input: &mut dyn BufRead, max_scan: usize) -> io::Result<usize> {
    let skipped = (0..max_scan)
        .map_while(|_| match input.skip_until(b'\n') {
            Ok(0) => None,
            Ok(_) => Some(Ok(())),
            Err(error) => Some(Err(error)),
        })
        .collect::<io::Result<Vec<()>>>()?;
    Ok(skipped.len())
}


pub fn count_skipped(lines: &[Line], cause: fn(&SkipReason) -> bool) -> usize {
    lines.iter().filter(|line| matches!(line, Line::Skipped(reason) if cause(reason))).count()
}


pub fn is_too_long(reason: &SkipReason) -> bool {
    matches!(reason, SkipReason::TooLong)
}


pub fn is_unreadable(reason: &SkipReason) -> bool {
    matches!(reason, SkipReason::Unreadable)
}


pub fn is_refused(reason: &SkipReason) -> bool {
    !is_too_long(reason) && !is_unreadable(reason)
}


/// At most `max_alerts` lines are read, each kept once: a line that is not an alert keeps its cause, so positions hold and each is counted.
pub fn read_alerts(input: &mut dyn BufRead, max_alerts: usize, max_scan: usize) -> io::Result<AlertFile> {
    let lines = (0..max_alerts)
        .map_while(|_| next_line(&mut *input).transpose())
        .collect::<io::Result<Vec<Line>>>()?;
    let unread = count_unread(&mut *input, max_scan)?;
    let unread_more = !input.fill_buf()?.is_empty();
    Ok(AlertFile {
        too_long: count_skipped(&lines, is_too_long),
        refused: count_skipped(&lines, is_refused),
        unreadable: count_skipped(&lines, is_unreadable),
        unread,
        unread_more,
        alerts: lines,
    })
}

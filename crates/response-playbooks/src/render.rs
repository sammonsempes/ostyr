use crate::batch::{AlertRun, DryRunReport};
use crate::model::{Catalogue, ConditionOutcome, Mode, Trace, TraceEvent};
use crate::runs::event_json;
use crate::types::ParamMap;
use std::io::{self, Write};
use unicode_general_category::{get_general_category, GeneralCategory};


pub fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Simulate => "simulate",
        Mode::Enforce => "enforce",
        Mode::DryRun => "dry-run",
        Mode::ApprovalRequired => "approval-required",
    }
}


pub fn params_text(params: &ParamMap) -> String {
    params.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join(" ")
}


pub fn outcome_text(outcome: &ConditionOutcome) -> String {
    match outcome {
        ConditionOutcome::True => "true".to_owned(),
        ConditionOutcome::False => "false".to_owned(),
        ConditionOutcome::Failed(message) => format!("error ({message}), run halted"),
    }
}


pub fn action_name(connector: Option<&str>, action: &str) -> String {
    connector.map_or_else(|| action.to_owned(), |name| format!("{name}/{action}"))
}


/// The text between double quotes, a backslash and a quote escaped, so no value runs into the words around it.
pub fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace(BACKSLASH, "\\\\").replace('"', "\\\""))
}


pub fn event_line(event: &TraceEvent) -> String {
    match event {
        TraceEvent::Trigger { matched: true, .. } => "trigger matched".to_owned(),
        TraceEvent::Trigger { mismatches, .. } => format!("trigger not matched: {}", mismatches.join(", ")),
        TraceEvent::Condition { path, expression, outcome } => format!("condition {path} {}: {expression}", outcome_text(outcome)),
        TraceEvent::Action {
            path,
            connector,
            action,
            params,
            verdict,
        } => format!(
            "action {path} {} {} breakers={}",
            action_name(connector.as_deref(), action),
            params_text(params),
            verdict.as_deref().unwrap_or("not applicable")
        ),
        TraceEvent::Rejected { path, action, reason } => format!("rejected {path} {action}: {reason}"),
        TraceEvent::Approval { path, params, granted } => format!(
            "approval {} {path} {}",
            if *granted { "granted" } else { "requested" },
            params_text(params)
        ),
        TraceEvent::NotRun { path, step } => format!("halted {path} {step}: not run"),
        TraceEvent::UnknownAsset { path, id } => format!("unknown asset {path} {}: not in the inventory, treated as protected", quoted(id)),
        TraceEvent::Halted { path } => format!("halted {path}: waiting for approval, on-call alert raised"),
        TraceEvent::Failure { path, action } => format!("failure simulated {path} {action}"),
        TraceEvent::ActionFailed { path, action, reason } => format!("failure {path} {action}: {reason}"),
        TraceEvent::Compensation { action, compensates } => format!("compensation {action} for {compensates}"),
        TraceEvent::ErrorHandler => "on_error handler".to_owned(),
    }
}


pub const BACKSLASH: char = '\\';


/// Categories Cc, Cf (bidi controls included), Zl and Zp: characters that move or hide text.
pub fn is_invisible(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    )
}


/// Injective: a backslash doubles and an invisible character becomes `\u{..}`, so no alert value forges a line or an escape.
pub fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == BACKSLASH {
                String::from("\\\\")
            } else if is_invisible(character) {
                character.escape_unicode().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}


/// Plain text, one line per event: byte for byte stable, the form the snapshots compare.
pub fn render_trace(trace: &Trace) -> String {
    std::iter::once(format!("playbook {} v{} mode={}", trace.playbook, trace.version, mode_label(trace.mode)))
        .chain(trace.events.iter().map(event_line))
        .map(|line| escape_controls(&line))
        .map(|line| format!("{line}\n"))
        .collect()
}


pub fn counted(count: usize, label: &str) -> Option<String> {
    (count > 0).then(|| format!("  {label}: {count}\n"))
}


/// One trace without a single value: the header and one fixed-schema JSON line per event (names and kinds of parameters only).
pub fn render_trace_redacted(catalogue: &Catalogue, trace: &Trace) -> String {
    std::iter::once(format!("playbook {} v{} mode={}", trace.playbook, trace.version, mode_label(trace.mode)))
        .map(|line| escape_controls(&line))
        .chain(trace.events.iter().map(|event| event_json(catalogue, event).to_string()))
        .map(|line| format!("{line}\n"))
        .collect()
}


pub fn alert_block(run: &AlertRun) -> String {
    alert_block_with(run, &render_trace)
}


pub fn alert_block_redacted(catalogue: &Catalogue, run: &AlertRun) -> String {
    alert_block_with(run, &|trace| render_trace_redacted(catalogue, trace))
}


pub fn alert_block_with(run: &AlertRun, render: &dyn Fn(&Trace) -> String) -> String {
    let skipped = run.skipped.map(|reason| format!("  skipped: {reason}\n"));
    let notes = [
        counted(run.matches_over_bound, "matching playbooks not run (per-alert bound)"),
        counted(run.matches_over_budget, "matching playbooks not run (trace budget)"),
        counted(run.events_omitted, "trace events omitted (trace budget)"),
    ];
    std::iter::once(format!("alert {} {}\n", run.position, run.request_id))
        .chain(skipped)
        .chain(run.traces.iter().map(render))
        .chain(notes.into_iter().flatten())
        .collect()
}


pub fn header(report: &DryRunReport) -> String {
    let refused = report
        .tenant_refused
        .then(|| "dry run refused: the batch tenant is not a valid tenant name\n".to_owned());
    let summary = format!(
        "dry run: {} alert(s) simulated, {} alert(s) not run (alert bound), {} trace event(s)\n",
        report.alerts.len(),
        report.alerts_not_run,
        report.trace_events
    );
    refused.into_iter().chain(std::iter::once(summary)).collect()
}


/// Plain text, one block per alert (a trace per matching playbook), then every bound that was hit; nothing was executed.
pub fn render_dry_run(report: &DryRunReport) -> String {
    std::iter::once(header(report)).chain(report.alerts.iter().map(alert_block)).collect()
}


/// The same text as `render_dry_run`, written one alert block at a time so the whole output is never held.
pub fn write_dry_run(out: &mut impl Write, report: &DryRunReport) -> io::Result<()> {
    out.write_all(header(report).as_bytes())?;
    report.alerts.iter().try_for_each(|run| out.write_all(alert_block(run).as_bytes()))
}


/// The service's stdout trace: the same blocks as `write_dry_run` but no alert-derived value (condition text, reasons, asset ids, parameter values).
pub fn write_dry_run_redacted(out: &mut impl Write, report: &DryRunReport, catalogue: &Catalogue) -> io::Result<()> {
    out.write_all(header(report).as_bytes())?;
    report
        .alerts
        .iter()
        .try_for_each(|run| out.write_all(alert_block_redacted(catalogue, run).as_bytes()))
}

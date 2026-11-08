use crate::model::{ConditionOutcome, Mode, Trace, TraceEvent};
use crate::types::ParamMap;


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
        TraceEvent::UnknownAsset { path, id } => format!("unknown asset {path} {id}: not in the inventory, treated as protected"),
        TraceEvent::Halted { path } => format!("halted {path}: waiting for approval, on-call alert raised"),
        TraceEvent::Failure { path, action } => format!("failure simulated {path} {action}"),
        TraceEvent::ActionFailed { path, action, reason } => format!("failure {path} {action}: {reason}"),
        TraceEvent::Compensation { action, compensates } => format!("compensation {action} for {compensates}"),
        TraceEvent::ErrorHandler => "on_error handler".to_owned(),
    }
}


/// Plain text, one line per event: byte for byte stable, the form the snapshots compare.
pub fn render_trace(trace: &Trace) -> String {
    std::iter::once(format!("playbook {} v{} mode={}", trace.playbook, trace.version, mode_label(trace.mode)))
        .chain(trace.events.iter().map(event_line))
        .map(|line| format!("{line}\n"))
        .collect()
}

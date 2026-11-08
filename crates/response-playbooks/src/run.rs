use crate::catalogue::find_entry;
use crate::error::ConnectorError;
use crate::model::{
    Catalogue, CatalogueEntry, ConnectorCall, ConnectorResult, Executor, Failure, Inventory, Mode, Playbook, SimulationInput, Trace, TraceEvent,
};
use crate::simulate::{target_id, trace_for, values_of, Context, Done, Work};
use crate::types::ResolvedMap;
use crate::validate::is_unsafe_compensation;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use response_breakers::breakers::Breakers;
use std::collections::BTreeMap;
use tracing::error;


pub const MODULE: &str = "response-playbooks";


pub const ACTION_AUDIT: &str = "playbook.action";


pub const COMPENSATION_AUDIT: &str = "playbook.compensation";


pub const DENIED_AUDIT: &str = "playbook.denied";


pub const COMPENSATION_PATH: &str = "compensation";


pub const MAX_DETAIL_CHARS: usize = 256;


/// Runs one alert for real: the same walk as `simulate`, each action going through the injected connector.
pub fn run(
    playbook: &Playbook,
    catalogue: &Catalogue,
    inventory: &Inventory,
    breakers: &Breakers,
    input: &SimulationInput,
    exec: &Executor,
) -> Trace {
    trace_for(playbook, catalogue, inventory, breakers, input, Some(exec))
}


/// Text from a peer or a connector is cut before it reaches the trace or the audit.
pub fn bounded(text: &str) -> String {
    text.chars().take(MAX_DETAIL_CHARS).collect()
}


/// A playbook in `approval-required` mode runs an action only when the input carries its approval record.
pub fn unapproved(context: &Context, entry: &CatalogueEntry) -> Option<String> {
    let waiting = context.exec.is_some() && context.playbook.mode == Mode::ApprovalRequired && !context.input.approvals.contains(&entry.action);
    waiting.then(|| format!("no approval record for `{}`", entry.action))
}


/// Only `enforce` and an approved `approval-required` playbook reach a connector; `simulate` and `dry-run` never do.
pub fn is_live(mode: Mode) -> bool {
    matches!(mode, Mode::Enforce | Mode::ApprovalRequired)
}


pub fn audit_entry(context: &Context, action: &str, target: String, outcome: Outcome, parameters: &[(&str, String)]) -> NewEntry {
    NewEntry {
        timestamp: (context.breakers.clock)(),
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: context.input.tenant.clone(),
        module: MODULE.to_owned(),
        action: action.to_owned(),
        target,
        outcome,
        request_id: context.input.request_id.clone(),
        justification: None,
        parameters: parameters
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}


/// A failing audit is logged: it never turns a refusal into an allowance.
pub fn write_audit(context: &Context, entry: NewEntry) {
    if let Err(audit_error) = (context.breakers.audit)(entry) {
        error!(%audit_error, "cannot audit a playbook action");
    }
}


pub fn target_of(entry: &CatalogueEntry, resolved: &ResolvedMap) -> String {
    entry
        .breaker
        .as_ref()
        .and_then(|binding| resolved.get(&binding.target))
        .map_or_else(|| entry.action.clone(), |found| bounded(&target_id(&found.value)))
}


/// A denied action (mode gate or breaker) is audited by a real run; a simulation audits nothing.
pub fn audit_denied(context: &Context, work: &Work, entry: &CatalogueEntry, resolved: &ResolvedMap, reason: &str) {
    if context.exec.is_some() {
        write_audit(
            context,
            audit_entry(
                context,
                DENIED_AUDIT,
                target_of(entry, resolved),
                Outcome::Denied,
                &[("step", work.path.clone()), ("action", entry.action.clone()), ("reason", bounded(reason))],
            ),
        );
    }
}


/// A call that outlives its deadline is a failure, whatever it returned; `simulate` and `dry-run` playbooks call nothing.
pub fn call_connector(context: &Context, exec: &Executor, call: &ConnectorCall) -> Result<ConnectorResult, ConnectorError> {
    if is_live(context.playbook.mode) {
        let started = (exec.clock)();
        let outcome = (exec.connector)(call);
        let elapsed = (exec.clock)().saturating_sub(started);
        match outcome {
            Ok(_) if elapsed > exec.deadline => Err(ConnectorError::Timeout {
                elapsed,
                deadline: exec.deadline,
            }),
            other => other,
        }
    } else {
        Ok(ConnectorResult {
            summary: "not executed".to_owned(),
        })
    }
}


/// Calls the connector and audits the outcome (the failure text, bounded, is the only detail kept).
pub fn execute_call(context: &Context, exec: &Executor, call: &ConnectorCall, audit_action: &str, target: String) -> Result<(), ConnectorError> {
    let result = call_connector(context, exec, call);
    let (outcome, detail) = match &result {
        Ok(found) => (Outcome::Success, bounded(&found.summary)),
        Err(failure) => (Outcome::Failure, bounded(&failure.to_string())),
    };
    write_audit(
        context,
        audit_entry(
            context,
            audit_action,
            target,
            outcome,
            &[
                ("action", call.action.clone()),
                ("executed", is_live(context.playbook.mode).to_string()),
                ("detail", detail),
            ],
        ),
    );
    result.map(|_| ())
}


pub fn call_for(context: &Context, exec: &Executor, connector: Option<String>, action: String, params: crate::types::ParamMap) -> ConnectorCall {
    ConnectorCall {
        tenant: context.input.tenant.clone(),
        request_id: context.input.request_id.clone(),
        connector,
        action,
        params,
        deadline: exec.deadline,
    }
}


/// The real counterpart of the simulated failure: `None` when the connector succeeded; a late success took effect.
pub fn run_action(context: &Context, exec: &Executor, work: &Work, entry: &CatalogueEntry, resolved: &ResolvedMap) -> Option<Failure> {
    let call = call_for(context, exec, work.step.connector.clone(), entry.action.clone(), values_of(resolved));
    execute_call(context, exec, &call, ACTION_AUDIT, target_of(entry, resolved))
        .err()
        .map(|failure| Failure {
            took_effect: matches!(failure, ConnectorError::Timeout { .. }),
            event: TraceEvent::ActionFailed {
                path: work.path.clone(),
                action: entry.action.clone(),
                reason: bounded(&failure.to_string()),
            },
        })
}


/// An undo is looked up in the catalogue, never destructive nor breaker-bound, and in `approval-required` mode covered by the approval of its action.
pub fn permitted_compensation<'a>(context: &'a Context, finished: &Done, compensate: &str) -> Result<&'a CatalogueEntry, ConnectorError> {
    let undo = find_entry(context.catalogue, finished.connector.as_deref(), compensate).ok_or(ConnectorError::UnknownCompensation)?;
    let waiting = context.playbook.mode == Mode::ApprovalRequired && !context.input.approvals.contains(&finished.action);
    match (is_unsafe_compensation(undo), waiting) {
        (true, _) => Err(ConnectorError::UnsafeCompensation),
        (false, true) => Err(ConnectorError::UnapprovedCompensation),
        (false, false) => Ok(undo),
    }
}


/// The failure of a compensation, if a real run called it and it failed or was refused; the remaining compensations still run.
pub fn compensation_failure(context: &Context, finished: &Done, compensate: &str) -> Option<TraceEvent> {
    context.exec.and_then(|exec| {
        permitted_compensation(context, finished, compensate)
            .inspect_err(|refusal| {
                write_audit(
                    context,
                    audit_entry(
                        context,
                        DENIED_AUDIT,
                        finished.action.clone(),
                        Outcome::Denied,
                        &[
                            ("step", COMPENSATION_PATH.to_owned()),
                            ("action", bounded(compensate)),
                            ("reason", refusal.to_string()),
                        ],
                    ),
                );
            })
            .and_then(|_| {
                let call = call_for(
                    context,
                    exec,
                    finished.connector.clone(),
                    compensate.to_owned(),
                    finished.compensation_params.clone(),
                );
                execute_call(context, exec, &call, COMPENSATION_AUDIT, finished.action.clone())
            })
            .err()
            .map(|failure| TraceEvent::ActionFailed {
                path: COMPENSATION_PATH.to_owned(),
                action: compensate.to_owned(),
                reason: bounded(&failure.to_string()),
            })
    })
}

use crate::catalogue::{find_entry, APPROVAL_ACTION};
use crate::expr::{evaluate_condition, PlaybookScope, Scope};
use crate::model::{BreakerBinding, BreakerKind, Catalogue, CatalogueEntry, ConditionOutcome, Playbook, SimulationInput, Step, Trace, TraceEvent};
use crate::params::{as_count, as_duration, as_ip, resolve_params};
use crate::trigger::mismatches;
use crate::types::{ParamMap, ResolvedMap};
use response_breakers::breakers::Breakers;
use response_breakers::check::check;
use response_breakers::model::{ActionKind, ProposedAction, Target, Verdict};
use std::ops::ControlFlow;
use std::time::Duration;


pub const MAX_WORK: usize = 100_000;


pub const STEPS_ROOT: &str = "steps";


pub const ON_ERROR_ROOT: &str = "on_error";


#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub playbook: &'a Playbook,
    pub catalogue: &'a Catalogue,
    pub breakers: &'a Breakers,
    pub input: &'a SimulationInput,
}


#[derive(Debug, Clone)]
pub struct Work<'a> {
    pub path: String,
    pub step: &'a Step,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub action: String,
    pub compensate: Option<String>,
}


#[derive(Debug, Default)]
pub struct Run<'a> {
    pub pending: Vec<Work<'a>>,
    pub events: Vec<TraceEvent>,
    pub done: Vec<Done>,
    pub ran: usize,
    pub failed: bool,
    pub halted: bool,
}


pub fn done_names(done: &[Done]) -> Vec<String> {
    done.iter().map(|finished| finished.action.clone()).collect()
}


pub fn scope_of<'a>(context: &'a Context, names: &'a [String]) -> Scope<'a> {
    Scope {
        alert: &context.input.alert,
        playbook: PlaybookScope {
            name: &context.playbook.name,
            version: context.playbook.version,
            mode: context.playbook.mode,
            variables: &context.playbook.variables,
            actions_done: names,
        },
    }
}


/// The work stack pops from its end, so the first step goes last.
pub fn work_for<'a>(steps: &'a [Step], root: &str) -> Vec<Work<'a>> {
    steps
        .iter()
        .enumerate()
        .rev()
        .map(|(index, step)| Work {
            path: format!("{root}.{index}"),
            step,
        })
        .collect()
}


pub fn values_of(resolved: &ResolvedMap) -> ParamMap {
    resolved.iter().map(|(name, found)| (name.clone(), found.value.clone())).collect()
}


pub fn target_id(value: &serde_json::Value) -> String {
    value.as_str().map_or_else(|| value.to_string(), str::to_owned)
}


pub fn duration_of(binding: &BreakerBinding, resolved: &ResolvedMap) -> Result<Duration, String> {
    match binding.duration.as_ref().and_then(|name| resolved.get(name)) {
        None => Ok(Duration::MAX),
        Some(found) => as_duration(&found.value).ok_or_else(|| format!("`{}` is not a duration", found.value)),
    }
}


pub fn machines_of(binding: &BreakerBinding, resolved: &ResolvedMap) -> Result<u64, String> {
    binding
        .machines
        .as_ref()
        .and_then(|name| resolved.get(name))
        .and_then(|found| as_count(&found.value))
        .ok_or_else(|| "the number of machines is missing".to_owned())
}


pub fn kind_of(context: &Context, binding: &BreakerBinding, resolved: &ResolvedMap, target: &serde_json::Value) -> Result<ActionKind, String> {
    match binding.kind {
        BreakerKind::IsolateEndpoint => Ok(ActionKind::IsolateEndpoint {
            fleet_size: context.input.fleet_size,
            isolated_now: context.input.isolated_now,
        }),
        BreakerKind::DisableAccount => Ok(ActionKind::DisableAccount),
        BreakerKind::BlockIp => Ok(ActionKind::BlockIp {
            address: as_ip(target).ok_or_else(|| format!("`{target}` is not an IP address"))?,
            duration: duration_of(binding, resolved)?,
        }),
        BreakerKind::BlockDomain => Ok(ActionKind::BlockDomain {
            duration: duration_of(binding, resolved)?,
        }),
        BreakerKind::RmmScript => Ok(ActionKind::RmmScript {
            machines: machines_of(binding, resolved)?,
        }),
    }
}


/// The action as the breakers see it: the target parameter gives the identifier and, for an entity, its tags.
pub fn proposal(context: &Context, binding: &BreakerBinding, resolved: &ResolvedMap) -> Result<ProposedAction, String> {
    let target = resolved
        .get(&binding.target)
        .ok_or_else(|| format!("the breaker target `{}` is missing", binding.target))?;
    Ok(ProposedAction {
        tenant: context.input.tenant.clone(),
        request_id: context.input.request_id.clone(),
        kind: kind_of(context, binding, resolved, &target.value)?,
        target: Target {
            id: target_id(&target.value),
            tags: target.tags.clone(),
        },
    })
}


pub fn is_approval(step: &Step) -> bool {
    step.connector.is_none() && step.action.as_deref() == Some(APPROVAL_ACTION)
}


pub fn reject(state: &mut Run, work: &Work, reason: String) {
    state.events.push(TraceEvent::Rejected {
        path: work.path.clone(),
        action: work.step.action.as_deref().map_or_else(String::new, str::to_owned),
        reason,
    });
}


/// The breakers decide before anything would run; a verdict that needs approval stops the playbook.
pub fn record_action(context: &Context, fail_at: Option<usize>, work: &Work, entry: &CatalogueEntry, resolved: &ResolvedMap, state: &mut Run) {
    let verdict = entry
        .breaker
        .as_ref()
        .map(|binding| proposal(context, binding, resolved).map(|action| check(context.breakers, &action)))
        .transpose();
    match verdict {
        Err(reason) => reject(state, work, reason),
        Ok(decided) => {
            let stopped = matches!(decided, Some(Verdict::NeedsApproval { .. }));
            state.events.push(TraceEvent::Action {
                path: work.path.clone(),
                connector: work.step.connector.clone(),
                action: entry.action.clone(),
                params: values_of(resolved),
                verdict: decided.map(|found| found.to_string()),
            });
            if stopped {
                state.halted = true;
                state.events.push(TraceEvent::Halted { path: work.path.clone() });
            } else {
                if fail_at == Some(state.ran) {
                    state.failed = true;
                    state.events.push(TraceEvent::Failure {
                        path: work.path.clone(),
                        action: entry.action.clone(),
                    });
                } else {
                    state.done.push(Done {
                        action: entry.action.clone(),
                        compensate: work.step.compensate.clone().or_else(|| entry.compensate.clone()),
                    });
                }
                state.ran += 1;
            }
        }
    }
}


pub fn act(context: &Context, fail_at: Option<usize>, work: &Work, state: &mut Run) {
    let names = done_names(&state.done);
    let scope = scope_of(context, &names);
    let step = work.step;
    let entry = step
        .action
        .as_deref()
        .and_then(|action| find_entry(context.catalogue, step.connector.as_deref(), action));
    match entry.map(|found| resolve_params(found, &step.params, &scope).map(|resolved| (found, resolved))) {
        None => reject(state, work, "no such action in the catalogue".to_owned()),
        Some(Err(reason)) => reject(state, work, reason),
        Some(Ok((_, resolved))) if is_approval(step) => state.events.push(TraceEvent::Approval {
            path: work.path.clone(),
            params: values_of(&resolved),
        }),
        Some(Ok((found, resolved))) => record_action(context, fail_at, work, found, &resolved, state),
    }
}


pub fn branch<'a>(context: &Context, work: &Work<'a>, condition: &str, state: &mut Run<'a>) {
    let names = done_names(&state.done);
    let scope = scope_of(context, &names);
    let outcome = evaluate_condition(condition, &scope).map_or_else(
        |failure| ConditionOutcome::Failed(failure.to_string()),
        |truth| if truth { ConditionOutcome::True } else { ConditionOutcome::False },
    );
    let (chosen, name): (&[Step], &str) = match outcome {
        ConditionOutcome::True => (&work.step.then, "then"),
        ConditionOutcome::False => (&work.step.otherwise, "else"),
        ConditionOutcome::Failed(_) => (&[], "none"),
    };
    state.events.push(TraceEvent::Condition {
        path: work.path.clone(),
        expression: condition.to_owned(),
        outcome,
    });
    state.pending.extend(work_for(chosen, &format!("{}.{name}", work.path)));
}


pub fn advance<'a>(context: &Context, fail_at: Option<usize>, mut state: Run<'a>) -> ControlFlow<Run<'a>, Run<'a>> {
    let stopped = state.failed || state.halted;
    match state.pending.pop().filter(|_| !stopped) {
        Some(work) => {
            match &work.step.condition {
                Some(condition) => branch(context, &work, condition, &mut state),
                None => act(context, fail_at, &work, &mut state),
            }
            ControlFlow::Continue(state)
        }
        None => ControlFlow::Break(state),
    }
}


/// Runs `steps` in order, depth first, until they end, one fails or the breakers stop the playbook.
pub fn run_sequence<'a>(context: &Context, steps: &'a [Step], root: &str, fail_at: Option<usize>, state: Run<'a>) -> Run<'a> {
    let seeded = Run {
        pending: work_for(steps, root),
        ..state
    };
    match (0..MAX_WORK).try_fold(seeded, |current, _| advance(context, fail_at, current)) {
        ControlFlow::Break(finished) | ControlFlow::Continue(finished) => finished,
    }
}


/// Compensations run in reverse order of the actions that would have run.
pub fn compensations(done: &[Done]) -> Vec<TraceEvent> {
    done.iter()
        .rev()
        .filter_map(|finished| {
            finished.compensate.as_ref().map(|compensate| TraceEvent::Compensation {
                action: compensate.clone(),
                compensates: finished.action.clone(),
            })
        })
        .collect()
}


pub fn run_all(context: &Context) -> Vec<TraceEvent> {
    let first = run_sequence(context, &context.playbook.steps, STEPS_ROOT, context.input.fail_action, Run::default());
    if first.failed {
        let mut events = first.events;
        events.extend(compensations(&first.done));
        events.push(TraceEvent::ErrorHandler);
        let handler = Run {
            events,
            done: first.done,
            ran: first.ran,
            ..Run::default()
        };
        run_sequence(context, &context.playbook.on_error, ON_ERROR_ROOT, None, handler).events
    } else {
        first.events
    }
}


/// Simulates one alert. The breakers are asked for every action (and count it); nothing is executed.
pub fn simulate(playbook: &Playbook, catalogue: &Catalogue, breakers: &Breakers, input: &SimulationInput) -> Trace {
    let context = Context {
        playbook,
        catalogue,
        breakers,
        input,
    };
    let unmet = mismatches(&playbook.trigger, &input.alert);
    let matched = unmet.is_empty();
    let trigger = TraceEvent::Trigger { matched, mismatches: unmet };
    let events = if matched { run_all(&context) } else { Vec::new() };
    Trace {
        playbook: playbook.name.clone(),
        version: playbook.version,
        mode: playbook.mode,
        events: std::iter::once(trigger).chain(events).collect(),
    }
}

use crate::catalogue::find_entry;
use crate::error::Problem;
use crate::expr::{check_template, is_template, single_expression};
use crate::model::{Catalogue, CatalogueEntry, Playbook, Step};
use crate::params::check_type;
use crate::trigger::ALERT_PREFIX;
use crate::walk::{flatten, FlatStep, MAX_DEPTH};
use serde_json::Value;


pub const STEPS_ROOT: &str = "steps";


pub const ON_ERROR_ROOT: &str = "on_error";


pub fn malformed(path: &str, reason: &str) -> Problem {
    Problem::MalformedStep {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}


pub fn expression_problem(path: &str, message: String) -> Problem {
    Problem::BadExpression {
        path: path.to_owned(),
        message,
    }
}


/// The shape of one step: a conditional holds `if`, `then` and `else` only; an action step holds no branch.
pub fn shape_problems(flat: &FlatStep) -> Vec<Problem> {
    let step = flat.step;
    let path = flat.path.as_str();
    match &step.condition {
        Some(condition) => {
            let stray = step.action.is_some() || step.connector.is_some() || !step.params.is_empty() || step.compensate.is_some();
            [
                stray.then(|| malformed(path, "a conditional step holds only `if`, `then` and `else`")),
                step.then.is_empty().then(|| malformed(path, "`if` needs a non-empty `then`")),
                single_expression(condition)
                    .is_none()
                    .then(|| expression_problem(path, "the condition must be one `{{ expression }}`".to_owned())),
                check_template(condition)
                    .err()
                    .map(|failure| expression_problem(&format!("{path}.if"), failure.to_string())),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
        None => [
            (!step.then.is_empty() || !step.otherwise.is_empty()).then(|| malformed(path, "`then` and `else` need an `if`")),
            step.action.is_none().then(|| malformed(path, "a step needs an `action` or an `if`")),
        ]
        .into_iter()
        .flatten()
        .collect(),
    }
}


pub fn literal_problem(path: &str, name: &str, value: &Value, entry: &CatalogueEntry) -> Option<Problem> {
    match (value, entry.params.get(name)) {
        (_, None) => Some(Problem::UnknownParam {
            path: path.to_owned(),
            action: entry.action.clone(),
            param: name.to_owned(),
        }),
        (Value::String(text), Some(_)) if is_template(text) => check_template(text)
            .err()
            .map(|failure| expression_problem(&format!("{path}.params.{name}"), failure.to_string())),
        (literal, Some(spec)) => check_type(spec.kind, literal).err().map(|message| Problem::ParamType {
            path: path.to_owned(),
            param: name.to_owned(),
            message,
        }),
    }
}


pub fn param_problems(path: &str, step: &Step, entry: &CatalogueEntry) -> Vec<Problem> {
    let missing = entry
        .params
        .iter()
        .filter(|(name, spec)| !spec.optional && !step.params.contains_key(*name))
        .map(|(name, _)| Problem::MissingParam {
            path: path.to_owned(),
            action: entry.action.clone(),
            param: name.clone(),
        });
    step.params
        .iter()
        .filter_map(|(name, value)| literal_problem(path, name, value, entry))
        .chain(missing)
        .collect()
}


/// The compensation of a destructive action is the step's own or the catalogue's; it must exist in the catalogue.
pub fn compensation_problem(path: &str, step: &Step, entry: &CatalogueEntry, catalogue: &Catalogue) -> Option<Problem> {
    match step.compensate.as_ref().or(entry.compensate.as_ref()) {
        None => entry.destructive.then(|| Problem::MissingCompensation {
            path: path.to_owned(),
            action: entry.action.clone(),
        }),
        Some(compensate) => find_entry(catalogue, entry.connector.as_deref(), compensate)
            .is_none()
            .then(|| Problem::UnknownCompensation {
                path: path.to_owned(),
                action: entry.action.clone(),
                compensate: compensate.clone(),
            }),
    }
}


pub const ENTITY_PREFIX: &str = "alert.";


/// A bare `{{ alert.name }}`: one level of the alert, nothing computed.
pub fn is_bare_entity(text: &str) -> bool {
    single_expression(text)
        .map(str::trim)
        .and_then(|inner| inner.strip_prefix(ENTITY_PREFIX))
        .is_some_and(|name| !name.is_empty() && name.chars().all(|letter| letter.is_alphanumeric() || letter == '_'))
}


/// The breakers look the target up in the inventory by identifier: it must come straight from the alert or be a literal.
pub fn target_problem(path: &str, step: &Step, entry: &CatalogueEntry) -> Option<Problem> {
    let binding = entry.breaker.as_ref()?;
    match step.params.get(&binding.target) {
        Some(Value::String(text)) if is_template(text) && !is_bare_entity(text) => Some(Problem::BreakerTargetNotEntity {
            path: path.to_owned(),
            param: binding.target.clone(),
        }),
        _ => None,
    }
}


pub fn action_problems(flat: &FlatStep, catalogue: &Catalogue) -> Vec<Problem> {
    let step = flat.step;
    step.action.as_ref().map_or_else(Vec::new, |action| {
        find_entry(catalogue, step.connector.as_deref(), action).map_or_else(
            || {
                vec![Problem::UnknownAction {
                    path: flat.path.clone(),
                    connector: step.connector.clone().unwrap_or_else(|| "(built-in)".to_owned()),
                    action: action.clone(),
                }]
            },
            |entry| {
                param_problems(&flat.path, step, entry)
                    .into_iter()
                    .chain(compensation_problem(&flat.path, step, entry, catalogue))
                    .chain(target_problem(&flat.path, step, entry))
                    .collect()
            },
        )
    })
}


pub fn step_problems(flat: &FlatStep, catalogue: &Catalogue) -> Vec<Problem> {
    let shape = shape_problems(flat);
    shape.into_iter().chain(action_problems(flat, catalogue)).collect()
}


pub fn sequence_problems(steps: &[Step], root: &str, catalogue: &Catalogue) -> Vec<Problem> {
    let flattened = flatten(steps, root);
    flattened
        .steps
        .iter()
        .flat_map(|flat| step_problems(flat, catalogue))
        .chain(flattened.truncated.then_some(Problem::TooDeep(MAX_DEPTH)))
        .collect()
}


pub fn trigger_problems(playbook: &Playbook) -> Vec<Problem> {
    playbook
        .trigger
        .keys()
        .filter(|key| !key.starts_with(ALERT_PREFIX))
        .map(|key| Problem::BadTrigger(key.clone()))
        .collect()
}


/// Every problem of a playbook against a catalogue, not only the first.
pub fn playbook_problems(playbook: &Playbook, catalogue: &Catalogue) -> Vec<Problem> {
    [
        playbook.name.trim().is_empty().then_some(Problem::EmptyName),
        playbook.steps.is_empty().then_some(Problem::EmptySteps),
        playbook.on_error.is_empty().then_some(Problem::MissingOnError),
    ]
    .into_iter()
    .flatten()
    .chain(trigger_problems(playbook))
    .chain(sequence_problems(&playbook.steps, STEPS_ROOT, catalogue))
    .chain(sequence_problems(&playbook.on_error, ON_ERROR_ROOT, catalogue))
    .collect()
}

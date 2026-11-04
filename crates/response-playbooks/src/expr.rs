use crate::error::ExprError;
use crate::model::Mode;
use crate::types::ParamMap;
use minijinja::value::Serde;
use minijinja::{escape_formatter, Environment, Output, State, UndefinedBehavior, Value};
use serde::Serialize;


pub const FUEL: u64 = 500;


pub const MAX_SOURCE_LEN: usize = 2_000;


pub const MAX_NESTING: usize = 16;


pub const OPENERS: [char; 3] = ['(', '[', '{'];


pub const CLOSERS: [char; 3] = [')', ']', '}'];


pub const RECURSION_LIMIT: usize = 8;


pub const DISPLAY_KEY: &str = "value";


pub const OPEN: &str = "{{";


pub const CLOSE: &str = "}}";


pub const FORBIDDEN_TAGS: [&str; 2] = ["{%", "{#"];


#[derive(Debug, Serialize)]
pub struct PlaybookScope<'a> {
    pub name: &'a str,
    pub version: u64,
    pub mode: Mode,
    pub variables: &'a ParamMap,
    pub actions_done: &'a [String],
}


#[derive(Debug, Serialize)]
pub struct Scope<'a> {
    pub alert: &'a serde_json::Value,
    pub playbook: PlaybookScope<'a>,
}


/// An entity (host, user, address) is a map with a `value` member: printed in text, it shows that member only.
pub fn display_entity(out: &mut Output, state: &mut State, value: &Value) -> Result<(), minijinja::Error> {
    match value.get_attr(DISPLAY_KEY) {
        Ok(inner) if !inner.is_undefined() => escape_formatter(out, state, &inner),
        _ => escape_formatter(out, state, value),
    }
}


/// No loader, no include, no filesystem, no network; missing fields are undefined (falsy, printed empty); bounded fuel and recursion.
pub fn sandbox<'a>() -> Environment<'a> {
    let mut environment = Environment::new();
    environment.set_undefined_behavior(UndefinedBehavior::Chainable);
    environment.set_fuel(Some(FUEL));
    environment.set_recursion_limit(RECURSION_LIMIT);
    environment.set_formatter(display_entity);
    environment
}


pub fn is_template(text: &str) -> bool {
    text.contains(OPEN) || FORBIDDEN_TAGS.iter().any(|tag| text.contains(tag))
}


/// The inner expression when the whole text is one `{{ expression }}`.
pub fn single_expression(text: &str) -> Option<&str> {
    text.trim()
        .strip_prefix(OPEN)
        .and_then(|rest| rest.strip_suffix(CLOSE))
        .filter(|inner| !inner.contains(OPEN) && !inner.contains(CLOSE))
}


/// Deepest bracket nesting of the text, by one bounded pass; brackets inside string literals count too, which only over-refuses.
pub fn nesting_depth(text: &str) -> usize {
    text.chars()
        .fold((0, 0), |(current, deepest): (usize, usize), letter| {
            let next = if OPENERS.contains(&letter) {
                current + 1
            } else if CLOSERS.contains(&letter) {
                current.saturating_sub(1)
            } else {
                current
            };
            (next, deepest.max(next))
        })
        .1
}


/// The size caps are checked before minijinja compiles anything: its compiler recurses over the syntax tree.
pub fn check_limits(text: &str) -> Result<(), ExprError> {
    let length = text.len();
    let depth = nesting_depth(text);
    if length > MAX_SOURCE_LEN {
        Err(ExprError::TooLong { length, max: MAX_SOURCE_LEN })
    } else if depth > MAX_NESTING {
        Err(ExprError::TooNested { depth, max: MAX_NESTING })
    } else {
        Ok(())
    }
}


/// Refused before any compilation: an oversized or too deeply nested source, then block tags.
pub fn refuse_blocks(text: &str) -> Result<(), ExprError> {
    check_limits(text)?;
    FORBIDDEN_TAGS
        .iter()
        .find(|tag| text.contains(**tag))
        .map_or(Ok(()), |tag| Err(ExprError::Forbidden((*tag).to_owned())))
}


/// Compiles without evaluating: a syntax error or a block tag is refused.
pub fn check_template(text: &str) -> Result<(), ExprError> {
    refuse_blocks(text)?;
    let environment = sandbox();
    single_expression(text).map_or_else(
        || environment.template_from_str(text).map(|_compiled| ()),
        |inner| environment.compile_expression(inner).map(|_compiled| ()),
    )?;
    Ok(())
}


pub fn scope_value(scope: &Scope) -> Value {
    Value::from(Serde(scope))
}


pub fn evaluate(expression: &str, scope: &Scope) -> Result<Value, ExprError> {
    refuse_blocks(expression)?;
    let environment = sandbox();
    Ok(environment.compile_expression(expression)?.eval(scope_value(scope))?)
}


/// A guard that cannot be evaluated is an error for the caller to treat as false, never as true.
pub fn evaluate_condition(text: &str, scope: &Scope) -> Result<bool, ExprError> {
    let inner = single_expression(text).ok_or_else(|| ExprError::Forbidden(text.to_owned()))?;
    Ok(evaluate(inner, scope)?.is_true())
}


pub fn render(text: &str, scope: &Scope) -> Result<String, ExprError> {
    refuse_blocks(text)?;
    Ok(sandbox().render_str(text, scope_value(scope))?)
}


/// A text that is one expression keeps the type of its result (entity maps included); other texts render to a string.
pub fn resolve(text: &str, scope: &Scope) -> Result<serde_json::Value, ExprError> {
    match single_expression(text) {
        Some(inner) => Ok(serde_json::to_value(evaluate(inner, scope)?)?),
        None => Ok(serde_json::Value::String(render(text, scope)?)),
    }
}

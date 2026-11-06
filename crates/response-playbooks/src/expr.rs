use crate::error::ExprError;
use crate::model::Mode;
use crate::types::ParamMap;
use minijinja::value::Serde;
use minijinja::{escape_formatter, Environment, Output, State, UndefinedBehavior, Value};
use serde::Serialize;
use std::thread;


pub const FUEL: u64 = 100;


pub const MAX_SOURCE_LEN: usize = 512;


pub const MAX_NESTING: usize = 32;


pub const MAX_OPERATORS: usize = 128;


pub const WORKER_STACK_BYTES: usize = 8_388_608;


pub const OPERATOR_CHARS: [char; 17] = ['(', '[', '{', '-', '+', '.', '|', '*', '~', '<', '>', '=', '!', '&', '/', '%', ','];


pub const OPERATOR_WORDS: [&str; 7] = ["not", "and", "or", "if", "is", "in", "else"];


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


/// Every construct that can nest the syntax tree (brackets, unary and binary operators including `%` and `//`, `,`, `.`, `|`, `**`, `~`, keywords), over-counted on purpose.
pub fn operator_count(text: &str) -> usize {
    let symbols = text.chars().filter(|letter| OPERATOR_CHARS.contains(letter)).count();
    let words = text
        .split(|letter: char| !letter.is_alphanumeric() && letter != '_')
        .filter(|word| OPERATOR_WORDS.contains(word))
        .count();
    symbols + words
}


/// The size caps are checked before minijinja compiles anything: its compiler recurses over the syntax tree.
pub fn check_limits(text: &str) -> Result<(), ExprError> {
    let length = text.len();
    let depth = nesting_depth(text);
    let operators = operator_count(text);
    if length > MAX_SOURCE_LEN {
        Err(ExprError::TooLong { length, max: MAX_SOURCE_LEN })
    } else if depth > MAX_NESTING {
        Err(ExprError::TooNested { depth, max: MAX_NESTING })
    } else if operators > MAX_OPERATORS {
        Err(ExprError::TooComplex {
            operators,
            max: MAX_OPERATORS,
        })
    } else {
        Ok(())
    }
}


/// Runs the work on a scoped thread with an explicit stack size, so the guarantee does not depend on the caller's thread.
pub fn on_worker<Output: Send>(stack_bytes: usize, work: impl FnOnce() -> Result<Output, ExprError> + Send) -> Result<Output, ExprError> {
    thread::scope(|scope| {
        let handle = thread::Builder::new().stack_size(stack_bytes).spawn_scoped(scope, work)?;
        handle.join().map_err(|_panic| ExprError::WorkerPanicked)?
    })
}


/// Refused before any compilation: an oversized or too deeply nested source, then block tags.
pub fn refuse_blocks(text: &str) -> Result<(), ExprError> {
    check_limits(text)?;
    FORBIDDEN_TAGS
        .iter()
        .find(|tag| text.contains(**tag))
        .map_or(Ok(()), |tag| Err(ExprError::Forbidden((*tag).to_owned())))
}


/// The value of a text that is one constant expression (no variable of the scope); `None` for any other text.
pub fn constant_value(text: &str) -> Result<Option<serde_json::Value>, ExprError> {
    refuse_blocks(text)?;
    match single_expression(text) {
        Some(inner) => on_worker(WORKER_STACK_BYTES, || {
            let environment = sandbox();
            let compiled = environment.compile_expression(inner)?;
            let constant = compiled.undeclared_variables(false).is_empty();
            constant
                .then(|| compiled.eval(()))
                .transpose()?
                .map(serde_json::to_value)
                .transpose()
                .map_err(ExprError::from)
        }),
        None => Ok(None),
    }
}


/// Compiles without evaluating: a syntax error or a block tag is refused.
pub fn check_template(text: &str) -> Result<(), ExprError> {
    refuse_blocks(text)?;
    on_worker(WORKER_STACK_BYTES, || {
        let environment = sandbox();
        single_expression(text).map_or_else(
            || environment.template_from_str(text).map(|_compiled| ()),
            |inner| environment.compile_expression(inner).map(|_compiled| ()),
        )?;
        Ok(())
    })
}


pub fn scope_value(scope: &Scope) -> Value {
    Value::from(Serde(scope))
}


pub fn evaluate(expression: &str, scope: &Scope) -> Result<Value, ExprError> {
    refuse_blocks(expression)?;
    on_worker(WORKER_STACK_BYTES, || {
        let environment = sandbox();
        Ok(environment.compile_expression(expression)?.eval(scope_value(scope))?)
    })
}


/// A guard that cannot be evaluated is an error for the caller to treat as false, never as true.
pub fn evaluate_condition(text: &str, scope: &Scope) -> Result<bool, ExprError> {
    let inner = single_expression(text).ok_or_else(|| ExprError::Forbidden(text.to_owned()))?;
    Ok(evaluate(inner, scope)?.is_true())
}


pub fn render(text: &str, scope: &Scope) -> Result<String, ExprError> {
    refuse_blocks(text)?;
    on_worker(WORKER_STACK_BYTES, || Ok(sandbox().render_str(text, scope_value(scope))?))
}


/// A text that is one expression keeps the type of its result (entity maps included); other texts render to a string.
pub fn resolve(text: &str, scope: &Scope) -> Result<serde_json::Value, ExprError> {
    match single_expression(text) {
        Some(inner) => Ok(serde_json::to_value(evaluate(inner, scope)?)?),
        None => Ok(serde_json::Value::String(render(text, scope)?)),
    }
}

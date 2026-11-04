use crate::types::SelectionResults;
use glob::Pattern;
use sigma_sql::condition::{Operator, Quantifier, Token};


/// A condition in postfix order, ready to be evaluated against the selection results of one event.
#[derive(Debug, Clone)]
pub enum Step {
    Selection(String),
    Of(Quantifier, Vec<String>),
    Apply(Operator),
}


pub struct Converter<'a> {
    pub output: Vec<Step>,
    pub operators: Vec<Option<Operator>>,
    pub names: &'a [String],
}


fn pop_into_output(converter: &mut Converter, count: usize) {
    (0..count).for_each(|_| {
        converter
            .operators
            .pop()
            .flatten()
            .into_iter()
            .for_each(|operator| converter.output.push(Step::Apply(operator)));
    });
}


fn shift_binary(converter: &mut Converter, incoming: Operator) {
    let count = converter.operators.iter().rev().take_while(|top| **top >= Some(incoming)).count();
    pop_into_output(converter, count);
    converter.operators.push(Some(incoming));
}


fn shift_close(converter: &mut Converter) {
    let count = converter.operators.iter().rev().take_while(|top| top.is_some()).count();
    pop_into_output(converter, count);
    converter.operators.pop();
}


fn expand(converter: &Converter, target: &str) -> Vec<String> {
    let pattern = if target == "them" { "*" } else { target };
    Pattern::new(pattern)
        .into_iter()
        .flat_map(|matcher| converter.names.iter().filter(move |name| matcher.matches(name)).cloned())
        .collect()
}


fn shift_token(converter: &mut Converter, token: &Token) {
    match token {
        Token::Open => converter.operators.push(None),
        Token::Close => shift_close(converter),
        Token::Not => converter.operators.push(Some(Operator::Not)),
        Token::And => shift_binary(converter, Operator::And),
        Token::Or => shift_binary(converter, Operator::Or),
        Token::Selection(name) => converter.output.push(Step::Selection(name.clone())),
        Token::Of(quantifier, target) => {
            let names = expand(converter, target);
            converter.output.push(Step::Of(*quantifier, names));
        }
    }
}


/// Shunting-yard over tokens that `sigma_sql::condition::compile_condition` already accepted; `not` binds tighter than `and`, then `or`.
pub fn to_steps(tokens: &[Token], names: &[String]) -> Vec<Step> {
    let mut converter = Converter {
        output: Vec::new(),
        operators: Vec::new(),
        names,
    };
    tokens.iter().for_each(|token| shift_token(&mut converter, token));
    let remaining = converter.operators.len();
    pop_into_output(&mut converter, remaining);
    converter.output
}


fn matched(results: &SelectionResults, name: &str) -> bool {
    results.get(name).is_some_and(|flag| *flag)
}


fn pop_bool(stack: &mut Vec<bool>) -> bool {
    stack.pop().is_some_and(|flag| flag)
}


fn apply_step(stack: &mut Vec<bool>, step: &Step, results: &SelectionResults) {
    match step {
        Step::Selection(name) => stack.push(matched(results, name)),
        Step::Of(Quantifier::One, names) => stack.push(names.iter().any(|name| matched(results, name))),
        Step::Of(Quantifier::All, names) => stack.push(names.iter().all(|name| matched(results, name))),
        Step::Apply(Operator::Not) => {
            let operand = pop_bool(stack);
            stack.push(!operand);
        }
        Step::Apply(Operator::And) => {
            let right = pop_bool(stack);
            let left = pop_bool(stack);
            stack.push(left && right);
        }
        Step::Apply(Operator::Or) => {
            let right = pop_bool(stack);
            let left = pop_bool(stack);
            stack.push(left || right);
        }
    }
}


pub fn evaluate(steps: &[Step], results: &SelectionResults) -> bool {
    let mut stack = Vec::new();
    steps.iter().for_each(|step| apply_step(&mut stack, step, results));
    pop_bool(&mut stack)
}

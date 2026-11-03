use crate::error::SigmaError;
use crate::types::SelectionSql;
use glob::Pattern;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    One,
    All,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Open,
    Close,
    And,
    Or,
    Not,
    Selection(String),
    Of(Quantifier, String),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Nothing,
    Quantifier(Quantifier),
    Of(Quantifier),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    Or,
    And,
    Not,
}


pub struct Parser {
    pub operands: Vec<String>,
    pub operators: Vec<Option<Operator>>,
    pub expect_operand: bool,
}


fn bad(rule: &str, reason: &str) -> SigmaError {
    SigmaError::BadCondition {
        rule: rule.to_string(),
        reason: reason.to_string(),
    }
}


fn lex_word(pending: Pending, word: &str, tokens: &mut Vec<Token>, rule: &str) -> Result<Pending, SigmaError> {
    match (pending, word) {
        (Pending::Nothing, "(") => Ok(push(tokens, Token::Open)),
        (Pending::Nothing, ")") => Ok(push(tokens, Token::Close)),
        (Pending::Nothing, "and") => Ok(push(tokens, Token::And)),
        (Pending::Nothing, "or") => Ok(push(tokens, Token::Or)),
        (Pending::Nothing, "not") => Ok(push(tokens, Token::Not)),
        (Pending::Nothing, "1") => Ok(Pending::Quantifier(Quantifier::One)),
        (Pending::Nothing, "all") => Ok(Pending::Quantifier(Quantifier::All)),
        (Pending::Nothing, name) => Ok(push(tokens, Token::Selection(name.to_string()))),
        (Pending::Quantifier(quantifier), "of") => Ok(Pending::Of(quantifier)),
        (Pending::Quantifier(_), _) => Err(bad(rule, "a quantifier must be followed by `of`")),
        (Pending::Of(quantifier), target) => Ok(push(tokens, Token::Of(quantifier, target.to_string()))),
    }
}


fn push(tokens: &mut Vec<Token>, token: Token) -> Pending {
    tokens.push(token);
    Pending::Nothing
}


/// Splits a condition into tokens; parentheses need no surrounding spaces.
pub fn tokenize(rule: &str, condition: &str) -> Result<Vec<Token>, SigmaError> {
    let spaced = condition.replace('(', " ( ").replace(')', " ) ");
    let mut tokens = Vec::new();
    let pending = spaced
        .split_whitespace()
        .try_fold(Pending::Nothing, |state, word| lex_word(state, word, &mut tokens, rule))?;
    if pending == Pending::Nothing {
        Ok(tokens)
    } else {
        Err(bad(rule, "incomplete `of` expression"))
    }
}


fn glob_matches(rule: &str, pattern: &str, selections: &SelectionSql) -> Result<Vec<String>, SigmaError> {
    let matcher = Pattern::new(pattern).map_err(|error| bad(rule, &error.to_string()))?;
    Ok(selections.keys().filter(|name| matcher.matches(name)).cloned().collect())
}


fn of_sql(rule: &str, quantifier: Quantifier, target: &str, selections: &SelectionSql) -> Result<String, SigmaError> {
    let pattern = if target == "them" { "*" } else { target };
    let names = glob_matches(rule, pattern, selections)?;
    let parts: Vec<String> = selections
        .iter()
        .filter(|(name, _)| names.contains(name))
        .map(|(_, sql)| sql.clone())
        .collect();
    let separator = if quantifier == Quantifier::One { " OR " } else { " AND " };
    if parts.is_empty() {
        Err(SigmaError::MissingSelection {
            rule: rule.to_string(),
            name: target.to_string(),
        })
    } else {
        Ok(format!("({})", parts.join(separator)))
    }
}


fn selection_sql(rule: &str, name: &str, selections: &SelectionSql) -> Result<String, SigmaError> {
    selections
        .get(name)
        .map(|sql| format!("({sql})"))
        .ok_or_else(|| SigmaError::MissingSelection {
            rule: rule.to_string(),
            name: name.to_string(),
        })
}


fn pop_operand(parser: &mut Parser) -> String {
    parser.operands.pop().into_iter().collect()
}


fn apply(parser: &mut Parser, operator: Operator) {
    let right = pop_operand(parser);
    let combined = match operator {
        Operator::Not => format!("NOT {right}"),
        Operator::And => format!("({} AND {right})", pop_operand(parser)),
        Operator::Or => format!("({} OR {right})", pop_operand(parser)),
    };
    parser.operands.push(combined);
}


fn reduce_times(parser: &mut Parser, count: usize) {
    (0..count).for_each(|_| parser.operators.pop().flatten().into_iter().for_each(|operator| apply(parser, operator)));
}


fn shift_binary(rule: &str, parser: &mut Parser, incoming: Operator) -> Result<(), SigmaError> {
    if parser.expect_operand {
        Err(bad(rule, "operator where an operand was expected"))
    } else {
        let count = parser.operators.iter().rev().take_while(|top| **top >= Some(incoming)).count();
        reduce_times(parser, count);
        parser.operators.push(Some(incoming));
        parser.expect_operand = true;
        Ok(())
    }
}


fn shift_open(rule: &str, parser: &mut Parser) -> Result<(), SigmaError> {
    if parser.expect_operand {
        parser.operators.push(None);
        Ok(())
    } else {
        Err(bad(rule, "missing operator before an opening parenthesis"))
    }
}


fn shift_not(rule: &str, parser: &mut Parser) -> Result<(), SigmaError> {
    if parser.expect_operand {
        parser.operators.push(Some(Operator::Not));
        Ok(())
    } else {
        Err(bad(rule, "`not` where an operator was expected"))
    }
}


fn shift_close(rule: &str, parser: &mut Parser) -> Result<(), SigmaError> {
    let count = parser.operators.iter().rev().take_while(|top| top.is_some()).count();
    if parser.expect_operand {
        Err(bad(rule, "operand missing before a closing parenthesis"))
    } else {
        reduce_times(parser, count);
        match parser.operators.pop() {
            Some(None) => Ok(()),
            _ => Err(bad(rule, "unbalanced parentheses")),
        }
    }
}


fn shift_operand(rule: &str, parser: &mut Parser, sql: String) -> Result<(), SigmaError> {
    if parser.expect_operand {
        parser.operands.push(sql);
        parser.expect_operand = false;
        Ok(())
    } else {
        Err(bad(rule, "two operands without an operator"))
    }
}


fn shift(rule: &str, parser: &mut Parser, token: &Token, selections: &SelectionSql) -> Result<(), SigmaError> {
    match token {
        Token::Open => shift_open(rule, parser),
        Token::Close => shift_close(rule, parser),
        Token::And => shift_binary(rule, parser, Operator::And),
        Token::Or => shift_binary(rule, parser, Operator::Or),
        Token::Not => shift_not(rule, parser),
        Token::Selection(name) => shift_operand(rule, parser, selection_sql(rule, name, selections)?),
        Token::Of(quantifier, target) => shift_operand(rule, parser, of_sql(rule, *quantifier, target, selections)?),
    }
}


/// Compiles a condition to a SQL boolean expression with an iterative shunting-yard; `not` binds tighter than `and`, then `or`.
pub fn compile_condition(rule: &str, condition: &str, selections: &SelectionSql) -> Result<String, SigmaError> {
    let tokens = tokenize(rule, condition)?;
    let mut parser = Parser {
        operands: Vec::new(),
        operators: Vec::new(),
        expect_operand: true,
    };
    tokens.iter().try_for_each(|token| shift(rule, &mut parser, token, selections))?;
    if parser.expect_operand {
        Err(bad(rule, "the condition is empty or ends with an operator"))
    } else if parser.operators.iter().any(Option::is_none) {
        Err(bad(rule, "unbalanced parentheses"))
    } else {
        let count = parser.operators.len();
        reduce_times(&mut parser, count);
        Ok(pop_operand(&mut parser))
    }
}

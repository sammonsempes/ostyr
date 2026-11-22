use crate::{
    model::{Context, Violation},
    rules_flow::at_offset,
    tokens::{before, significant_tokens, Token},
};
use ra_ap_rustc_lexer::TokenKind;


pub const BOOL_ARRAY: &str = "bool-array";


const CONTAINS_PREFIX: &[&str] = &["]", ".", "contains", "(", "&"];


const CONTAINS_WIDTH: usize = 7;


const ANY_PREFIX: &[&str] = &["]", ".", "iter", "(", ")", ".", "any", "(", "|"];


const ANY_WIDTH: usize = 14;


const MESSAGE: &str = "a boolean array literal evaluates every operand and hides branches from the coverage gate; use `||` or `&&`";


fn texts_start_with(window: &[Token], expected: &[&str]) -> bool {
    window.iter().map(|token| token.text).take(expected.len()).eq(expected.iter().copied())
}


fn text_at<'a>(window: &[Token<'a>], index: usize) -> Option<&'a str> {
    window.get(index).map(|token| token.text)
}


fn is_contains_bool(window: &[Token]) -> bool {
    texts_start_with(window, CONTAINS_PREFIX)
        && matches!(text_at(window, CONTAINS_PREFIX.len()), Some("true" | "false"))
        && text_at(window, CONTAINS_PREFIX.len() + 1) == Some(")")
}


fn is_any_identity(window: &[Token]) -> bool {
    let tail: Vec<&Token> = window.iter().skip(ANY_PREFIX.len()).collect();
    texts_start_with(window, ANY_PREFIX)
        && matches!(tail.as_slice(), [param, bar, star, again, close]
            if param.kind == TokenKind::Ident && bar.text == "|" && star.text == "*" && again.text == param.text && close.text == ")")
}


fn is_array_literal(tokens: &[Token], close: usize) -> bool {
    tokens
        .iter()
        .enumerate()
        .take(close + 1)
        .rev()
        .scan(0usize, |depth, (index, token)| {
            match token.kind {
                TokenKind::CloseParen | TokenKind::CloseBracket | TokenKind::CloseBrace => *depth += 1,
                TokenKind::OpenParen | TokenKind::OpenBracket | TokenKind::OpenBrace => *depth = depth.saturating_sub(1),
                _ => {}
            }
            Some((index, token.kind, *depth))
        })
        .find(|(_, kind, depth)| *kind == TokenKind::OpenBracket && *depth == 0)
        .is_some_and(|(open, _, _)| {
            !before(tokens, open, 1)
                .is_some_and(|previous| matches!(previous.kind, TokenKind::Ident | TokenKind::CloseParen | TokenKind::CloseBracket))
        })
}


pub fn bool_array(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    let contains = tokens.windows(CONTAINS_WIDTH).enumerate().filter(|(_, window)| is_contains_bool(window));
    let any = tokens.windows(ANY_WIDTH).enumerate().filter(|(_, window)| is_any_identity(window));
    contains
        .chain(any)
        .filter(|(index, _)| is_array_literal(&tokens, *index))
        .filter_map(|(index, _)| tokens.get(index))
        .map(|token| at_offset(context, BOOL_ARRAY, token.offset, MESSAGE.to_string()))
        .collect()
}

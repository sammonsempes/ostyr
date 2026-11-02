use crate::{
    model::{violation_at, Context, Violation},
    position::line_column,
    tokens::{is_keyword, significant_tokens, Token},
};
use ra_ap_rustc_lexer::TokenKind;


pub const UNCAPPED_WHILE: &str = "uncapped-while";


pub const LOOP_NESTING: &str = "loop-nesting";


const MAX_NESTING: usize = 3;


pub struct Pending<'a> {
    pub depth: usize,
    pub keyword: &'a str,
    pub offset: usize,
    pub condition: Vec<Token<'a>>,
}


pub struct LoopScan<'a> {
    pub depth: usize,
    pub pending: Vec<Pending<'a>>,
    pub bodies: Vec<usize>,
    pub in_impl_header: bool,
    pub violations: Vec<Violation>,
}


pub fn is_const_name(text: &str) -> bool {
    text.chars().any(|character| character.is_ascii_uppercase())
        && text
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
}


pub fn has_comparison(condition: &[Token]) -> bool {
    let relational = condition.iter().any(|token| matches!(token.kind, TokenKind::Lt | TokenKind::Gt));
    let equality = condition
        .iter()
        .zip(condition.iter().skip(1))
        .any(|(first, second)| matches!(first.kind, TokenKind::Eq | TokenKind::Bang) && second.kind == TokenKind::Eq);
    relational || equality
}


pub fn is_capped(condition: &[Token]) -> bool {
    let names_const = condition.iter().any(|token| token.kind == TokenKind::Ident && is_const_name(token.text));
    names_const && has_comparison(condition)
}


pub fn is_while_true(condition: &[Token]) -> bool {
    matches!(condition, [only] if is_keyword(only, "true"))
}


pub fn loop_keyword<'a>(token: &Token<'a>, next: Option<&Token>, in_impl_header: bool) -> Option<&'a str> {
    let generic_binder = next.is_some_and(|following| following.kind == TokenKind::Lt);
    let is_for = is_keyword(token, "for") && !in_impl_header && !generic_binder;
    let is_loop = is_keyword(token, "loop") || is_keyword(token, "while") || is_for;
    is_loop.then_some(token.text)
}


pub fn at_offset(context: &Context, rule: &'static str, offset: usize, message: String) -> Violation {
    violation_at(context, rule, line_column(&context.source, offset), message)
}


pub fn open_body<'a>(context: &Context, mut scan: LoopScan<'a>, opened: Pending<'a>) -> LoopScan<'a> {
    scan.bodies.push(opened.depth);
    let uncapped = opened.keyword == "while" && !is_while_true(&opened.condition) && !is_capped(&opened.condition);
    let too_deep = scan.bodies.len() > MAX_NESTING;
    scan.violations.extend(uncapped.then(|| {
        at_offset(
            context,
            UNCAPPED_WHILE,
            opened.offset,
            "`while` condition does not compare a counter against a const".to_string(),
        )
    }));
    scan.violations.extend(too_deep.then(|| {
        at_offset(
            context,
            LOOP_NESTING,
            opened.offset,
            format!("loops are nested more than {MAX_NESTING} levels deep"),
        )
    }));
    scan
}


pub fn is_body_brace(scan: &LoopScan, token: &Token) -> bool {
    token.kind == TokenKind::OpenBrace && scan.pending.last().is_some_and(|last| last.depth == scan.depth)
}


pub fn close_depth<'a>(mut scan: LoopScan<'a>, token: &Token) -> LoopScan<'a> {
    let closes = matches!(token.kind, TokenKind::CloseParen | TokenKind::CloseBrace | TokenKind::CloseBracket);
    let opens = matches!(token.kind, TokenKind::OpenParen | TokenKind::OpenBrace | TokenKind::OpenBracket);
    scan.depth = (scan.depth + usize::from(opens)).saturating_sub(usize::from(closes));
    let depth = scan.depth;
    scan.bodies.retain(|body| *body < depth);
    scan.pending.retain(|pending| pending.depth <= depth);
    scan
}


pub fn track_impl_header(in_impl_header: bool, token: &Token) -> bool {
    let resets = matches!(token.kind, TokenKind::Semi | TokenKind::OpenBrace | TokenKind::CloseBrace);
    (in_impl_header || is_keyword(token, "impl")) && !resets
}


pub fn step<'a>(context: &Context, mut scan: LoopScan<'a>, token: Token<'a>, next: Option<&Token>) -> LoopScan<'a> {
    let body = is_body_brace(&scan, &token).then(|| scan.pending.pop()).flatten();
    scan.pending.iter_mut().for_each(|pending| pending.condition.push(token));
    let keyword = loop_keyword(&token, next, scan.in_impl_header);
    let depth = scan.depth;
    scan.pending.extend(keyword.map(|word| Pending {
        depth,
        keyword: word,
        offset: token.offset,
        condition: Vec::new(),
    }));
    scan.in_impl_header = track_impl_header(scan.in_impl_header, &token);
    let moved = close_depth(scan, &token);
    body.into_iter().fold(moved, |current, opened| open_body(context, current, opened))
}


pub fn loop_violations(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    let initial = LoopScan {
        depth: 0,
        pending: Vec::new(),
        bodies: Vec::new(),
        in_impl_header: false,
        violations: Vec::new(),
    };
    tokens
        .iter()
        .enumerate()
        .fold(initial, |scan, (index, token)| step(context, scan, *token, tokens.get(index + 1)))
        .violations
}


pub fn violations_of(context: &Context, rule: &'static str) -> Vec<Violation> {
    loop_violations(context).into_iter().filter(|violation| violation.rule == rule).collect()
}


pub fn uncapped_while(context: &Context) -> Vec<Violation> {
    violations_of(context, UNCAPPED_WHILE)
}


pub fn loop_nesting(context: &Context) -> Vec<Violation> {
    violations_of(context, LOOP_NESTING)
}

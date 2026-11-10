use crate::{
    model::{Context, Violation},
    rules_flow::at_offset,
    tokens::{closing_index, is_keyword, significant_tokens, Token},
};
use ra_ap_rustc_lexer::TokenKind;
use std::{ffi::OsStr, path::Path};


pub const UNDECLARED_AUDIT: &str = "undeclared-audit";


const AUDIT_CRATE: &str = "core-audit";


const LOG_APPEND: &[&str] = &["log", ":", ":", "append"];


const GROUP_START: &[&str] = &["core_audit", ":", ":", "log", ":", ":", "{"];


const MESSAGE: &str = "`core_audit::log::append` is only for core-audit; use `append_declared`";


pub fn in_checked_source(path: &Path) -> bool {
    let names: Vec<&OsStr> = path.components().map(|component| component.as_os_str()).collect();
    matches!(names.as_slice(), [first, second, third, ..] if *first == "crates" && *second != AUDIT_CRATE && *third == "src")
}


fn texts_equal(window: &[Token], expected: &[&str]) -> bool {
    window.iter().map(|token| token.text).eq(expected.iter().copied())
}


pub fn log_append<'a>(window: &[Token<'a>]) -> Option<Token<'a>> {
    window.last().copied().filter(|_| texts_equal(window, LOG_APPEND))
}


pub fn is_group_start(window: &[Token]) -> bool {
    texts_equal(window, GROUP_START)
}


pub fn group_appends<'a>(tokens: &[Token<'a>], start: usize) -> Vec<Token<'a>> {
    let open = start + GROUP_START.len() - 1;
    let close = closing_index(tokens, open, |kind, depth| kind == TokenKind::CloseBrace && depth == 0);
    tokens
        .iter()
        .take(close)
        .skip(open)
        .filter(|token| is_keyword(token, "append"))
        .copied()
        .collect()
}


pub fn undeclared_audit(context: &Context) -> Vec<Violation> {
    if in_checked_source(&context.path) {
        let tokens = significant_tokens(&context.source);
        let direct = tokens.windows(LOG_APPEND.len()).filter_map(log_append);
        let grouped = tokens
            .windows(GROUP_START.len())
            .enumerate()
            .filter(|(_, window)| is_group_start(window))
            .flat_map(|(index, _)| group_appends(&tokens, index));
        direct
            .chain(grouped)
            .map(|token| at_offset(context, UNDECLARED_AUDIT, token.offset, MESSAGE.to_string()))
            .collect()
    } else {
        Vec::new()
    }
}

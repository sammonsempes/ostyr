use crate::{
    model::{violation_at, Context, Violation},
    position::line_column,
    tokens::{is_keyword, is_while_true, significant_tokens, Token},
};
use ra_ap_rustc_lexer::TokenKind;


pub const RETURN: &str = "return";


pub const BREAK_CONTINUE: &str = "break-continue";


pub const BARE_LOOP: &str = "bare-loop";


pub const PROCESS_EXIT: &str = "process-exit";


const EXIT_PATH_WIDTH: usize = 4;


const WHILE_TRUE_WIDTH: usize = 2;


pub fn at_offset(context: &Context, rule: &'static str, offset: usize, message: String) -> Violation {
    violation_at(context, rule, line_column(&context.source, offset), message)
}


fn keyword_violations(context: &Context, rule: &'static str, words: &[&str]) -> Vec<Violation> {
    significant_tokens(&context.source)
        .iter()
        .filter(|token| words.iter().any(|word| is_keyword(token, word)))
        .map(|token| at_offset(context, rule, token.offset, format!("`{}` is not allowed", token.text)))
        .collect()
}


pub fn return_expression(context: &Context) -> Vec<Violation> {
    keyword_violations(context, RETURN, &["return"])
}


pub fn break_continue(context: &Context) -> Vec<Violation> {
    keyword_violations(context, BREAK_CONTINUE, &["break", "continue"])
}


pub fn bare_loop(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    let while_true = tokens
        .windows(WHILE_TRUE_WIDTH)
        .filter(|pair| pair.split_first().is_some_and(|(first, rest)| is_while_true(first.text, rest)))
        .filter_map(|pair| pair.first())
        .map(|token| at_offset(context, BARE_LOOP, token.offset, "`while true` is not allowed".to_string()));
    let bare = tokens
        .iter()
        .filter(|token| is_keyword(token, "loop"))
        .map(|token| at_offset(context, BARE_LOOP, token.offset, "`loop` is not allowed".to_string()));
    bare.chain(while_true).collect()
}


pub fn is_exit_path(window: &[Token]) -> bool {
    matches!(
        window,
        [process, first_colon, second_colon, exit]
            if is_keyword(process, "process")
                && first_colon.kind == TokenKind::Colon
                && second_colon.kind == TokenKind::Colon
                && is_keyword(exit, "exit")
    )
}


pub fn process_exit(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .windows(EXIT_PATH_WIDTH)
        .filter(|window| is_exit_path(window))
        .filter_map(|window| window.first())
        .map(|token| at_offset(context, PROCESS_EXIT, token.offset, "`process::exit` is not allowed".to_string()))
        .collect()
}

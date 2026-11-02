use crate::{
    model::{Context, Violation},
    rules_flow::at_offset,
    tokens::{attributes, is_keyword, significant_tokens, Token},
};
use ra_ap_rustc_lexer::{LiteralKind, TokenKind};
use std::path::Path;


pub const ASSERT_OUTSIDE_TESTS: &str = "assert-outside-tests";


pub const TEST_IN_SRC: &str = "test-in-src";


pub const SILENCER: &str = "silencer";


pub const LET_UNDERSCORE: &str = "let-underscore";


pub const SHELL_C: &str = "shell-c";


const ASSERT_MACROS: [&str; 6] = ["assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne"];


const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "cmd", "powershell"];


const SHELL_FLAGS: [&str; 3] = ["-c", "/c", "-command"];


const SHELL_SPAWN_WIDTH: usize = 6;


const PAIR_WIDTH: usize = 2;


const TRIPLE_WIDTH: usize = 3;


pub fn has_component(path: &Path, name: &str) -> bool {
    path.components().any(|component| component.as_os_str() == name)
}


pub fn is_assert_call(window: &[Token]) -> bool {
    matches!(window, [name, bang] if ASSERT_MACROS.iter().any(|macro_name| is_keyword(name, macro_name)) && bang.kind == TokenKind::Bang)
}


pub fn assert_outside_tests(context: &Context) -> Vec<Violation> {
    if has_component(&context.path, "tests") {
        Vec::new()
    } else {
        significant_tokens(&context.source)
            .windows(PAIR_WIDTH)
            .filter(|window| is_assert_call(window))
            .filter_map(|window| window.first())
            .map(|token| {
                at_offset(
                    context,
                    ASSERT_OUTSIDE_TESTS,
                    token.offset,
                    format!("`{}!` is only allowed in tests/", token.text),
                )
            })
            .collect()
    }
}


pub fn test_in_src(context: &Context) -> Vec<Violation> {
    if has_component(&context.path, "src") {
        let tokens = significant_tokens(&context.source);
        let attribute_hits = attributes(&tokens)
            .into_iter()
            .filter(|attribute| {
                let texts: Vec<&str> = attribute.tokens.iter().map(|token| token.text).collect();
                matches!(texts.as_slice(), ["test"] | ["cfg", "(", "test", ")"])
            })
            .map(|attribute| attribute.offset);
        let module_hits = tokens
            .windows(PAIR_WIDTH)
            .filter(|window| matches!(window, [first, second] if is_keyword(first, "mod") && is_keyword(second, "tests")))
            .filter_map(|window| window.first())
            .map(|token| token.offset);
        attribute_hits
            .chain(module_hits)
            .map(|offset| at_offset(context, TEST_IN_SRC, offset, "tests belong under tests/, not src/".to_string()))
            .collect()
    } else {
        Vec::new()
    }
}


pub fn silencer(context: &Context) -> Vec<Violation> {
    attributes(&significant_tokens(&context.source))
        .into_iter()
        .filter(|attribute| {
            let texts: Vec<&str> = attribute.tokens.iter().map(|token| token.text).collect();
            texts.iter().any(|text| *text == "allow" || *text == "expect")
                || texts.windows(TRIPLE_WIDTH).any(|window| matches!(window, ["coverage", "(", "off"]))
        })
        .map(|attribute| {
            at_offset(
                context,
                SILENCER,
                attribute.offset,
                "lint and coverage silencers are not allowed".to_string(),
            )
        })
        .collect()
}


pub fn let_underscore(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .windows(PAIR_WIDTH)
        .filter(|window| matches!(window, [first, second] if is_keyword(first, "let") && is_keyword(second, "_")))
        .filter_map(|window| window.first())
        .map(|token| at_offset(context, LET_UNDERSCORE, token.offset, "`let _ =` discards a value silently".to_string()))
        .collect()
}


pub fn string_content<'a>(token: &Token<'a>) -> Option<&'a str> {
    matches!(
        token.kind,
        TokenKind::Literal {
            kind: LiteralKind::Str { .. },
            ..
        }
    )
    .then(|| token.text.trim_matches('"'))
}


pub fn is_shell_literal(token: &Token) -> bool {
    string_content(token)
        .and_then(|content| Path::new(content).file_stem())
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| SHELLS.contains(&stem.to_ascii_lowercase().as_str()))
}


pub fn is_shell_flag(token: &Token) -> bool {
    string_content(token).is_some_and(|content| SHELL_FLAGS.contains(&content.to_ascii_lowercase().as_str()))
}


pub fn is_shell_spawn(window: &[Token]) -> bool {
    matches!(
        window,
        [command, first_colon, second_colon, new, paren, literal]
            if is_keyword(command, "Command")
                && first_colon.kind == TokenKind::Colon
                && second_colon.kind == TokenKind::Colon
                && is_keyword(new, "new")
                && paren.kind == TokenKind::OpenParen
                && is_shell_literal(literal)
    )
}


pub fn shell_c(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    tokens
        .windows(SHELL_SPAWN_WIDTH)
        .enumerate()
        .filter(|(_, window)| is_shell_spawn(window))
        .filter(|(index, _)| {
            tokens
                .iter()
                .skip(*index)
                .take_while(|token| token.kind != TokenKind::Semi)
                .any(is_shell_flag)
        })
        .filter_map(|(_, window)| window.first())
        .map(|token| {
            at_offset(
                context,
                SHELL_C,
                token.offset,
                "running a shell with a command string is not allowed".to_string(),
            )
        })
        .collect()
}

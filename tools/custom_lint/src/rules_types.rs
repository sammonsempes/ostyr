use crate::{
    model::{violation_at, Context, Violation},
    rules_flow::at_offset,
    rules_recursion::flatten_items,
    tokens::{is_item_start, is_keyword, significant_tokens, Token},
    types::HeaderToken,
};
use ra_ap_rustc_lexer::TokenKind;
use syn::{spanned::Spanned, Item};


pub const INHERENT_IMPL: &str = "inherent-impl";


pub const CUSTOM_TRAIT: &str = "custom-trait";


pub const IMPL_ALLOWLIST: &str = "impl-allowlist";


pub const ANY_TYPE: &str = "any-type";


pub const TYPE_ALIAS_LOCATION: &str = "type-alias-location";


const ALLOWED_TRAITS: [&str; 9] = ["Display", "Error", "From", "TryFrom", "FromStr", "Default", "Drop", "Read", "Write"];


const TYPES_FILE: &str = "types.rs";


pub fn impl_header<'a>(tokens: &[Token<'a>], impl_index: usize) -> Vec<HeaderToken<'a>> {
    tokens
        .iter()
        .skip(impl_index + 1)
        .scan((0usize, false), |(angle, after_minus), token| {
            let before = *angle;
            match token.kind {
                TokenKind::Lt => *angle += 1,
                TokenKind::Gt if !*after_minus => *angle = angle.saturating_sub(1),
                _ => {}
            }
            *after_minus = token.kind == TokenKind::Minus;
            Some((*token, before.min(*angle)))
        })
        .take_while(|(token, angle)| !(*angle == 0 && (token.kind == TokenKind::OpenBrace || is_keyword(token, "where"))))
        .collect()
}


pub fn trait_name<'a>(header: &[HeaderToken<'a>]) -> Option<Option<&'a str>> {
    header
        .iter()
        .position(|(token, angle)| *angle == 0 && is_keyword(token, "for"))
        .map(|position| {
            header
                .iter()
                .take(position)
                .rfind(|(token, angle)| *angle == 0 && token.kind == TokenKind::Ident)
                .map(|(token, _)| token.text)
        })
}


pub fn impl_violation(context: &Context, impl_token: &Token, header: &[HeaderToken]) -> Option<Violation> {
    match trait_name(header) {
        None => Some(at_offset(
            context,
            INHERENT_IMPL,
            impl_token.offset,
            "inherent `impl` blocks are not allowed".to_string(),
        )),
        Some(name) => name.filter(|trait_name| !ALLOWED_TRAITS.contains(trait_name)).map(|trait_name| {
            at_offset(
                context,
                IMPL_ALLOWLIST,
                impl_token.offset,
                format!("`impl {trait_name}` is not an allowed trait implementation"),
            )
        }),
    }
}


pub fn impl_findings(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| is_keyword(token, "impl") && is_item_start(&tokens, *index))
        .filter_map(|(index, token)| impl_violation(context, token, &impl_header(&tokens, index)))
        .collect()
}


pub fn inherent_impl(context: &Context) -> Vec<Violation> {
    impl_findings(context)
        .into_iter()
        .filter(|violation| violation.rule == INHERENT_IMPL)
        .collect()
}


pub fn impl_allowlist(context: &Context) -> Vec<Violation> {
    impl_findings(context)
        .into_iter()
        .filter(|violation| violation.rule == IMPL_ALLOWLIST)
        .collect()
}


pub fn custom_trait(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .iter()
        .filter(|token| is_keyword(token, "trait"))
        .map(|token| at_offset(context, CUSTOM_TRAIT, token.offset, "custom traits are not allowed".to_string()))
        .collect()
}


pub fn any_type(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .iter()
        .filter(|token| is_keyword(token, "Any"))
        .map(|token| at_offset(context, ANY_TYPE, token.offset, "`Any` is not allowed".to_string()))
        .collect()
}


pub fn type_alias_location(context: &Context) -> Vec<Violation> {
    let in_types_file = context.path.file_name().is_some_and(|name| name == TYPES_FILE);
    flatten_items(&context.file.items)
        .into_iter()
        .filter(|item| matches!(item, Item::Type(_)) && !in_types_file)
        .map(|item| {
            let start = item.span().start();
            violation_at(
                context,
                TYPE_ALIAS_LOCATION,
                (start.line, start.column + 1),
                format!("type aliases belong in {TYPES_FILE}"),
            )
        })
        .collect()
}

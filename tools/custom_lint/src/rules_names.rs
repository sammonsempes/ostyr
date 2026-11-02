use crate::{
    model::{Context, Violation},
    rules_flow::at_offset,
    tokens::{before, closing_index, is_item_start, is_keyword, kind_at, significant_tokens, Token},
    types::Span,
};
use ra_ap_rustc_lexer::{LiteralKind, TokenKind};


pub const FORBIDDEN_IDENT: &str = "forbidden-ident";


pub const MAGIC_NUMBER: &str = "magic-number";


pub const GLOBAL_MUTABLE: &str = "global-mutable";


const ALLOWED_SHORT_IDENTS: [&str; 3] = ["i", "j", "k"];


const ALLOWED_NUMBERS: [&str; 2] = ["0", "1"];


const NOT_CONST_ITEM: [&str; 4] = ["fn", "unsafe", "async", "extern"];


const MUTABLE_TYPES: [&str; 4] = ["Mutex", "RwLock", "Cell", "RefCell"];


const TWO: usize = 2;


const ATOMIC_PREFIX: &str = "Atomic";


const THREAD_LOCAL_TYPES: [&str; 2] = ["Cell", "RefCell"];


pub fn is_short_ident(token: &Token) -> bool {
    token.kind == TokenKind::Ident && token.text.chars().count() == 1 && token.text.chars().all(char::is_alphabetic)
}


pub fn forbidden_ident(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .iter()
        .filter(|token| is_short_ident(token) && !ALLOWED_SHORT_IDENTS.contains(&token.text))
        .map(|token| {
            at_offset(
                context,
                FORBIDDEN_IDENT,
                token.offset,
                format!("identifier `{}` is too short or ambiguous", token.text),
            )
        })
        .collect()
}


pub fn attribute_spans(tokens: &[Token]) -> Vec<Span> {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| {
            token.kind == TokenKind::Pound
                && (kind_at(tokens, index + 1) == Some(TokenKind::OpenBracket)
                    || (kind_at(tokens, index + 1) == Some(TokenKind::Bang) && kind_at(tokens, index + TWO) == Some(TokenKind::OpenBracket)))
        })
        .map(|(index, _)| {
            (
                index,
                closing_index(tokens, index, |kind, depth| kind == TokenKind::CloseBracket && depth == 0),
            )
        })
        .collect()
}


pub fn item_spans(tokens: &[Token], word: &str) -> Vec<Span> {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| {
            is_keyword(token, word)
                && is_item_start(tokens, *index)
                && tokens
                    .get(index + 1)
                    .is_some_and(|next| next.kind == TokenKind::Ident && !NOT_CONST_ITEM.contains(&next.text))
        })
        .map(|(index, _)| (index, closing_index(tokens, index, |kind, depth| kind == TokenKind::Semi && depth == 0)))
        .collect()
}


pub fn in_spans(spans: &[Span], index: usize) -> bool {
    spans.iter().any(|(start, end)| (*start..=*end).contains(&index))
}


pub fn is_tuple_index(tokens: &[Token], index: usize) -> bool {
    before(tokens, index, 1).is_some_and(|previous| previous.kind == TokenKind::Dot)
        && before(tokens, index, TWO).is_none_or(|earlier| earlier.kind != TokenKind::Dot)
}


pub fn is_magic_literal(token: &Token) -> bool {
    match token.kind {
        TokenKind::Literal {
            kind: LiteralKind::Int { .. } | LiteralKind::Float { .. },
            suffix_start,
        } => token
            .text
            .get(..suffix_start as usize)
            .is_some_and(|number| !ALLOWED_NUMBERS.contains(&number)),
        _ => false,
    }
}


pub fn magic_number(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    let excluded: Vec<Span> = attribute_spans(&tokens)
        .into_iter()
        .chain(item_spans(&tokens, "const"))
        .chain(item_spans(&tokens, "static"))
        .collect();
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| is_magic_literal(token) && !in_spans(&excluded, *index) && !is_tuple_index(&tokens, *index))
        .map(|(_, token)| {
            at_offset(
                context,
                MAGIC_NUMBER,
                token.offset,
                format!("numeric literal `{}` must be a named const", token.text),
            )
        })
        .collect()
}


pub fn thread_local_spans(tokens: &[Token]) -> Vec<Span> {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| is_keyword(token, "thread_local") && kind_at(tokens, index + 1) == Some(TokenKind::Bang))
        .map(|(index, _)| {
            let end = closing_index(tokens, index, |kind, depth| {
                matches!(kind, TokenKind::CloseBrace | TokenKind::CloseParen | TokenKind::CloseBracket) && depth == 0
            });
            (index, end)
        })
        .collect()
}


pub fn is_mutable_type(name: &str) -> bool {
    MUTABLE_TYPES.contains(&name) || name.starts_with(ATOMIC_PREFIX)
}


pub fn span_tokens<'a, 'b>(tokens: &'b [Token<'a>], span: &Span) -> impl Iterator<Item = &'b Token<'a>> {
    tokens.iter().skip(span.0).take((span.1 + 1).saturating_sub(span.0))
}


pub fn static_reason(tokens: &[Token], span: &Span) -> Option<String> {
    let declared_mut = span_tokens(tokens, span).nth(1).is_some_and(|token| is_keyword(token, "mut"));
    let held = span_tokens(tokens, span)
        .take_while(|token| token.kind != TokenKind::Eq)
        .find(|token| token.kind == TokenKind::Ident && is_mutable_type(token.text))
        .map(|token| format!("`{}` in a static is global mutable state", token.text));
    declared_mut.then(|| "`static mut` is global mutable state".to_string()).or(held)
}


pub fn thread_local_reason(tokens: &[Token], span: &Span) -> Option<String> {
    span_tokens(tokens, span)
        .find(|token| token.kind == TokenKind::Ident && THREAD_LOCAL_TYPES.contains(&token.text))
        .map(|token| format!("`thread_local!` holding `{}` is global mutable state", token.text))
}


pub fn global_mutable(context: &Context) -> Vec<Violation> {
    let tokens = significant_tokens(&context.source);
    let thread_locals = thread_local_spans(&tokens);
    let statics = item_spans(&tokens, "static")
        .into_iter()
        .filter(|span| !in_spans(&thread_locals, span.0))
        .filter_map(|span| static_reason(&tokens, &span).map(|reason| (span.0, reason)));
    let locals = thread_locals
        .iter()
        .filter_map(|span| thread_local_reason(&tokens, span).map(|reason| (span.0, reason)));
    statics
        .chain(locals)
        .filter_map(|(index, reason)| tokens.get(index).map(|token| at_offset(context, GLOBAL_MUTABLE, token.offset, reason)))
        .collect()
}

use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, TokenKind};


const ITEM_PREFIXES: [&str; 3] = ["pub", "unsafe", "default"];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    pub kind: TokenKind,
    pub text: &'a str,
    pub offset: usize,
}


pub fn is_trivia(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Whitespace | TokenKind::LineComment { .. } | TokenKind::BlockComment { .. }
    )
}


pub fn significant_tokens(source: &str) -> Vec<Token<'_>> {
    tokenize(source, FrontmatterAllowed::No)
        .scan(0, |offset, token| {
            let start = *offset;
            *offset += token.len as usize;
            Some((start, token))
        })
        .filter(|(_, token)| !is_trivia(token.kind))
        .filter_map(|(start, token)| {
            source.get(start..start + token.len as usize).map(|text| Token {
                kind: token.kind,
                text,
                offset: start,
            })
        })
        .collect()
}


pub fn is_keyword(token: &Token, word: &str) -> bool {
    token.kind == TokenKind::Ident && token.text == word
}


pub fn before<'a, 'b>(tokens: &'b [Token<'a>], index: usize, distance: usize) -> Option<&'b Token<'a>> {
    index.checked_sub(distance).and_then(|position| tokens.get(position))
}


pub fn kind_at(tokens: &[Token], index: usize) -> Option<TokenKind> {
    tokens.get(index).map(|token| token.kind)
}


pub fn is_item_start(tokens: &[Token], index: usize) -> bool {
    before(tokens, index, 1).is_none_or(|previous| {
        matches!(
            previous.kind,
            TokenKind::CloseBrace | TokenKind::Semi | TokenKind::OpenBrace | TokenKind::CloseBracket | TokenKind::CloseParen
        ) || ITEM_PREFIXES.iter().any(|word| is_keyword(previous, word))
    })
}


pub fn closing_index(tokens: &[Token], start: usize, is_end: fn(TokenKind, usize) -> bool) -> usize {
    tokens
        .iter()
        .enumerate()
        .skip(start)
        .scan(0usize, |depth, (index, token)| {
            match token.kind {
                TokenKind::OpenParen | TokenKind::OpenBracket | TokenKind::OpenBrace => *depth += 1,
                TokenKind::CloseParen | TokenKind::CloseBracket | TokenKind::CloseBrace => *depth = depth.saturating_sub(1),
                _ => {}
            }
            Some((index, token.kind, *depth))
        })
        .find(|(_, kind, depth)| is_end(*kind, *depth))
        .map_or(tokens.len(), |(index, _, _)| index)
}

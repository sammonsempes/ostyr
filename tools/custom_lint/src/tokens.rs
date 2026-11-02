use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, TokenKind};


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

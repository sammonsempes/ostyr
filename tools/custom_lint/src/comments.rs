use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, TokenKind};


use crate::model::{Comment, CommentKind};


pub fn classify(kind: TokenKind) -> Option<CommentKind> {
    match kind {
        TokenKind::LineComment { doc_style: None } => Some(CommentKind::Line),
        TokenKind::LineComment { doc_style: Some(_) } => Some(CommentKind::DocLine),
        TokenKind::BlockComment { doc_style: None, .. } => Some(CommentKind::Block),
        TokenKind::BlockComment { doc_style: Some(_), .. } => Some(CommentKind::DocBlock),
        _ => None,
    }
}


pub fn extract_comments(source: &str) -> Vec<Comment> {
    tokenize(source, FrontmatterAllowed::No)
        .scan(0, |offset, token| {
            let start = *offset;
            *offset += token.len as usize;
            Some((start, token))
        })
        .filter_map(|(start, token)| {
            classify(token.kind).and_then(|kind| {
                source.get(start..start + token.len as usize).map(|text| Comment {
                    kind,
                    offset: start,
                    text: text.to_string(),
                })
            })
        })
        .collect()
}

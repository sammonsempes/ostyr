use std::path::Path;


use crate::{
    model::{violation_at, Comment, CommentKind, Context, Violation},
    position::line_column,
};


pub const LINE_COMMENT: &str = "line-comment";


pub const DOC_COMMENT_MULTILINE: &str = "doc-comment-multiline";


const LINE_COMMENT_MESSAGE: &str = "comments are not allowed in src/ or tests/";


const DOC_COMMENT_MESSAGE: &str = "doc comment spans more than one line";


const SAFETY_PREFIX: &str = "// SAFETY:";


const UNSAFE_KEYWORD: &str = "unsafe";


const CHECKED_DIRS: [&str; 2] = ["src", "tests"];


pub fn in_checked_dir(path: &Path) -> bool {
    path.components()
        .any(|component| CHECKED_DIRS.iter().any(|dir| component.as_os_str() == *dir))
}


pub fn is_safety_comment(context: &Context, comment: &Comment) -> bool {
    let (line, _) = line_column(&context.source, comment.offset);
    comment.text.starts_with(SAFETY_PREFIX) && context.source.lines().nth(line).is_some_and(|next| next.contains(UNSAFE_KEYWORD))
}


pub fn line_comment(context: &Context) -> Vec<Violation> {
    if in_checked_dir(&context.path) {
        context
            .comments
            .iter()
            .filter(|comment| matches!(comment.kind, CommentKind::Line | CommentKind::Block))
            .filter(|comment| !is_safety_comment(context, comment))
            .map(|comment| {
                violation_at(
                    context,
                    LINE_COMMENT,
                    line_column(&context.source, comment.offset),
                    LINE_COMMENT_MESSAGE.to_string(),
                )
            })
            .collect()
    } else {
        Vec::new()
    }
}


pub fn starts_group(doc_lines: &[(&Comment, usize)], index: usize, line: usize) -> bool {
    let follows_previous = index
        .checked_sub(1)
        .and_then(|previous| doc_lines.get(previous))
        .is_some_and(|(_, previous_line)| previous_line + 1 == line);
    let precedes_next = doc_lines.get(index + 1).is_some_and(|(_, next_line)| *next_line == line + 1);
    !follows_previous && precedes_next
}


pub fn doc_comment_multiline(context: &Context) -> Vec<Violation> {
    let doc_lines: Vec<(&Comment, usize)> = context
        .comments
        .iter()
        .filter(|comment| comment.kind == CommentKind::DocLine)
        .map(|comment| (comment, line_column(&context.source, comment.offset).0))
        .collect();
    let group_starts = doc_lines
        .iter()
        .enumerate()
        .filter(|(index, (_, line))| starts_group(&doc_lines, *index, *line))
        .map(|(_, (comment, _))| *comment);
    let multiline_blocks = context
        .comments
        .iter()
        .filter(|comment| comment.kind == CommentKind::DocBlock && comment.text.contains('\n'));
    group_starts
        .chain(multiline_blocks)
        .map(|comment| {
            violation_at(
                context,
                DOC_COMMENT_MULTILINE,
                line_column(&context.source, comment.offset),
                DOC_COMMENT_MESSAGE.to_string(),
            )
        })
        .collect()
}

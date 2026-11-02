use crate::{
    model::{violation_at, Comment, CommentKind, Context, Violation},
    position::line_column,
    rules_flow::at_offset,
    rules_recursion::flatten_items,
    tokens::{is_keyword, significant_tokens},
};
use quote::ToTokens;
use ra_ap_rustc_lexer::TokenKind;
use std::path::Path;
use syn::{ImplItem, Item, Signature, Visibility};


pub const UNSAFE_OUTSIDE_BOUNDARY: &str = "unsafe-outside-boundary";


pub const UNSAFE_WITHOUT_SAFETY: &str = "unsafe-without-safety";


const BOUNDARY_CRATES: [&str; 2] = ["sys-windows", "ebpf-probes"];


const SAFETY_PREFIX: &str = "// SAFETY:";


const PAIR_WIDTH: usize = 2;


pub fn in_boundary(path: &Path) -> bool {
    let names: Vec<&std::ffi::OsStr> = path.components().map(|component| component.as_os_str()).collect();
    matches!(names.as_slice(), [first, second, ..] if *first == "crates" && BOUNDARY_CRATES.iter().any(|name| *second == *name))
}


pub fn unsafe_outside_boundary(context: &Context) -> Vec<Violation> {
    if in_boundary(&context.path) {
        Vec::new()
    } else {
        significant_tokens(&context.source)
            .iter()
            .filter(|token| is_keyword(token, "unsafe"))
            .map(|token| {
                at_offset(
                    context,
                    UNSAFE_OUTSIDE_BOUNDARY,
                    token.offset,
                    "`unsafe` is only allowed in the boundary crates".to_string(),
                )
            })
            .collect()
    }
}


pub fn is_filled_safety(comment: &Comment) -> bool {
    comment.kind == CommentKind::Line && comment.text.strip_prefix(SAFETY_PREFIX).is_some_and(|rest| !rest.trim().is_empty())
}


pub fn has_safety_comment(context: &Context, unsafe_offset: usize) -> bool {
    let unsafe_line = line_column(&context.source, unsafe_offset).0;
    context
        .comments
        .iter()
        .any(|comment| is_filled_safety(comment) && line_column(&context.source, comment.offset).0 + 1 == unsafe_line)
}


pub fn undocumented_blocks(context: &Context) -> Vec<Violation> {
    significant_tokens(&context.source)
        .windows(PAIR_WIDTH)
        .filter(|window| matches!(window, [first, second] if is_keyword(first, "unsafe") && second.kind == TokenKind::OpenBrace))
        .filter_map(|window| window.first())
        .filter(|token| !has_safety_comment(context, token.offset))
        .map(|token| {
            at_offset(
                context,
                UNSAFE_WITHOUT_SAFETY,
                token.offset,
                "`unsafe` block needs a `// SAFETY: <reason>` comment on the line above".to_string(),
            )
        })
        .collect()
}


pub fn public_signatures(context: &Context) -> Vec<&Signature> {
    flatten_items(&context.file.items)
        .into_iter()
        .flat_map(|item| match item {
            Item::Fn(function) if matches!(function.vis, Visibility::Public(_)) => vec![&function.sig],
            Item::Impl(implementation) => implementation
                .items
                .iter()
                .filter_map(|member| match member {
                    ImplItem::Fn(method) if matches!(method.vis, Visibility::Public(_)) => Some(&method.sig),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}


pub fn has_raw_pointer(signature: &Signature) -> bool {
    significant_tokens(&signature.to_token_stream().to_string())
        .windows(PAIR_WIDTH)
        .any(|window| matches!(window, [star, qualifier] if star.kind == TokenKind::Star && matches!(qualifier.text, "const" | "mut")))
}


pub fn signature_violations(context: &Context, signature: &Signature) -> Vec<Violation> {
    let start = signature.ident.span().start();
    let position = (start.line, start.column + 1);
    let unsafe_fn = signature.unsafety.is_some().then(|| {
        violation_at(
            context,
            UNSAFE_WITHOUT_SAFETY,
            position,
            format!("`pub unsafe fn {}` is not allowed in the public API", signature.ident),
        )
    });
    let pointer = has_raw_pointer(signature).then(|| {
        violation_at(
            context,
            UNSAFE_WITHOUT_SAFETY,
            position,
            format!("`pub fn {}` exposes a raw pointer", signature.ident),
        )
    });
    unsafe_fn.into_iter().chain(pointer).collect()
}


pub fn unsafe_without_safety(context: &Context) -> Vec<Violation> {
    if in_boundary(&context.path) {
        let signatures = public_signatures(context)
            .into_iter()
            .flat_map(|signature| signature_violations(context, signature));
        undocumented_blocks(context).into_iter().chain(signatures).collect()
    } else {
        Vec::new()
    }
}

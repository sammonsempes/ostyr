use custom_lint::scan::lint_source;
use std::path::Path;


const SRC_PATH: &str = "crates/x/src/lib.rs";


const LINE_COMMENT_MESSAGE: &str = "line-comment: comments are not allowed in src/ or tests/";


const DOC_MESSAGE: &str = "doc-comment-multiline: doc comment spans more than one line";


fn report(path: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(path), source)?
        .iter()
        .filter(|violation| violation.rule.ends_with("comment") || violation.rule.ends_with("multiline"))
        .map(ToString::to_string)
        .collect())
}


#[test]
pub fn clean_source_passes() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "fn main() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn line_comment_is_reported_with_position() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {\n    // hi\n}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:2:5: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn block_comment_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {\n    /* hi */\n}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:2:5: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn column_counts_characters() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {\n    let _s = \"é\"; /* c */\n}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:2:19: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn slashes_in_a_string_are_not_a_comment() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "fn a() -> &'static str {\n    \"http://x\"\n}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn comments_outside_src_and_tests_are_ignored() -> anyhow::Result<()> {
    assert!(report("crates/x/build.rs", "fn a() {\n    // hi\n}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn comments_in_tests_are_reported() -> anyhow::Result<()> {
    let found = report("crates/x/tests/t.rs", "fn a() {\n    // hi\n}\n")?;
    assert_eq!(found, vec![format!("crates/x/tests/t.rs:2:5: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn safety_comment_before_unsafe_is_allowed() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "fn a() {\n    // SAFETY: sound\n    unsafe { b() }\n}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn safety_comment_without_unsafe_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {\n    // SAFETY: sound\n    let x = 1;\n}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:2:5: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn safety_comment_at_end_of_file_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {}\n\n\n// SAFETY: sound")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:4:1: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn plain_comment_before_unsafe_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "fn a() {\n    // other\n    unsafe { b() }\n}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:2:5: {LINE_COMMENT_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn single_line_doc_comment_passes() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "/// one\nfn a() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn two_line_doc_comment_is_reported_once() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "/// one\n/// two\nfn a() {}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:1:1: {DOC_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn three_line_doc_comment_is_reported_once() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "/// one\n/// two\n/// three\nfn a() {}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:1:1: {DOC_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn separate_doc_groups_are_reported_separately() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "/// a\n/// b\nfn a() {}\n\n\n/// c\n/// d\nfn b() {}\n")?;
    assert_eq!(
        found,
        vec![format!("{SRC_PATH}:1:1: {DOC_MESSAGE}"), format!("{SRC_PATH}:6:1: {DOC_MESSAGE}")]
    );
    Ok(())
}


#[test]
pub fn doc_comments_on_distant_lines_pass() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "/// a\nfn a() {}\n\n\n/// b\nfn b() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn inner_doc_comment_over_two_lines_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "//! a\n//! b\nfn a() {}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:1:1: {DOC_MESSAGE}")]);
    Ok(())
}


#[test]
pub fn single_line_block_doc_comment_passes() -> anyhow::Result<()> {
    assert!(report(SRC_PATH, "/** one */\nfn a() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn multiline_block_doc_comment_is_reported() -> anyhow::Result<()> {
    let found = report(SRC_PATH, "/**\n * one\n */\nfn a() {}\n")?;
    assert_eq!(found, vec![format!("{SRC_PATH}:1:1: {DOC_MESSAGE}")]);
    Ok(())
}

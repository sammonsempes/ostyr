use custom_lint::{rules_spacing::ITEM_SPACING, scan::lint_source};
use std::path::Path;


const SRC_PATH: &str = "crates/x/src/lib.rs";


fn report(source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(SRC_PATH), source)?
        .iter()
        .filter(|violation| violation.rule == ITEM_SPACING)
        .map(ToString::to_string)
        .collect())
}


fn expected(position: &str, found: &str) -> String {
    format!("{SRC_PATH}:{position}: item-spacing: expected 2 blank lines between items, found {found}")
}


#[test]
pub fn two_blank_lines_pass() -> anyhow::Result<()> {
    assert!(report("fn a() {}\n\n\nfn b() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn empty_and_single_item_files_pass() -> anyhow::Result<()> {
    assert!(report("")?.is_empty());
    assert!(report("fn a() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn one_blank_line_is_reported() -> anyhow::Result<()> {
    assert_eq!(report("fn a() {}\n\nfn b() {}\n")?, vec![expected("3:1", "1")]);
    Ok(())
}


#[test]
pub fn no_blank_line_is_reported() -> anyhow::Result<()> {
    assert_eq!(report("fn a() {}\nfn b() {}\n")?, vec![expected("2:1", "0")]);
    Ok(())
}


#[test]
pub fn three_blank_lines_are_reported() -> anyhow::Result<()> {
    assert_eq!(report("fn a() {}\n\n\n\nfn b() {}\n")?, vec![expected("5:1", "3")]);
    Ok(())
}


#[test]
pub fn items_on_one_line_are_reported() -> anyhow::Result<()> {
    assert_eq!(report("fn a() {} fn b() {}\n")?, vec![expected("1:11", "0")]);
    Ok(())
}


#[test]
pub fn attributes_belong_to_their_item() -> anyhow::Result<()> {
    assert!(report("fn a() {}\n\n\n#[derive(Debug)]\nstruct B;\n")?.is_empty());
    Ok(())
}


#[test]
pub fn multiline_items_are_measured_from_their_last_line() -> anyhow::Result<()> {
    assert!(report("fn a() {\n}\n\n\nfn b() {}\n")?.is_empty());
    Ok(())
}


fn group_message(position: &str, kind: &str) -> String {
    format!("{SRC_PATH}:{position}: item-spacing: expected no blank line inside a {kind} group")
}


#[test]
pub fn use_group_without_blank_passes() -> anyhow::Result<()> {
    assert!(report("use a::b;\npub use c::d;\n#[cfg(test)]\nuse e::f;\n")?.is_empty());
    Ok(())
}


#[test]
pub fn use_group_with_blank_is_reported() -> anyhow::Result<()> {
    assert_eq!(report("use a::b;\n\nuse c::d;\n")?, vec![group_message("3:1", "use")]);
    Ok(())
}


#[test]
pub fn mod_group_without_blank_passes() -> anyhow::Result<()> {
    assert!(report("mod a;\npub mod b;\n")?.is_empty());
    Ok(())
}


#[test]
pub fn mod_group_with_blank_is_reported() -> anyhow::Result<()> {
    assert_eq!(report("mod a;\n\nmod b;\n")?, vec![group_message("3:1", "mod")]);
    Ok(())
}


#[test]
pub fn inline_modules_are_ordinary_items() -> anyhow::Result<()> {
    assert!(report("mod a {}\n\n\nmod b {}\n")?.is_empty());
    assert!(report("mod a;\n\n\nmod b {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn use_group_then_fn_needs_two_blank_lines() -> anyhow::Result<()> {
    assert!(report("use a::b;\nuse c::d;\n\n\nfn f() {}\n")?.is_empty());
    assert_eq!(report("use a::b;\n\nfn f() {}\n")?, vec![expected("3:1", "1")]);
    Ok(())
}


#[test]
pub fn mod_group_then_use_group_needs_two_blank_lines() -> anyhow::Result<()> {
    assert!(report("mod a;\nmod b;\n\n\nuse c::d;\nuse e::f;\n")?.is_empty());
    assert_eq!(report("mod a;\nuse c::d;\n")?, vec![expected("2:1", "0")]);
    Ok(())
}


#[test]
pub fn comments_are_not_blank_lines() -> anyhow::Result<()> {
    assert!(report("fn a() {}\n\n\n// note\nfn b() {}\n")?.is_empty());
    assert!(report("fn a() {}\n\n// one\n\nfn b() {}\n")?.is_empty());
    assert_eq!(report("fn a() {}\n// note\nfn b() {}\n")?, vec![expected("3:1", "0")]);
    assert!(report("use a::b;\n// note\nuse c::d;\n")?.is_empty());
    Ok(())
}

use std::path::Path;


use custom_lint::scan::lint_source;


const SRC_PATH: &str = "crates/x/src/lib.rs";


fn report(source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(SRC_PATH), source)?.iter().map(ToString::to_string).collect())
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

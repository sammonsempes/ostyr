use custom_lint::scan::lint_source;
use std::path::Path;


const RULE: &str = "bool-array";


const MESSAGE: &str = "a boolean array literal evaluates every operand and hides branches from the coverage gate; use `||` or `&&`";


fn report(source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new("crates/x/src/lib.rs"), source)?
        .iter()
        .filter(|violation| violation.rule == RULE)
        .map(ToString::to_string)
        .collect())
}


fn expected(position: &str) -> String {
    format!("crates/x/src/lib.rs:{position}: {RULE}: {MESSAGE}")
}


#[test]
pub fn contains_true_on_a_literal_is_reported() -> anyhow::Result<()> {
    let source = "fn a(x: bool, y: bool) -> bool {\n    [x, y].contains(&true)\n}\n";
    assert_eq!(report(source)?, vec![expected("2:10")]);
    Ok(())
}


#[test]
pub fn contains_false_on_a_multi_line_literal_is_reported() -> anyhow::Result<()> {
    let source = "fn a(x: bool, y: bool) -> bool {\n    [\n        x,\n        y,\n    ]\n    .contains(&false)\n}\n";
    assert_eq!(report(source)?, vec![expected("5:5")]);
    Ok(())
}


#[test]
pub fn any_identity_on_a_literal_is_reported() -> anyhow::Result<()> {
    let source = "fn a(x: bool, y: bool) -> bool {\n    [x, y].iter().any(|flag| *flag)\n}\n";
    assert_eq!(report(source)?, vec![expected("2:10")]);
    Ok(())
}


#[test]
pub fn vec_macro_literal_is_reported() -> anyhow::Result<()> {
    let source = "fn a(x: bool) -> bool {\n    vec![x].contains(&true)\n}\n";
    assert_eq!(report(source)?, vec![expected("2:11")]);
    Ok(())
}


#[test]
pub fn variables_and_indexing_are_not_reported() -> anyhow::Result<()> {
    let source = "fn a(v: Vec<bool>) -> bool {\n    v.contains(&true)\n}\n\
fn b(g: [Vec<bool>; 2]) -> bool {\n    g[0].contains(&true)\n}\n\
fn c(f: fn() -> [bool; 1]) -> bool {\n    f().contains(&false)\n}\n\
fn d(v: Vec<bool>) -> bool {\n    v.iter().any(|flag| *flag)\n}\n";
    assert!(report(source)?.is_empty());
    Ok(())
}


#[test]
pub fn a_nested_literal_finds_its_own_opening_bracket() -> anyhow::Result<()> {
    let source = "fn a(x: bool) -> bool {\n    [[x], [x]].contains(&true)\n}\n";
    assert_eq!(report(source)?, vec![expected("2:14")]);
    Ok(())
}


#[test]
pub fn other_calls_on_a_literal_are_not_reported() -> anyhow::Result<()> {
    let source = "fn a(x: bool) -> bool {\n    [x].contains(&x) || [x].iter().any(|flag| !*flag) || [x].iter().any(|flag| *x)\n}\n\
fn b(x: bool) -> bool {\n    [x].iter().all(|flag| *flag) || [x].contains(&true.clone()) || [x].iter().any(|flag| *flag && x)\n}\n\
fn c(x: bool) -> bool {\n    [x].iter().any(|&flag| *flag) || [x].iter().any(|flag: bool| *flag)\n}\n";
    assert!(report(source)?.is_empty());
    Ok(())
}

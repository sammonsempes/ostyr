use custom_lint::scan::lint_source;
use std::path::Path;


const SRC_PATH: &str = "crates/x/src/lib.rs";


fn report_at(path: &str, rule: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(path), source)?
        .iter()
        .filter(|violation| violation.rule == rule)
        .map(|violation| format!("{}:{}", violation.line, violation.column))
        .collect())
}


fn report(rule: &str, source: &str) -> anyhow::Result<Vec<String>> {
    report_at(SRC_PATH, rule, source)
}


#[test]
pub fn inherent_impl_is_reported() -> anyhow::Result<()> {
    assert!(report(
        "inherent-impl",
        "struct A;\n\n\nimpl Default for A {\n    fn default() -> Self {\n        A\n    }\n}\n"
    )?
    .is_empty());
    assert_eq!(report("inherent-impl", "struct A;\n\n\nimpl A {\n    fn go(&self) {}\n}\n")?, vec!["4:1"]);
    assert_eq!(
        report("inherent-impl", "struct A<X>(X);\n\n\nimpl<X: Fn() -> u8> A<X> where X: Copy {}\n")?,
        vec!["4:1"]
    );
    assert_eq!(
        report("inherent-impl", "mod m {\n    pub struct A;\n    unsafe impl A {}\n}\n")?,
        vec!["3:12"]
    );
    Ok(())
}


#[test]
pub fn impl_in_type_position_is_not_an_item() -> anyhow::Result<()> {
    let source = "fn a(x: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {\n    x\n}\n\n\nfn b() -> Box<impl Copy> {\n    Box::new(1)\n}\n";
    assert!(report("inherent-impl", source)?.is_empty());
    assert!(report("impl-allowlist", source)?.is_empty());
    Ok(())
}


#[test]
pub fn impl_allowlist_accepts_standard_traits_and_rejects_others() -> anyhow::Result<()> {
    let allowed = "struct A;\n\n\nimpl std::fmt::Display for A {\n    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {\n        Ok(())\n    }\n}\n\n\nimpl<T: Copy> From<T> for A {\n    fn from(_value: T) -> Self {\n        A\n    }\n}\n\n\nimpl std::io::Write for A {}\n";
    assert!(report("impl-allowlist", allowed)?.is_empty());
    assert_eq!(report("impl-allowlist", "struct A;\n\n\nimpl Iterator for A {}\n")?, vec!["4:1"]);
    assert_eq!(
        report("impl-allowlist", "struct A;\n\n\nimpl<T> Clone for A where T: Copy {}\n")?,
        vec!["4:1"]
    );
    assert!(report("inherent-impl", "struct A;\n\n\nimpl Iterator for A {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn custom_traits_are_reported() -> anyhow::Result<()> {
    assert!(report("custom-trait", "fn a(x: &dyn std::fmt::Debug) {}\n")?.is_empty());
    assert_eq!(report("custom-trait", "pub trait Shape {\n    fn area(&self) -> u8;\n}\n")?, vec!["1:5"]);
    Ok(())
}


#[test]
pub fn any_is_reported_in_every_form() -> anyhow::Result<()> {
    assert!(report("any-type", "fn a() { let any = 1; let _x = any; }\n")?.is_empty());
    assert_eq!(report("any-type", "use std::any::Any;\n")?, vec!["1:15"]);
    assert_eq!(report("any-type", "fn a(x: Box<dyn Any>) {}\n")?, vec!["1:17"]);
    assert_eq!(report("any-type", "fn a(x: &dyn std::any::Any) {}\n")?, vec!["1:24"]);
    Ok(())
}


#[test]
pub fn type_alias_is_allowed_only_in_types_rs() -> anyhow::Result<()> {
    assert!(report_at("crates/x/src/types.rs", "type-alias-location", "pub type A = u8;\n")?.is_empty());
    assert_eq!(report("type-alias-location", "pub type A = u8;\n")?, vec!["1:1"]);
    assert_eq!(report("type-alias-location", "mod m {\n    type B = u8;\n}\n")?, vec!["2:5"]);
    assert!(report("type-alias-location", "struct A;\n\n\nimpl Iterator for A {\n    type Item = u8;\n}\n")?.is_empty());
    Ok(())
}

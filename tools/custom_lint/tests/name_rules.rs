use custom_lint::scan::lint_source;
use std::path::Path;


const SRC_PATH: &str = "crates/x/src/lib.rs";


fn report(rule: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(SRC_PATH), source)?
        .iter()
        .filter(|violation| violation.rule == rule)
        .map(|violation| format!("{}:{}", violation.line, violation.column))
        .collect())
}


#[test]
pub fn forbidden_idents_are_reported() -> anyhow::Result<()> {
    assert!(report("forbidden-ident", "fn go() { for i in 0..1 { let j = i; let _k = j; } let _ = 1; }\n")?.is_empty());
    assert!(report("forbidden-ident", "fn go<'a>(r#x: &'a str) -> &'a str { r#x }\n")?.is_empty());
    assert_eq!(
        report("forbidden-ident", "fn go() {\n    let l = 1;\n    let O = l;\n    let _I = O;\n}\n")?,
        vec!["2:9", "3:9", "3:13", "4:14"]
    );
    assert_eq!(report("forbidden-ident", "fn go<T>() {}\n")?, vec!["1:7"]);
    Ok(())
}


#[test]
pub fn magic_numbers_are_reported() -> anyhow::Result<()> {
    assert!(report("magic-number", "const MAX: u32 = 3;\n\n\nstatic NAMES: [&str; 4] = [\"a\"; 4];\n")?.is_empty());
    assert!(report("magic-number", "fn a() -> u8 {\n    let x = 0;\n    let y = 1u8;\n    x + y\n}\n")?.is_empty());
    assert!(report("magic-number", "const A: [u8; 2] = { let x = [0; 2]; x };\n")?.is_empty());
    assert!(report(
        "magic-number",
        "#[derive(Debug)]\n#[cfg(any(a = \"b\", feature = \"c\"))]\nstruct A;\n#[allow(x = 7)]\nfn go() {}\n"
    )?
    .is_empty());
    assert!(report("magic-number", "#[doc = 5]\nstruct A;\n")?.is_empty());
    assert!(report("magic-number", "#![doc = 5]\nstruct A;\n")?.is_empty());
    assert_eq!(
        report("magic-number", "macro_rules! mac {\n    () => { # 7 };\n    (a) => { #! 8 };\n}\n")?,
        vec!["2:15", "3:17"]
    );
    assert!(report("magic-number", "fn a(t: ((u8, u8), u8)) -> u8 {\n    t.0.1 + t.1\n}\n")?.is_empty());
    assert!(report("magic-number", "struct A { x: [u8; 3] }\n\n\nimpl A {\n    const N: usize = 5;\n}\n")?.len() == 1);
    assert_eq!(report("magic-number", "fn a() {\n    sleep(3);\n}\n")?, vec!["2:11"]);
    assert_eq!(
        report("magic-number", "fn a() {\n    let _x = 0.5 + 1e3;\n    let _y = 0xff;\n}\n")?,
        vec!["2:14", "2:20", "3:14"]
    );
    assert_eq!(report("magic-number", "fn a() {\n    for _n in 1..3 {}\n}\n")?, vec!["2:18"]);
    assert_eq!(
        report("magic-number", "fn a() {\n    let _x = 2;\n    const Z: u8 = 9;\n    let _y = 4;\n}\n")?,
        vec!["2:14", "4:14"]
    );
    assert_eq!(
        report(
            "magic-number",
            "fn a<const N: usize>() {\n    const unsafe fn b() {}\n    let _x = 8;\n}\n"
        )?,
        vec!["3:14"]
    );
    assert_eq!(report("magic-number", "fn go() {\n    const { 5 };\n}\n")?, vec!["2:13"]);
    assert_eq!(report("magic-number", "pub const fn a() -> u8 {\n    6\n}\n")?, vec!["2:5"]);
    assert_eq!(report("magic-number", "#[a]\nfn a() {\n    let _x = 7;\n}\n")?, vec!["3:14"]);
    assert_eq!(
        report("magic-number", "const X: u8 = 1;\n\n\nstatic mut Y: u8 = 2;\nfn a() -> u8 {\n    9\n}\n")?,
        vec!["6:5"]
    );
    Ok(())
}


#[test]
pub fn global_mutable_state_is_reported() -> anyhow::Result<()> {
    assert!(report(
        "global-mutable",
        "static A: u8 = 1;\n\n\nstatic B: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();\n"
    )?
    .is_empty());
    assert!(report(
        "global-mutable",
        "static C: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {\n    let mut v = Vec::new();\n    v.push(1);\n    v\n});\n"
    )?
    .is_empty());
    assert!(report("global-mutable", "fn a<'a>(x: &'static str, y: &'a str) {}\n")?.is_empty());
    assert!(report("global-mutable", "thread_local! {\n    static T: u8 = 1;\n}\n")?.is_empty());
    assert!(report("global-mutable", "fn a() {\n    thread_local!(static T: u8 = 1);\n}\n")?.is_empty());
    assert!(report("global-mutable", "fn a() { thread_local; let _x = 1; }\n")?.is_empty());
    assert_eq!(report("global-mutable", "static mut A: u8 = 1;\n")?, vec!["1:1"]);
    assert_eq!(
        report("global-mutable", "static B: std::sync::Mutex<u8> = std::sync::Mutex::new(1);\n")?,
        vec!["1:1"]
    );
    assert_eq!(
        report("global-mutable", "static C: std::sync::RwLock<u8> = std::sync::RwLock::new(1);\n")?,
        vec!["1:1"]
    );
    assert_eq!(
        report(
            "global-mutable",
            "static D: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);\n"
        )?,
        vec!["1:1"]
    );
    assert_eq!(
        report("global-mutable", "static E: std::cell::Cell<u8> = x();\nstatic F: RefCell<u8> = y();\n")?,
        vec!["1:1", "2:1"]
    );
    assert_eq!(
        report("global-mutable", "thread_local! {\n    static G: RefCell<u8> = x();\n}\n")?,
        vec!["1:1"]
    );
    assert_eq!(report("global-mutable", "thread_local!(static H: Cell<u8> = x());\n")?, vec!["1:1"]);
    assert_eq!(report("global-mutable", "fn a() {\n    static J: Mutex<u8> = x();\n}\n")?, vec!["2:5"]);
    Ok(())
}

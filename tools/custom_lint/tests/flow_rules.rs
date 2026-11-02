use custom_lint::scan::lint_source;
use std::path::Path;


const SRC_PATH: &str = "crates/x/src/lib.rs";


fn report(rule: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(SRC_PATH), source)?
        .iter()
        .filter(|violation| violation.rule == rule)
        .map(ToString::to_string)
        .collect())
}


fn line(position: &str, rule: &str, message: &str) -> String {
    format!("{SRC_PATH}:{position}: {rule}: {message}")
}


#[test]
pub fn return_is_reported_early_trailing_and_in_closures() -> anyhow::Result<()> {
    assert!(report("return", "fn a() -> u8 {\n    1\n}\n")?.is_empty());
    assert!(report("return", "fn a() -> u8 {\n    let r#return = 1;\n    r#return\n}\n")?.is_empty());
    assert!(report("return", "fn a() -> &'static str {\n    \"return\"\n}\n")?.is_empty());
    let expected = vec![line("2:5", "return", "`return` is not allowed")];
    assert_eq!(report("return", "fn a() -> u8 {\n    return 1;\n}\n")?, expected);
    let closure = vec![line("2:23", "return", "`return` is not allowed")];
    assert_eq!(report("return", "fn a() {\n    let f = |x: u8| { return x; };\n}\n")?, closure);
    Ok(())
}


#[test]
pub fn break_and_continue_are_reported() -> anyhow::Result<()> {
    assert!(report("break-continue", "fn a() {}\n")?.is_empty());
    let source = "fn a() {\n    for i in 0..3 {\n        if i == 1 { continue; }\n        break;\n    }\n}\n";
    assert_eq!(
        report("break-continue", source)?,
        vec![
            line("3:21", "break-continue", "`continue` is not allowed"),
            line("4:9", "break-continue", "`break` is not allowed")
        ]
    );
    Ok(())
}


#[test]
pub fn bare_loops_are_reported() -> anyhow::Result<()> {
    assert!(report("bare-loop", "fn a() { for i in 0..2 { let _x = i; } }\n")?.is_empty());
    assert!(report("bare-loop", "fn a() { let b = true; let c = b; if c {} }\n")?.is_empty());
    assert_eq!(
        report("bare-loop", "fn a() {\n    loop {}\n}\n")?,
        vec![line("2:5", "bare-loop", "`loop` is not allowed")]
    );
    assert_eq!(
        report("bare-loop", "fn a() {\n    while true {}\n}\n")?,
        vec![line("2:5", "bare-loop", "`while true` is not allowed")]
    );
    assert!(report("uncapped-while", "fn a() {\n    while true {}\n}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn process_exit_is_reported() -> anyhow::Result<()> {
    assert!(report("process-exit", "fn a() { let _p = std::process::id(); }\n")?.is_empty());
    assert!(report("process-exit", "fn a() { process.exit(); }\n")?.is_empty());
    assert!(report("process-exit", "fn a() { process::Exit; }\n")?.is_empty());
    assert!(report("process-exit", "fn a(process: u8, exit: u8) {}\n")?.is_empty());
    let expected = vec![line("1:15", "process-exit", "`process::exit` is not allowed")];
    assert_eq!(report("process-exit", "fn a() { std::process::exit(1); }\n")?, expected);
    let short = vec![line("1:10", "process-exit", "`process::exit` is not allowed")];
    assert_eq!(report("process-exit", "fn a() { process::exit(1); }\n")?, short);
    Ok(())
}


#[test]
pub fn uncapped_while_heuristic() -> anyhow::Result<()> {
    let capped = "fn a() { let mut n = 0; while n < MAX_ATTEMPTS { n += 1; } }\n";
    assert!(report("uncapped-while", capped)?.is_empty());
    let compound = "fn a() { let d = false; let mut n = 0; while !d && n != LIMIT { n += 1; } }\n";
    assert!(report("uncapped-while", compound)?.is_empty());
    let numbered = "fn a() { let mut n = 0; while n < LIMIT_2 { n += 1; } }\n";
    assert!(report("uncapped-while", numbered)?.is_empty());
    let equal = "fn a() { let mut n = 0; while n == LIMIT { n += 1; } }\n";
    assert!(report("uncapped-while", equal)?.is_empty());
    let message = "`while` condition does not compare a counter against a const";
    let no_const = "fn a() { let mut n = 0; while n < 3 { n += 1; } }\n";
    assert_eq!(report("uncapped-while", no_const)?, vec![line("1:25", "uncapped-while", message)]);
    let no_comparison = "fn a() { let n = 0; while MAX_ATTEMPTS { } }\n";
    assert_eq!(report("uncapped-while", no_comparison)?, vec![line("1:21", "uncapped-while", message)]);
    let lower = "fn a() { let n = 0; while n < max { } }\n";
    assert_eq!(report("uncapped-while", lower)?, vec![line("1:21", "uncapped-while", message)]);
    let mixed = "fn a() { let n = 0; while Max_1 != n { } }\n";
    assert_eq!(report("uncapped-while", mixed)?, vec![line("1:21", "uncapped-while", message)]);
    let while_let = "fn a(mut it: std::vec::IntoIter<u8>) { while let Some(x) = it.next() { drop(x); } }\n";
    assert_eq!(report("uncapped-while", while_let)?, vec![line("1:40", "uncapped-while", message)]);
    Ok(())
}


#[test]
pub fn loop_nesting_allows_three_levels() -> anyhow::Result<()> {
    let three = "fn a() { for i in 0..2 { for j in 0..2 { for k in 0..2 { let _s = i + j + k; } } } }\n";
    assert!(report("loop-nesting", three)?.is_empty());
    let sequential = "fn a() { for i in 0..2 { drop(i); } for i in 0..2 { drop(i); } for i in 0..2 { drop(i); } for i in 0..2 { drop(i); } }\n";
    assert!(report("loop-nesting", sequential)?.is_empty());
    let closures = "fn a() { for i in 0..2 { (0..2).for_each(|j| (0..2).for_each(|k| drop(i + j + k))); } }\n";
    assert!(report("loop-nesting", closures)?.is_empty());
    Ok(())
}


#[test]
pub fn loop_nesting_reports_the_fourth_level() -> anyhow::Result<()> {
    let four = "fn a() {\n    for i in 0..2 { for j in 0..2 { for k in 0..2 { for l in 0..2 { drop((i, j, k, l)); } } } }\n}\n";
    assert_eq!(
        report("loop-nesting", four)?,
        vec![line("2:53", "loop-nesting", "loops are nested more than 3 levels deep")]
    );
    let mixed = "fn a() {\n    for i in 0..2 { while i < MAX_N { loop { for j in 0..2 { drop(j); } } } }\n}\n";
    assert_eq!(report("loop-nesting", mixed)?.len(), 1);
    Ok(())
}


#[test]
pub fn for_in_impl_headers_and_binders_is_not_a_loop() -> anyhow::Result<()> {
    let impls = "struct S;\nimpl Clone for S {\n    fn clone(&self) -> S { S }\n}\nfn a<F>(f: F) where F: for<'x> Fn(&'x u8) {}\n";
    assert!(report("loop-nesting", impls)?.is_empty());
    let nested_impls = "struct S;\nimpl Clone for S { fn clone(&self) -> S { S } }\nimpl Copy for S {}\nimpl S { fn f(self) { for i in 0..2 { for j in 0..2 { for k in 0..2 { for l in 0..2 { drop((i, j, k, l)); } } } } } }\n";
    assert_eq!(report("loop-nesting", nested_impls)?.len(), 1);
    Ok(())
}


#[test]
pub fn unbalanced_closers_do_not_underflow() -> anyhow::Result<()> {
    assert!(report("loop-nesting", "fn a() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn direct_recursion_is_reported() -> anyhow::Result<()> {
    let source = "fn a(n: u8) -> u8 {\n    a(n)\n}\n";
    assert_eq!(report("recursion", source)?, vec![line("1:4", "recursion", "function `a` is recursive")]);
    Ok(())
}


#[test]
pub fn mutual_recursion_is_reported_for_both() -> anyhow::Result<()> {
    let source = "fn a() { b() }\nfn b() { c() }\nfn c() { a() }\nfn d() { a() }\n";
    assert_eq!(
        report("recursion", source)?,
        vec![
            line("1:4", "recursion", "function `a` is recursive"),
            line("2:4", "recursion", "function `b` is recursive"),
            line("3:4", "recursion", "function `c` is recursive")
        ]
    );
    Ok(())
}


#[test]
pub fn recursion_through_a_use_alias_is_reported() -> anyhow::Result<()> {
    let source = "use self::a as g;\nfn a() { g() }\n";
    assert_eq!(report("recursion", source)?, vec![line("2:4", "recursion", "function `a` is recursive")]);
    Ok(())
}


#[test]
pub fn recursion_inside_inline_modules_is_reported() -> anyhow::Result<()> {
    let source = "mod inner {\n    pub fn a() { a() }\n}\nmod outside;\n";
    assert_eq!(report("recursion", source)?, vec![line("2:12", "recursion", "function `a` is recursive")]);
    Ok(())
}


#[test]
pub fn non_recursive_calls_pass() -> anyhow::Result<()> {
    let source = "use std::fmt::Debug as Dbg;\nuse std::vec as v;\nstruct S;\nimpl S {\n    fn a(&self) {}\n}\nfn a(s: S) { s.a(); b(); }\nfn b() { fn a() {} let _r = c(); let _o = other(); }\nfn c() -> u8 { 1 }\n";
    assert!(report("recursion", source)?.is_empty());
    Ok(())
}

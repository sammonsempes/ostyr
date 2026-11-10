use custom_lint::scan::lint_source;
use std::path::Path;


const RULE: &str = "undeclared-audit";


const SRC_PATH: &str = "crates/core-api/src/lib.rs";


const MESSAGE: &str = "`core_audit::log::append` is only for core-audit; use `append_declared`";


fn report_at(path: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(path), source)?
        .iter()
        .filter(|violation| violation.rule == RULE)
        .map(ToString::to_string)
        .collect())
}


fn expected(path: &str, position: &str) -> String {
    format!("{path}:{position}: {RULE}: {MESSAGE}")
}


#[test]
pub fn full_path_call_is_reported() -> anyhow::Result<()> {
    let source = "fn a() {\n    core_audit::log::append(1);\n}\n";
    assert_eq!(report_at(SRC_PATH, source)?, vec![expected(SRC_PATH, "2:22")]);
    Ok(())
}


#[test]
pub fn call_through_the_log_module_is_reported() -> anyhow::Result<()> {
    let source = "use core_audit::log;\nfn a() {\n    log::append(1);\n}\n";
    assert_eq!(report_at(SRC_PATH, source)?, vec![expected(SRC_PATH, "3:10")]);
    Ok(())
}


#[test]
pub fn plain_import_is_reported() -> anyhow::Result<()> {
    let source = "use core_audit::log::append;\n";
    assert_eq!(report_at(SRC_PATH, source)?, vec![expected(SRC_PATH, "1:22")]);
    Ok(())
}


#[test]
pub fn grouped_import_is_reported() -> anyhow::Result<()> {
    let source = "use core_audit::log::{append, AuditLog};\nuse core_audit::log::{self, append_declared};\n";
    assert_eq!(report_at(SRC_PATH, source)?, vec![expected(SRC_PATH, "1:23")]);
    Ok(())
}


#[test]
pub fn declared_and_sample_variants_are_not_reported() -> anyhow::Result<()> {
    let source = "use core_audit::log::{append_declared, append_samples};\nfn a() {\n    log::append_declared(1);\n    log::append_samples(1);\n}\n";
    assert!(report_at(SRC_PATH, source)?.is_empty());
    Ok(())
}


#[test]
pub fn core_audit_itself_examples_and_tests_are_not_checked() -> anyhow::Result<()> {
    let source = "use core_audit::log::append;\n";
    assert!(report_at("crates/core-audit/src/lib.rs", source)?.is_empty());
    assert!(report_at("crates/core-api/examples/run.rs", source)?.is_empty());
    assert!(report_at("crates/core-api/tests/it.rs", source)?.is_empty());
    assert!(report_at("lib.rs", source)?.is_empty());
    assert!(report_at("other/x/src/lib.rs", source)?.is_empty());
    Ok(())
}

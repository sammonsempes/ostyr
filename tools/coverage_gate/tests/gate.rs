use coverage_gate::check::{check, Violation};
use coverage_gate::error::GateError;
use coverage_gate::executable::has_executable_code;
use coverage_gate::export::parse_export;
use coverage_gate::run::run;
use coverage_gate::scan::find_sources;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;


const TWO_SHORTFALLS: usize = 2;


const BRANCHES_COVERED: u64 = 3;


const BRANCHES_TOTAL: u64 = 4;


const LINES_COVERED: u64 = 8;


const LINES_TOTAL: u64 = 10;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const COVERED: &str = include_str!("fixtures/covered.json");


const BRANCH_MISSED: &str = include_str!("fixtures/branch_missed.json");


const LINE_MISSED: &str = include_str!("fixtures/line_missed.json");


const ZERO_BRANCHES: &str = include_str!("fixtures/zero_branches.json");


const ABSENT: &str = include_str!("fixtures/absent.json");


const LOCKED_MODE: u32 = 0o000;


const OPEN_MODE: u32 = 0o755;


struct FailingReader;


impl io::Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("unreadable"))
    }
}


struct FailingWriter;


impl io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("unwritable"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn touch(root: &Path, relative: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, "")?;
    Ok(())
}


fn workspace() -> Result<(TempDir, PathBuf), anyhow::Error> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    touch(&root, "crates/demo/src/lib.rs")?;
    fs::write(root.join("crates/demo/src/lib.rs"), "pub fn demo() {}")?;
    touch(&root, "crates/demo/src/types.rs")?;
    fs::write(
        root.join("crates/demo/src/types.rs"),
        "//! doc\nuse std::fmt;\npub mod a;\n#[derive(Debug)]\npub struct T;\n",
    )?;
    touch(&root, "crates/demo/src/notes.txt")?;
    touch(&root, "crates/demo/build.rs")?;
    touch(&root, "target/debug/src/generated.rs")?;
    touch(&root, ".hidden/src/hidden.rs")?;
    fs::create_dir_all(root.join("crates/demo/src/empty"))?;
    Ok((dir, root))
}


fn write_export(root: &Path, template: &str) -> Result<PathBuf, anyhow::Error> {
    let path = root.join("export.json");
    fs::write(&path, template.replace("{ROOT}", &root.display().to_string()))?;
    Ok(path)
}


fn args(export: &Path, root: &Path) -> Vec<String> {
    vec!["coverage_gate".to_string(), export.display().to_string(), root.display().to_string()]
}


fn run_report(template: &str) -> Result<(bool, String, PathBuf), anyhow::Error> {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, template)?;
    let mut out = Vec::new();
    let passed = run(&args(&export, &root), &mut out)?;
    Ok((passed, String::from_utf8(out)?, root))
}


#[test]
fn all_covered_passes() -> anyhow::Result<()> {
    let (passed, report, _root) = run_report(COVERED)?;
    assert!(passed);
    assert!(report.is_empty());
    Ok(())
}


#[test]
fn zero_branches_passes() -> anyhow::Result<()> {
    let (passed, _report, _root) = run_report(ZERO_BRANCHES)?;
    assert!(passed);
    Ok(())
}


#[test]
fn missed_branch_fails_with_counts() -> anyhow::Result<()> {
    let (passed, report, _root) = run_report(BRANCH_MISSED)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: branches 3/4"));
    Ok(())
}


#[test]
fn missed_line_fails_with_counts() -> anyhow::Result<()> {
    let (passed, report, _root) = run_report(LINE_MISSED)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: lines 9/10"));
    Ok(())
}


#[test]
fn absent_file_fails() -> anyhow::Result<()> {
    let (passed, report, _root) = run_report(ABSENT)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: absent from the coverage export"));
    assert!(!report.contains("generated.rs"));
    assert!(!report.contains("hidden.rs"));
    assert!(!report.contains("build.rs"));
    Ok(())
}


#[test]
fn both_shortfalls_are_listed() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let both = BRANCH_MISSED.replace("\"covered\":10", "\"covered\":8");
    let export = write_export(&root, &both)?;
    let parsed = parse_export(fs::File::open(&export)?)?;
    let violations = check(&parsed, &find_sources(&root)?)?;
    assert_eq!(violations.len(), TWO_SHORTFALLS);
    assert!(matches!(
        violations.first(),
        Some(Violation::Branches {
            covered: BRANCHES_COVERED,
            total: BRANCHES_TOTAL,
            ..
        })
    ));
    assert!(matches!(
        violations.get(1),
        Some(Violation::Lines {
            covered: LINES_COVERED,
            total: LINES_TOTAL,
            ..
        })
    ));
    Ok(())
}


#[test]
fn malformed_json_is_a_parse_error() -> anyhow::Result<()> {
    assert!(matches!(parse_export("{not json".as_bytes()), Err(GateError::Parse(_))));
    Ok(())
}


#[test]
fn unreadable_input_is_a_read_error() -> anyhow::Result<()> {
    assert!(matches!(parse_export(FailingReader), Err(GateError::Read(_))));
    Ok(())
}


#[test]
fn missing_arguments_is_a_usage_error() -> anyhow::Result<()> {
    let result = run(&["coverage_gate".to_string()], Vec::new());
    assert!(matches!(result, Err(GateError::Usage)));
    Ok(())
}


#[test]
fn missing_export_is_an_open_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let result = run(&args(&root.join("nope.json"), &root), Vec::new());
    assert!(matches!(result, Err(GateError::Open { .. })));
    Ok(())
}


#[test]
fn missing_root_is_a_resolve_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, COVERED)?;
    let result = run(&args(&export, &root.join("nope")), Vec::new());
    assert!(matches!(result, Err(GateError::Resolve { .. })));
    Ok(())
}


#[test]
fn unwritable_report_is_a_write_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, LINE_MISSED)?;
    let result = run(&args(&export, &root), FailingWriter);
    assert!(matches!(result, Err(GateError::Write(_))));
    Ok(())
}


#[test]
fn unwalkable_directory_is_a_walk_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let locked = root.join("crates/locked");
    fs::create_dir_all(&locked)?;
    fs::set_permissions(&locked, fs::Permissions::from_mode(LOCKED_MODE))?;
    let result = find_sources(&root);
    fs::set_permissions(&locked, fs::Permissions::from_mode(OPEN_MODE))?;
    assert!(matches!(result, Err(GateError::Walk(_))));
    Ok(())
}


#[test]
fn errors_keep_their_cause() -> anyhow::Result<()> {
    let error = GateError::Read(io::Error::other("cause"));
    assert_eq!(error.to_string(), "cannot read the coverage export");
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn default_root_is_the_current_directory() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, COVERED)?;
    let arguments = vec!["coverage_gate".to_string(), export.display().to_string()];
    let passed = run(&arguments, Vec::new());
    assert!(passed.is_ok());
    Ok(())
}


#[test]
fn binary_exit_codes() -> anyhow::Result<()> {
    let binary = env!("CARGO_BIN_EXE_coverage_gate");
    let (_dir, root) = workspace()?;
    let passing = write_export(&root, COVERED)?;
    let pass = Command::new(binary).arg(&passing).arg(&root).output()?;
    assert!(pass.status.success());
    let failing = write_export(&root, BRANCH_MISSED)?;
    let fail = Command::new(binary).arg(&failing).arg(&root).output()?;
    assert_eq!(fail.status.code(), Some(1));
    assert!(String::from_utf8(fail.stdout)?.contains("branches 3/4"));
    let usage = Command::new(binary).output()?;
    assert!(!usage.status.success());
    assert!(String::from_utf8(usage.stderr)?.contains("usage"));
    Ok(())
}


#[test]
fn absent_file_without_code_passes() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    fs::remove_file(root.join("crates/demo/src/lib.rs"))?;
    let export = write_export(&root, ABSENT)?;
    assert!(run(&args(&export, &root), Vec::new())?);
    Ok(())
}


#[test]
fn absent_unreadable_source_is_an_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    fs::write(root.join("crates/demo/src/lib.rs"), INVALID_UTF8)?;
    let export = write_export(&root, ABSENT)?;
    assert!(matches!(run(&args(&export, &root), Vec::new()), Err(GateError::ReadSource { .. })));
    Ok(())
}


#[test]
fn absent_unparsable_source_is_an_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    fs::write(root.join("crates/demo/src/lib.rs"), "fn (")?;
    let export = write_export(&root, ABSENT)?;
    let error = run(&args(&export, &root), Vec::new());
    assert!(matches!(&error, Err(GateError::ParseSource { .. })));
    assert!(error.err().ok_or_else(|| anyhow::anyhow!("no error"))?.source().is_some());
    Ok(())
}


#[test]
fn executable_code_detection() -> anyhow::Result<()> {
    let code = [
        "fn a() {}",
        "struct S; impl S { fn m(&self) {} }",
        "trait T { fn d() {} }",
        "mod m { pub mod n { fn deep() {} } }",
        "const C: fn() = || {};",
        "static S: fn() = || {};",
    ];
    for text in code {
        assert!(has_executable_code(text)?, "{text}");
    }
    let plain = [
        "",
        "use std::fmt;",
        "struct S; impl S { const X: u8 = 1; }",
        "trait T { fn d(); }",
        "mod m;",
        "mod m { struct S; }",
        "const C: u8 = 1;",
        "static S: u8 = 1;",
        "type A = fn(u8);",
    ];
    for text in plain {
        assert!(!has_executable_code(text)?, "{text}");
    }
    Ok(())
}

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use coverage_gate::check::{check, Violation};
use coverage_gate::error::GateError;
use coverage_gate::export::parse_export;
use coverage_gate::run::run;
use coverage_gate::scan::find_sources;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

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

fn touch(root: &Path, relative: &str) -> TestResult {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(path, "")?;
    Ok(())
}

fn workspace() -> Result<(TempDir, PathBuf), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    touch(&root, "crates/demo/src/lib.rs")?;
    touch(&root, "crates/demo/src/notes.txt")?;
    touch(&root, "crates/demo/build.rs")?;
    touch(&root, "target/debug/src/generated.rs")?;
    touch(&root, ".hidden/src/hidden.rs")?;
    fs::create_dir_all(root.join("crates/demo/src/empty"))?;
    Ok((dir, root))
}

fn write_export(root: &Path, template: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = root.join("export.json");
    fs::write(&path, template.replace("{ROOT}", &root.display().to_string()))?;
    Ok(path)
}

fn args(export: &Path, root: &Path) -> Vec<String> {
    vec!["coverage_gate".to_string(), export.display().to_string(), root.display().to_string()]
}

fn run_report(template: &str) -> Result<(bool, String, PathBuf), Box<dyn Error>> {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, template)?;
    let mut out = Vec::new();
    let passed = run(&args(&export, &root), &mut out)?;
    Ok((passed, String::from_utf8(out)?, root))
}

#[test]
fn all_covered_passes() -> TestResult {
    let (passed, report, _root) = run_report(COVERED)?;
    assert!(passed);
    assert!(report.is_empty());
    Ok(())
}

#[test]
fn zero_branches_passes() -> TestResult {
    let (passed, _report, _root) = run_report(ZERO_BRANCHES)?;
    assert!(passed);
    Ok(())
}

#[test]
fn missed_branch_fails_with_counts() -> TestResult {
    let (passed, report, _root) = run_report(BRANCH_MISSED)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: branches 3/4"));
    Ok(())
}

#[test]
fn missed_line_fails_with_counts() -> TestResult {
    let (passed, report, _root) = run_report(LINE_MISSED)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: lines 9/10"));
    Ok(())
}

#[test]
fn absent_file_fails() -> TestResult {
    let (passed, report, _root) = run_report(ABSENT)?;
    assert!(!passed);
    assert!(report.contains("crates/demo/src/lib.rs: absent from the coverage export"));
    assert!(!report.contains("generated.rs"));
    assert!(!report.contains("hidden.rs"));
    assert!(!report.contains("build.rs"));
    Ok(())
}

#[test]
fn both_shortfalls_are_listed() -> TestResult {
    let (_dir, root) = workspace()?;
    let both = BRANCH_MISSED.replace("\"covered\":10", "\"covered\":8");
    let export = write_export(&root, &both)?;
    let parsed = parse_export(fs::File::open(&export)?)?;
    let violations = check(&parsed, &find_sources(&root)?);
    assert_eq!(violations.len(), 2);
    assert!(matches!(violations.first(), Some(Violation::Branches { covered: 3, total: 4, .. })));
    assert!(matches!(violations.get(1), Some(Violation::Lines { covered: 8, total: 10, .. })));
    Ok(())
}

#[test]
fn malformed_json_is_a_parse_error() {
    assert!(matches!(parse_export("{not json".as_bytes()), Err(GateError::Parse(_))));
}

#[test]
fn unreadable_input_is_a_read_error() {
    assert!(matches!(parse_export(FailingReader), Err(GateError::Read(_))));
}

#[test]
fn missing_arguments_is_a_usage_error() {
    let result = run(&["coverage_gate".to_string()], Vec::new());
    assert!(matches!(result, Err(GateError::Usage)));
}

#[test]
fn missing_export_is_an_open_error() -> TestResult {
    let (_dir, root) = workspace()?;
    let result = run(&args(&root.join("nope.json"), &root), Vec::new());
    assert!(matches!(result, Err(GateError::Open { .. })));
    Ok(())
}

#[test]
fn missing_root_is_a_resolve_error() -> TestResult {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, COVERED)?;
    let result = run(&args(&export, &root.join("nope")), Vec::new());
    assert!(matches!(result, Err(GateError::Resolve { .. })));
    Ok(())
}

#[test]
fn unwritable_report_is_a_write_error() -> TestResult {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, LINE_MISSED)?;
    let result = run(&args(&export, &root), FailingWriter);
    assert!(matches!(result, Err(GateError::Write(_))));
    Ok(())
}

#[test]
fn unwalkable_directory_is_a_walk_error() -> TestResult {
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
fn errors_keep_their_cause() -> TestResult {
    let error = GateError::Read(io::Error::other("cause"));
    assert_eq!(error.to_string(), "cannot read the coverage export");
    assert!(error.source().is_some());
    Ok(())
}

#[test]
fn default_root_is_the_current_directory() -> TestResult {
    let (_dir, root) = workspace()?;
    let export = write_export(&root, COVERED)?;
    let arguments = vec!["coverage_gate".to_string(), export.display().to_string()];
    let passed = run(&arguments, Vec::new());
    assert!(passed.is_ok());
    Ok(())
}

#[test]
fn binary_exit_codes() -> TestResult {
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

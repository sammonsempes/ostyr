#[path = "common/types.rs"]
mod types;


use core_config::apply_cli::{apply_to_dir, read_state, run, write_plan, ApplyCliError};
use core_config::plan::{change_of, ChangeKind};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use types::TestResult;


const INVALID_UTF8: &[u8] = &[u8::MAX, u8::MAX - 1];


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn output_of(args: &[&str]) -> Result<String, ApplyCliError> {
    let mut out = Vec::new();
    run(args, &mut out).map(|()| String::from_utf8_lossy(&out).into_owned())
}


fn text(path: &Path) -> String {
    path.display().to_string()
}


#[test]
fn plan_apply_read_back_and_drift_on_a_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let desired = root.path().join("desired");
    let state = root.path().join("state");
    fs::create_dir_all(desired.join("sub"))?;
    fs::create_dir_all(&state)?;
    fs::write(desired.join("a.yaml"), "x: 1\n")?;
    fs::write(state.join("old.yaml"), "gone\n")?;
    let audit = text(&root.path().join("audit.log"));
    let (desired_arg, state_arg) = (text(&desired), text(&state));
    assert!(output_of(&["plan", &desired_arg, &state_arg])?.contains("Create a.yaml"));
    assert_eq!(
        output_of(&["apply", &desired_arg, &state_arg, &audit, "alice", "ticket 1"])?,
        "applied 2\n"
    );
    assert_eq!(fs::read_to_string(state.join("a.yaml"))?, "x: 1\n");
    assert!(!state.join("old.yaml").exists());
    assert!(output_of(&["plan", &desired_arg, &state_arg])?.is_empty());
    assert_eq!(output_of(&["drift", &desired_arg, &state_arg])?, "");
    let log = fs::read_to_string(&audit)?;
    assert!(log.contains("alice") && log.contains("ticket 1") && log.contains("config.delete"));
    fs::write(state.join("a.yaml"), "x: 2\n")?;
    let drifted = output_of(&["drift", &desired_arg, &state_arg]);
    assert!(matches!(drifted, Err(ApplyCliError::Drift { count: 1 })));
    assert!(drifted.err().map(|error| error.to_string()).ok_or("no error")?.contains("1 change"));
    Ok(())
}


#[test]
fn errors_are_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let missing = text(&root.path().join("missing"));
    let dir = text(root.path());
    assert!(matches!(output_of(&[]), Err(ApplyCliError::Usage)));
    assert!(matches!(output_of(&["plan", &missing, &dir]), Err(ApplyCliError::Io(_))));
    assert!(matches!(output_of(&["drift", &dir, &missing]), Err(ApplyCliError::Io(_))));
    let bad_audit = text(&root.path().join("no-dir").join("audit.log"));
    assert!(matches!(
        output_of(&["apply", &dir, &dir, &bad_audit, "a", "j"]),
        Err(ApplyCliError::Audit(_))
    ));
    Ok(())
}


#[test]
fn apply_failure_is_an_apply_error() -> TestResult {
    let root = tempfile::tempdir()?;
    let desired = root.path().join("desired");
    let state = root.path().join("state");
    fs::create_dir_all(&desired)?;
    fs::create_dir_all(state.join("a"))?;
    fs::write(desired.join("a"), "1")?;
    let audit = text(&root.path().join("audit.log"));
    let outcome = output_of(&["apply", &text(&desired), &text(&state), &audit, "a", "j"]);
    assert!(matches!(outcome, Err(ApplyCliError::Apply(_))));
    Ok(())
}


#[test]
fn helpers_and_output_failures() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("f"), INVALID_UTF8)?;
    assert!(read_state(root.path()).is_err());
    assert!(apply_to_dir(root.path(), &change_of(ChangeKind::Delete, "nothing", "x", "")).is_err());
    let changes = vec![change_of(ChangeKind::Create, "k", "", "v\n")];
    assert!(write_plan(&changes, &mut FailingWriter).is_err());
    let desired = root.path().join("d");
    fs::create_dir_all(&desired)?;
    fs::write(desired.join("k"), "v")?;
    let empty = root.path().join("e");
    fs::create_dir_all(&empty)?;
    let mut sink = FailingWriter;
    assert!(matches!(
        run(&["plan", &text(&desired), &text(&empty)], &mut sink),
        Err(ApplyCliError::Io(_))
    ));
    assert!(matches!(
        run(&["drift", &text(&desired), &text(&empty)], &mut sink),
        Err(ApplyCliError::Io(_))
    ));
    let audit = text(&root.path().join("audit.log"));
    assert!(matches!(
        run(&["apply", &text(&empty), &text(&empty), &audit, "a", "j"], &mut sink),
        Err(ApplyCliError::Io(_))
    ));
    Ok(())
}


#[test]
fn example_binary_reports_errors_with_a_failure_code() -> TestResult {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let failure = Command::new(&cargo)
        .args(["run", "--offline", "-q", "-p", "core-config", "--example", "config_apply"])
        .output()?;
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("usage:"));
    let root = tempfile::tempdir()?;
    let dir = text(root.path());
    let success = Command::new(&cargo)
        .args([
            "run",
            "--offline",
            "-q",
            "-p",
            "core-config",
            "--example",
            "config_apply",
            "--",
            "plan",
            &dir,
            &dir,
        ])
        .output()?;
    assert!(success.status.success());
    Ok(())
}

#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/types.rs"]
mod types;


use core_audit::cli::{append_samples, parse_count, run, sample_entry};
use core_audit::error::AuditError;
use core_audit::log::genesis_log;
use failing_writer::FailingWriter;
use std::fs;
use std::process::Command;
use types::TestResult;


const SAMPLE_COUNT: usize = 5;


fn output_of(args: &[&str]) -> Result<String, AuditError> {
    let mut out = Vec::new();
    run(args, &mut out).map(|()| String::from_utf8_lossy(&out).into_owned())
}


#[test]
fn append_verify_and_export_round_trip() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log").display().to_string();
    let appended = output_of(&["append", &path, "5"])?;
    let head = appended.trim().strip_prefix("head ").ok_or("no head")?.to_owned();
    assert_eq!(output_of(&["verify", &path])?, format!("ok {SAMPLE_COUNT} records head {head}\n"));
    assert!(output_of(&["verify", &path, &head])?.starts_with("ok 5 records"));
    assert!(matches!(output_of(&["verify", &path, "abc"]), Err(AuditError::HeadMismatch { .. })));
    assert_eq!(output_of(&["export", &path])?.lines().count(), SAMPLE_COUNT);
    assert_eq!(output_of(&["export", &path, &head])?.lines().count(), SAMPLE_COUNT);
    assert!(matches!(output_of(&["export", &path, "abc"]), Err(AuditError::HeadMismatch { .. })));
    assert!(!fs::read_to_string(&path)?.contains("hunter2"));
    Ok(())
}


#[test]
fn bad_arguments_and_files_are_errors() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing.log").display().to_string();
    assert!(matches!(output_of(&[]), Err(AuditError::Usage)));
    assert!(matches!(output_of(&["append", &missing, "many"]), Err(AuditError::InvalidCount { .. })));
    assert!(matches!(output_of(&["verify", &missing]), Err(AuditError::Io(_))));
    assert!(matches!(output_of(&["export", &missing]), Err(AuditError::Io(_))));
    assert!(parse_count("many")
        .err()
        .map(|error| error.to_string())
        .ok_or("no error")?
        .contains("many"));
    Ok(())
}


#[test]
fn output_failures_are_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log").display().to_string();
    let mut sink = FailingWriter {
        fail_write: true,
        fail_flush: false,
    };
    assert!(matches!(run(&["append", &path, "1"], &mut sink), Err(AuditError::Io(_))));
    assert!(matches!(run(&["verify", &path], &mut sink), Err(AuditError::Io(_))));
    let failing = genesis_log(sink);
    assert!(append_samples(&failing, 1).is_err());
    assert_eq!(sample_entry(1).target, "setting-1");
    Ok(())
}


#[test]
fn example_binary_reports_errors_with_a_failure_code() -> TestResult {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let failure = Command::new(&cargo)
        .args(["run", "--offline", "-q", "-p", "core-audit", "--example", "audit_tool"])
        .output()?;
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("usage:"));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log").display().to_string();
    let success = Command::new(&cargo)
        .args([
            "run",
            "--offline",
            "-q",
            "-p",
            "core-audit",
            "--example",
            "audit_tool",
            "--",
            "append",
            &path,
            "2",
        ])
        .output()?;
    assert!(success.status.success());
    Ok(())
}

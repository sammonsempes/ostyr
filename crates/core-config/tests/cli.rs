mod common;


use common::fixture;
use common::types::TestResult;
use core_config::cli::{run, run_reporting, CliError, USAGE};
use std::error::Error;
use std::io::{self, Write};
use std::process::{Command, ExitCode};


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


const EXPECTED_SCHEMA_FILES: usize = 2;


const COMMAND_COUNT: usize = 4;


fn output_of(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let mut out = Vec::new();
    run(args, &mut out)?;
    Ok(String::from_utf8(out)?)
}


fn path_text(name: &str) -> String {
    fixture(name).display().to_string()
}


#[test]
fn check_commands_report_ok() -> TestResult {
    let platform = path_text("platform_ok.yaml");
    let module = path_text("module_ok.yaml");
    let base = path_text("base/module.yaml");
    let tenant = path_text("tenant/module.yaml");
    assert_eq!(output_of(&["check", "platform", &platform])?, format!("ok {platform}\n"));
    assert_eq!(output_of(&["check", "module", &module])?, format!("ok {module}\n"));
    assert_eq!(output_of(&["check", "tenant", &base, &tenant])?, format!("ok {tenant}\n"));
    Ok(())
}


#[test]
fn schema_command_lists_files() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().display().to_string();
    let output = output_of(&["schema", &target])?;
    assert_eq!(output.lines().count(), EXPECTED_SCHEMA_FILES);
    Ok(())
}


#[test]
fn invalid_files_report_config_errors() -> TestResult {
    let bad = path_text("module_unknown_field.yaml");
    let error = output_of(&["check", "module", &bad]).err().ok_or("no error")?;
    assert!(error.to_string().contains(":3:1: at `.`: unknown field"));
    Ok(())
}


#[test]
fn every_command_reports_config_failures() -> TestResult {
    let absent = path_text("absent.yaml");
    let base = path_text("base/module.yaml");
    let dir = tempfile::tempdir()?;
    let blocker = dir.path().join("file");
    std::fs::write(&blocker, "x")?;
    let blocked = blocker.join("sub").display().to_string();
    let commands: [&[&str]; COMMAND_COUNT] = [
        &["check", "platform", &absent],
        &["check", "module", &absent],
        &["check", "tenant", &base, &absent],
        &["schema", &blocked],
    ];
    assert!(commands.iter().all(|args| matches!(run(args, &mut Vec::new()), Err(CliError::Config(_)))));
    Ok(())
}


#[test]
fn unknown_command_prints_usage() -> TestResult {
    let error = output_of(&["bogus"]).err().ok_or("no error")?;
    assert_eq!(error.to_string(), USAGE);
    Ok(())
}


#[test]
fn output_failure_is_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().display().to_string();
    let platform = path_text("platform_ok.yaml");
    let module = path_text("module_ok.yaml");
    let base = path_text("base/module.yaml");
    let tenant = path_text("tenant/module.yaml");
    let commands: [&[&str]; COMMAND_COUNT] = [
        &["check", "platform", &platform],
        &["check", "module", &module],
        &["check", "tenant", &base, &tenant],
        &["schema", &target],
    ];
    assert!(commands
        .iter()
        .all(|args| matches!(run(args, &mut FailingWriter), Err(CliError::Output(_)))));
    Ok(())
}


#[test]
fn run_reporting_writes_display_to_err_and_fails() -> TestResult {
    let bad = path_text("module_unknown_field.yaml");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_reporting(&["check", "module", &bad], &mut out, &mut err)?;
    let text = String::from_utf8(err)?;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(out.is_empty());
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains(":3:1: at `.`: unknown field") && !text.contains("Parse {"), "{text}");
    Ok(())
}


#[test]
fn run_reporting_succeeds_on_valid_file() -> TestResult {
    let module = path_text("module_ok.yaml");
    let code = run_reporting(&["check", "module", &module], &mut Vec::new(), &mut Vec::new())?;
    assert_eq!(code, ExitCode::SUCCESS);
    Ok(())
}


#[test]
fn run_reporting_propagates_stderr_failure() -> TestResult {
    let result = run_reporting(&["bogus"], &mut Vec::new(), &mut FailingWriter);
    assert!(result.is_err());
    Ok(())
}


#[test]
fn example_binary_prints_display_and_exits_non_zero() -> TestResult {
    let bad = path_text("module_unknown_field.yaml");
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "-p",
            "core-config",
            "--example",
            "config_tool",
            "--",
            "check",
            "module",
            &bad,
        ])
        .output()?;
    let text = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(text.contains(":3:1: at `.`: unknown field") && !text.contains("Parse {"), "{text}");
    Ok(())
}

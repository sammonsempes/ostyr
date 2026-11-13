mod common;


use common::types::TestResult;
use core_config::error::ConfigError;
use remote_shell::cli::{run_cli, MAX_CASE_BYTES};
use remote_shell::error::CliError;
use std::io::{self, Write};


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected failure"))
    }
}


const POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/policy.yaml");


fn example(name: &str) -> String {
    format!("{}/examples/requests/{name}.json", env!("CARGO_MANIFEST_DIR"))
}


fn run(args: &[&str]) -> Result<String, CliError> {
    let arguments: Vec<String> = args.iter().map(|argument| argument.to_string()).collect();
    let mut out = Vec::new();
    run_cli(&arguments, &mut out).map(|()| String::from_utf8_lossy(&out).into_owned())
}


fn run_example(name: &str) -> Result<String, CliError> {
    run(&[POLICY, &example(name)])
}


#[test]
fn the_committed_examples_give_the_documented_decisions() -> TestResult {
    let medium = run_example("allowed-medium")?;
    assert!(medium.starts_with("Allowed { idle_timeout: 600, max_duration: 7200, approved_by: [] }"));
    assert!(run_example("refused-no-mfa")?.starts_with("Refused(MfaMissing)"));
    assert!(run_example("refused-self-approval")?.starts_with("Refused(ApprovalRequired)"));
    let critical = run_example("allowed-critical-approved")?;
    assert!(critical.starts_with("Allowed {") && critical.contains("approved_by: [\"bob\"]"));
    assert!(run_example("refused-unknown-asset")?.starts_with("Refused(ApprovalRequired)"));
    Ok(())
}


#[test]
fn the_output_carries_the_audit_fields() -> TestResult {
    let shown = run_example("refused-no-mfa")?;
    assert!(shown.contains("request_id: \"req-refused-no-mfa\""));
    assert!(shown.contains("refusal: Some(\"mfa_missing\")"));
    Ok(())
}


#[test]
fn a_wrong_argument_count_prints_the_usage() -> TestResult {
    assert!(matches!(run(&[]), Err(CliError::Usage)));
    assert!(matches!(run(&[POLICY]), Err(CliError::Usage)));
    assert!(matches!(run(&[POLICY, POLICY, POLICY]), Err(CliError::Usage)));
    Ok(())
}


#[test]
fn a_missing_policy_or_case_file_is_reported() -> TestResult {
    let missing = example("nothing-here");
    assert!(matches!(run(&[&missing, &missing]), Err(CliError::Policy(_))));
    assert!(matches!(run(&[POLICY, &missing]), Err(CliError::Config(ConfigError::Io { .. }))));
    Ok(())
}


#[test]
fn an_oversized_or_malformed_case_is_refused() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let big = directory.path().join("big.json");
    std::fs::write(&big, vec![b' '; usize::try_from(MAX_CASE_BYTES)? + 1])?;
    let bad = directory.path().join("bad.json");
    std::fs::write(&bad, "{}")?;
    let big_path = big.display().to_string();
    let bad_path = bad.display().to_string();
    assert!(matches!(run(&[POLICY, &big_path]), Err(CliError::Config(ConfigError::TooLarge { .. }))));
    assert!(matches!(run(&[POLICY, &bad_path]), Err(CliError::Case { .. })));
    Ok(())
}


#[test]
fn a_failing_writer_is_reported() -> TestResult {
    let arguments = [POLICY.to_string(), example("allowed-medium")];
    assert!(matches!(run_cli(&arguments, &mut FailingWriter), Err(CliError::Write(_))));
    Ok(())
}

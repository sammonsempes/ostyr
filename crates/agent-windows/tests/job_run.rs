#![cfg(windows)]

#[path = "common/types.rs"]
mod types;


use agent_windows::error::RunError;
use agent_windows::job_run::exit_code;
use agent_windows::model::{RunEnd, RunRequest};
use agent_windows::run::run_process;
use types::TestResult;


const CMD: &str = r"C:\Windows\System32\cmd.exe";


const BIG: usize = 1_000_000;


const SMALL: usize = 64;


const GENEROUS: u64 = 60;


const SHORT: u64 = 2;


const EXIT_THREE: i32 = 3;


const SIGNED_CODE: u32 = 0x8A15_000B;


const PAIRS: [(&str, &str); 2] = [("PATH", r"C:\Windows\System32"), ("SystemRoot", r"C:\Windows")];


fn run(args: &[&str], max_bytes: usize, deadline: u64) -> Result<(RunEnd, Vec<u8>), RunError> {
    let owned: Vec<String> = args.iter().map(|argument| (*argument).to_owned()).collect();
    let mut received = Vec::new();
    let end = run_process(
        &RunRequest {
            program: CMD,
            args: &owned,
            max_bytes,
            deadline_seconds: deadline,
            environment: Some(&PAIRS),
        },
        &mut |chunk| received.extend_from_slice(chunk),
    )?;
    Ok((end, received))
}


#[test]
fn the_child_sees_exactly_the_given_environment() -> TestResult {
    let (end, received) = run(&["/c", "set"], BIG, GENEROUS)?;
    let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
    assert_eq!(end, RunEnd::Done);
    assert!(text.contains(r"systemroot=c:\windows"));
    assert!(std::env::var("CARGO_MANIFEST_DIR").is_ok() && !text.contains("cargo_"));
    Ok(())
}


#[test]
fn a_non_zero_exit_code_is_reported_as_signed() -> TestResult {
    let (end, _) = run(&["/c", "exit 3"], BIG, GENEROUS)?;
    assert_eq!(end, RunEnd::Failed(Some(EXIT_THREE)));
    assert_eq!(exit_code(SIGNED_CODE), i32::from_ne_bytes(SIGNED_CODE.to_ne_bytes()));
    assert!(exit_code(SIGNED_CODE) < 0);
    Ok(())
}


#[test]
fn output_over_the_cap_ends_the_job_and_is_named() -> TestResult {
    let (end, received) = run(
        &["/c", "for /l %i in (1,1,1000000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
        SMALL,
        GENEROUS,
    )?;
    assert_eq!(end, RunEnd::Capped);
    assert!(received.len() <= SMALL);
    Ok(())
}


#[test]
fn a_silent_child_ends_at_the_deadline() -> TestResult {
    let (end, _) = run(&["/c", "for /l %i in (1,1,2000000000) do @rem"], BIG, SHORT)?;
    assert_eq!(end, RunEnd::Deadline);
    Ok(())
}


#[test]
fn a_program_that_cannot_start_is_a_job_error() -> TestResult {
    let mut received = Vec::new();
    let outcome = run_process(
        &RunRequest {
            program: r"C:\Windows\System32\absent-program.exe",
            args: &[],
            max_bytes: BIG,
            deadline_seconds: SHORT,
            environment: Some(&PAIRS),
        },
        &mut |chunk| received.extend_from_slice(chunk),
    );
    assert!(matches!(outcome, Err(RunError::Job(_))));
    Ok(())
}

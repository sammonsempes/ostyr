#[path = "common/types.rs"]
mod types;


use dhcp_kea::cli::{counts_line, follow_file, no_pause, one_shot, parse_args, report, run, COUNTS_EVERY_POLLS, POLL_INTERVAL};
use dhcp_kea::error::KeaError;
use dhcp_kea::follow::Counts;
use std::fs::{create_dir, write};
use std::process::ExitCode;
use tempfile::tempdir;
use types::TestResult;


const CSV: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n\
10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,\n\
10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,\n\
bad,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,\n";


const TWO_POLLS: u64 = 2;


const TWO_LINES: usize = 2;


fn code(value: ExitCode) -> String {
    format!("{value:?}")
}


#[test]
fn arguments_are_a_path_with_an_optional_follow_flag() -> TestResult {
    assert!(matches!(parse_args(&["a.csv"]), Ok((_, false))));
    assert!(matches!(parse_args(&["a.csv", "--follow"]), Ok((_, true))));
    assert!(matches!(parse_args(&[]), Err(KeaError::Usage)));
    assert!(matches!(parse_args(&["a.csv", "--other"]), Err(KeaError::Usage)));
    Ok(())
}


#[test]
fn a_run_writes_ecs_lines_and_reports_the_counts() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, CSV)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run(&[path.to_str().ok_or("path")?], &mut out, &mut err, TWO_POLLS, no_pause)?;
    assert_eq!(code(status), code(ExitCode::SUCCESS));
    let text = String::from_utf8(out)?;
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("\"mac\":\"AA-BB-CC-DD-EE-01\""));
    assert_eq!(
        String::from_utf8(err)?,
        "processed=1 duplicate=1 evicted=0 restarts=0 absent=0 refused=0 malformed=address=1\n"
    );
    Ok(())
}


#[test]
fn a_follow_run_polls_the_bounded_number_of_times() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, CSV)?;
    let mut out = Vec::new();
    let mut counts_out = Vec::new();
    let counts = follow_file(&path, TWO_POLLS, &mut out, &mut counts_out, no_pause)?;
    assert!(counts_out.is_empty());
    assert_eq!((counts.processed, counts.duplicate), (1, 1));
    let mut err = Vec::new();
    let status = run(&[path.to_str().ok_or("path")?, "--follow"], &mut out, &mut err, TWO_POLLS, no_pause)?;
    assert_eq!(code(status), code(ExitCode::SUCCESS));
    no_pause(POLL_INTERVAL);
    Ok(())
}


#[test]
fn an_error_is_reported_with_a_failure_status() -> TestResult {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run(&[], &mut out, &mut err, 1, no_pause)?;
    assert_eq!(code(status), code(ExitCode::FAILURE));
    assert!(String::from_utf8(err)?.starts_with("usage:"));
    Ok(())
}


#[test]
fn a_failing_output_is_an_error() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, CSV)?;
    let mut sink: &mut [u8] = &mut [];
    let mut counts_out = Vec::new();
    let result = follow_file(&path, 1, &mut sink, &mut counts_out, no_pause);
    assert!(matches!(result, Err(KeaError::Io(_))));
    let mut failing_err: &mut [u8] = &mut [];
    assert!(report(Ok(Counts::default()), &mut failing_err).is_err());
    assert!(report(Err(KeaError::Usage), &mut failing_err).is_err());
    Ok(())
}


#[test]
fn the_counts_are_written_every_fixed_number_of_polls() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, CSV)?;
    let mut out = Vec::new();
    let mut counts_out = Vec::new();
    let counts = follow_file(&path, COUNTS_EVERY_POLLS * TWO_POLLS, &mut out, &mut counts_out, no_pause)?;
    let text = String::from_utf8(counts_out)?;
    assert_eq!(text.lines().count(), TWO_LINES);
    assert!(text.lines().all(|line| line == counts_line(&counts)));
    let mut failing: &mut [u8] = &mut [];
    assert!(follow_file(&path, COUNTS_EVERY_POLLS, &mut out, &mut failing, no_pause).is_err());
    Ok(())
}


#[test]
fn a_follow_counts_a_refused_path_and_keeps_going_while_a_one_shot_fails() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    create_dir(&path)?;
    let mut out = Vec::new();
    let mut counts_out = Vec::new();
    let counts = follow_file(&path, TWO_POLLS, &mut out, &mut counts_out, no_pause)?;
    assert_eq!(counts.refused, TWO_POLLS);
    assert!(matches!(one_shot(&path, &mut out, &mut counts_out), Err(KeaError::NotRegular)));
    let mut err = Vec::new();
    let one_shot_status = run(&[path.to_str().ok_or("path")?], &mut out, &mut err, 1, no_pause)?;
    assert_eq!(code(one_shot_status), code(ExitCode::FAILURE));
    let follow_status = run(&[path.to_str().ok_or("path")?, "--follow"], &mut out, &mut err, TWO_POLLS, no_pause)?;
    assert_eq!(code(follow_status), code(ExitCode::SUCCESS));
    Ok(())
}

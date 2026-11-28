#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use agent_windows::error::RunError;
use agent_windows::model::{Drained, RunEnd, RunRequest, WORKING_DIRECTORY};
use agent_windows::run::{drain, finish, forward, pump, run_process};
use std::io::{self, ErrorKind, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc::sync_channel;
use std::sync::LazyLock;
use types::TestResult;


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(io::sink).finish()).is_ok());


const HEAD: &str = "/usr/bin/head";


const PWD: &str = "/bin/pwd";


const SLEEP: &str = "/bin/sleep";


const ZERO: &str = "/dev/zero";


const SMALL: usize = 10;


const BIG: usize = 1_000_000;


const GENEROUS: u64 = 60;


const DEPTH: usize = 4;


const HUGE_FACTOR: usize = 4;


const CAP_BYTES: usize = 6;


const CHUNK_PAIR: usize = 2;


const CHUNK_TRIPLE: usize = 3;


pub struct Scripted {
    pub steps: Vec<io::Result<usize>>,
}


impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.steps.pop() {
            Some(Ok(count)) => {
                buffer.iter_mut().take(count).for_each(|byte| *byte = b'x');
                Ok(count.min(buffer.len()))
            }
            Some(Err(error)) => Err(error),
            None => Ok(0),
        }
    }
}


fn request<'a>(program: &'a str, args: &'a [String], max_bytes: usize, deadline: u64) -> RunRequest<'a> {
    RunRequest {
        program,
        args,
        max_bytes,
        deadline_seconds: deadline,
        environment: None,
    }
}


fn head_args(bytes: usize, file: &str) -> Vec<String> {
    vec!["-c".to_string(), bytes.to_string(), file.to_string()]
}


fn run(program: &str, args: &[String], max_bytes: usize, deadline: u64) -> Result<(RunEnd, usize), RunError> {
    let mut received = 0usize;
    let end = run_process(&request(program, args, max_bytes, deadline), &mut |chunk| received += chunk.len())?;
    Ok((end, received))
}


#[test]
fn every_child_runs_from_the_fixed_working_directory() -> TestResult {
    let mut received = Vec::new();
    let end = run_process(&request(PWD, &[], BIG, GENEROUS), &mut |chunk| received.extend_from_slice(chunk))?;
    assert_eq!(end, RunEnd::Done);
    assert_eq!(String::from_utf8(received)?.trim(), WORKING_DIRECTORY);
    Ok(())
}


#[test]
fn a_finished_child_within_the_cap_is_done() -> TestResult {
    let (end, received) = run(HEAD, &head_args(SMALL, ZERO), BIG, GENEROUS)?;
    assert_eq!((end, received), (RunEnd::Done, SMALL));
    Ok(())
}


#[test]
fn output_at_the_cap_is_done_and_one_past_it_is_capped() -> TestResult {
    let (at, received) = run(HEAD, &head_args(SMALL, ZERO), SMALL, GENEROUS)?;
    assert_eq!((at, received), (RunEnd::Done, SMALL));
    let (past, kept) = run(HEAD, &head_args(SMALL + 1, ZERO), SMALL, GENEROUS)?;
    assert_eq!(past, RunEnd::Capped);
    assert_eq!(kept, SMALL);
    let (huge, _) = run(HEAD, &head_args(BIG * HUGE_FACTOR, ZERO), SMALL, GENEROUS)?;
    assert_eq!(huge, RunEnd::Capped);
    Ok(())
}


#[test]
fn a_hung_child_past_the_deadline_is_killed_and_named() -> TestResult {
    let (end, received) = run(SLEEP, &["30".to_string()], BIG, 0)?;
    assert_eq!((end, received), (RunEnd::Deadline, 0));
    Ok(())
}


#[test]
fn a_failing_child_reports_its_exit_code() -> TestResult {
    let (end, _) = run(HEAD, &["/nonexistent/ostyr-file".to_string()], BIG, GENEROUS)?;
    assert_eq!(end, RunEnd::Failed(Some(1)));
    Ok(())
}


#[test]
fn a_program_that_does_not_exist_is_a_spawn_error() -> TestResult {
    let outcome = run("/nonexistent/ostyr-program", &[], BIG, GENEROUS);
    assert!(matches!(outcome, Err(RunError::Spawn(_))));
    Ok(())
}


#[test]
fn a_child_killed_by_a_signal_has_no_exit_code() -> TestResult {
    let mut child = Command::new(SLEEP).arg("30").stdin(Stdio::null()).spawn()?;
    child.kill()?;
    child.wait()?;
    assert_eq!(finish(&mut child, Drained::Eof)?, RunEnd::Failed(None));
    assert_eq!(finish(&mut child, Drained::Capped)?, RunEnd::Capped);
    assert_eq!(finish(&mut child, Drained::Deadline)?, RunEnd::Deadline);
    Ok(())
}


#[test]
fn the_pump_stops_on_eof_an_error_and_a_closed_receiver() -> TestResult {
    LazyLock::force(&LOGGING);
    let (sender, receiver) = sync_channel(DEPTH);
    let mut eof = Scripted { steps: vec![] };
    pump(&mut eof, &sender);
    assert!(receiver.try_recv().is_err());
    let mut broken = Scripted {
        steps: vec![
            Err(io::Error::new(ErrorKind::BrokenPipe, "x")),
            Err(io::Error::from(ErrorKind::Interrupted)),
        ],
    };
    pump(&mut broken, &sender);
    assert!(broken.steps.is_empty());
    let mut data = Scripted {
        steps: vec![Ok(CHUNK_TRIPLE), Ok(CHUNK_PAIR), Ok(1)],
    };
    pump(&mut data, &sender);
    let sizes: Vec<usize> = receiver.try_iter().map(|chunk| chunk.len()).collect();
    assert_eq!(sizes, vec![1, CHUNK_PAIR, CHUNK_TRIPLE]);
    drop(receiver);
    let mut orphan = Scripted { steps: vec![Ok(1)] };
    pump(&mut orphan, &sender);
    assert!(orphan.steps.is_empty());
    Ok(())
}


#[test]
fn forward_keeps_only_the_bytes_within_the_cap() -> TestResult {
    let mut total = 0usize;
    let mut kept = Vec::new();
    let first = forward(b"abcd", &mut total, CAP_BYTES, &mut |part| kept.extend_from_slice(part));
    assert!(first.is_none());
    let second = forward(b"efgh", &mut total, CAP_BYTES, &mut |part| kept.extend_from_slice(part));
    assert_eq!(second, Some(Drained::Capped));
    assert_eq!(kept, b"abcdef");
    Ok(())
}


#[test]
fn drain_names_a_deadline_and_a_disconnect() -> TestResult {
    let (sender, receiver) = sync_channel::<Vec<u8>>(DEPTH);
    let none: [String; 0] = [];
    let timed = request("x", &none, BIG, 0);
    assert_eq!(drain(&receiver, &timed, &mut |_| ()), Drained::Deadline);
    drop(sender);
    assert_eq!(drain(&receiver, &timed, &mut |_| ()), Drained::Eof);
    Ok(())
}


const ENV: &str = "/usr/bin/env";


#[test]
fn an_explicit_environment_is_exactly_the_given_pairs() -> TestResult {
    let pairs = [("ONLY", "this")];
    let mut received = Vec::new();
    let end = run_process(
        &RunRequest {
            program: ENV,
            args: &[],
            max_bytes: BIG,
            deadline_seconds: GENEROUS,
            environment: Some(&pairs),
        },
        &mut |chunk| received.extend_from_slice(chunk),
    )?;
    assert_eq!(end, RunEnd::Done);
    assert_eq!(received, b"ONLY=this\n");
    Ok(())
}


#[test]
fn without_an_explicit_environment_the_agent_environment_is_inherited() -> TestResult {
    let mut received = Vec::new();
    run_process(
        &RunRequest {
            program: ENV,
            args: &[],
            max_bytes: BIG,
            deadline_seconds: GENEROUS,
            environment: None,
        },
        &mut |chunk| received.extend_from_slice(chunk),
    )?;
    assert!(received.len() > SMALL);
    Ok(())
}


#[test]
fn a_job_failure_keeps_its_cause() -> TestResult {
    let error = RunError::Job(sys_windows::types::ConsoleError::AlreadyClosed);
    assert_eq!(error.to_string(), "the job run failed");
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}

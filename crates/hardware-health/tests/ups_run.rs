#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use hardware_health::model::{BlindReason, FailureClass, Health, RunOutput, UpsFailure, UpsSettings};
use hardware_health::smart_run::run_smartctl;
use hardware_health::ups_run::{run_ups, run_ups_with, ups_failure_health, ups_failure_of, UPSC_PROGRAM};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use types::TestResult;


const OL: &str = include_str!("fixtures/lab-ups-OL.txt");


const SHORT: u64 = 5;


const LONG: u64 = 30;


const ROUND: u64 = 10;


const SLOW: &str = "6";


const COUNT_TWO: usize = 2;


const COUNT_THREE: usize = 3;


const INDEX_FOUR: usize = 4;


const INDEX_FIVE: usize = 5;


const INDEX_SIX: usize = 6;


const INDEX_SEVEN: usize = 7;


const MARKER: &str = "STDERR-MARKER-5C1D";


fn scratch() -> Result<tempfile::TempDir, io::Error> {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
}


fn read_or_empty(path: &Path) -> Result<String, io::Error> {
    fs::read_to_string(path).or_else(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Ok(String::new())
        } else {
            Err(error)
        }
    })
}


fn seconds(text: &str) -> Result<u64, FailureClass> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Ok(0)
    } else {
        trimmed.parse().map_err(|error| {
            tracing::debug!(%error, "bad clock fixture");
            FailureClass::Io
        })
    }
}


static BASE: OnceLock<Instant> = OnceLock::new();


fn clock_seconds(program: &Path) -> Result<u64, FailureClass> {
    let dir = program.parent().ok_or(FailureClass::Io)?;
    seconds(&read_or_empty(&dir.join("clock"))?)
}


fn fake_clock(program: &Path) -> Instant {
    let base = *BASE.get_or_init(Instant::now);
    match clock_seconds(program) {
        Ok(ticks) => base + Duration::from_secs(ticks),
        Err(class) => {
            tracing::debug!(?class, "clock fixture unreadable");
            base
        }
    }
}


fn missing(part: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("fake runner called without {part}"))
}


fn fake_runner(program: &Path, arguments: &[&str], _cap: u64, deadline: Duration) -> Result<RunOutput, FailureClass> {
    let dir = program.parent().ok_or_else(|| missing("a program directory"))?;
    let target = arguments.first().ok_or_else(|| missing("a target"))?;
    let ups = target.split('@').next().ok_or_else(|| missing("a name"))?;
    let log = dir.join("calls.log");
    let mut text = read_or_empty(&log)?;
    text.push_str(&format!(
        "{} argc={} deadline={}\n",
        arguments.join(" "),
        arguments.len(),
        deadline.as_secs()
    ));
    fs::write(&log, text)?;
    let slow = read_or_empty(&dir.join(format!("{ups}.elapsed")))?;
    let ticks = read_or_empty(&dir.join("clock"))?;
    fs::write(dir.join("clock"), (seconds(&ticks)? + seconds(&slow)?).to_string())?;
    let behaviour = read_or_empty(&dir.join(format!("{ups}.behaviour")))?;
    match behaviour.trim() {
        "timed_out" => Err(FailureClass::TimedOut),
        "too_large" => Err(FailureClass::TooLarge),
        "signal" => Ok(RunOutput {
            bytes: Vec::new(),
            exit_code: None,
        }),
        "fail" => Ok(RunOutput {
            bytes: OL.as_bytes().to_vec(),
            exit_code: Some(1),
        }),
        "garbage" => Ok(RunOutput {
            bytes: b"ups.status: OL\nups.status: OB\n".to_vec(),
            exit_code: Some(0),
        }),
        _ => Ok(RunOutput {
            bytes: OL.as_bytes().to_vec(),
            exit_code: Some(0),
        }),
    }
}


fn settings(targets: &[&str]) -> UpsSettings {
    UpsSettings {
        ups_targets: targets.iter().map(|text| (*text).to_owned()).collect(),
        deadline_seconds: SHORT,
        round_deadline_seconds: LONG,
    }
}


fn program_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("upsc")
}


fn names<Item>(entries: &[(hardware_health::model::UpsTarget, Item)]) -> Vec<&str> {
    entries.iter().map(|(target, _)| target.text.as_str()).collect()
}


#[test]
fn two_targets_run_and_the_bad_ones_are_refused_by_index() -> TestResult {
    let dir = scratch()?;
    let all = settings(&[
        "one@alpha",
        "-l@localhost",
        "two@beta:3493",
        "one@alpha:3493",
        "ONE@alpha",
        "x@127.1",
        "a@b@c",
        "three@gamma:0",
    ]);
    let report = run_ups_with(&all, &program_in(&dir), fake_runner, fake_clock);
    assert_eq!(names(&report.reports), vec!["one@alpha", "two@beta:3493"]);
    assert_eq!(
        report.refused_targets,
        vec![1, COUNT_THREE, INDEX_FOUR, INDEX_FIVE, INDEX_SIX, INDEX_SEVEN]
    );
    assert!(report.failed.is_empty());
    let log = fs::read_to_string(dir.path().join("calls.log"))?;
    assert_eq!(log.lines().count(), COUNT_TWO);
    assert!(log.lines().all(|line| line.contains("argc=1")));
    Ok(())
}


#[test]
fn failures_are_classed_and_listed_never_dropped() -> TestResult {
    let dir = scratch()?;
    ["a", "b", "c", "d", "e"]
        .iter()
        .zip(["timed_out", "too_large", "signal", "fail", "garbage"])
        .try_for_each(|(ups, behaviour)| fs::write(dir.path().join(format!("{ups}.behaviour")), behaviour))?;
    let all = settings(&["a@h", "b@h", "c@h", "d@h", "e@h"]);
    let report = run_ups_with(&all, &program_in(&dir), fake_runner, fake_clock);
    assert!(report.reports.is_empty() && report.refused_targets.is_empty());
    let classes: Vec<UpsFailure> = report.failed.iter().map(|(_, class)| *class).collect();
    assert_eq!(
        classes,
        vec![
            UpsFailure::TimedOut,
            UpsFailure::TooLarge,
            UpsFailure::Signalled,
            UpsFailure::CommandFailed,
            UpsFailure::Unparsable
        ]
    );
    assert!(classes
        .iter()
        .all(|class| ups_failure_health(*class) == Health::BlindSpot(BlindReason::NoVerdict)));
    Ok(())
}


#[test]
fn targets_past_the_round_budget_are_deferred() -> TestResult {
    let dir = scratch()?;
    fs::write(dir.path().join("a.elapsed"), SLOW)?;
    fs::write(dir.path().join("b.elapsed"), SLOW)?;
    let mut all = settings(&["a@h", "b@h", "c@h"]);
    all.round_deadline_seconds = ROUND;
    let report = run_ups_with(&all, &program_in(&dir), fake_runner, fake_clock);
    assert_eq!(names(&report.reports), vec!["a@h", "b@h"]);
    assert_eq!(names(&report.failed), vec!["c@h"]);
    assert_eq!(report.failed.first().map(|(_, class)| *class), Some(UpsFailure::Deferred));
    let log = fs::read_to_string(dir.path().join("calls.log"))?;
    assert_eq!(log.lines().count(), COUNT_TWO);
    assert!(log.lines().nth(1).is_some_and(|line| line.ends_with("deadline=4")));
    Ok(())
}


#[test]
fn the_runner_failure_classes_map_one_to_one() -> TestResult {
    let pairs = [
        (FailureClass::TimedOut, UpsFailure::TimedOut),
        (FailureClass::TooLarge, UpsFailure::TooLarge),
        (FailureClass::Spawn, UpsFailure::Spawn),
        (FailureClass::Unwaitable, UpsFailure::Unwaitable),
        (FailureClass::Signalled, UpsFailure::Signalled),
        (FailureClass::ProgramRefused, UpsFailure::ProgramRefused),
        (FailureClass::Deferred, UpsFailure::Deferred),
        (FailureClass::CommandLine, UpsFailure::CommandFailed),
        (FailureClass::OpenFailed, UpsFailure::CommandFailed),
        (FailureClass::Unparsable, UpsFailure::Unparsable),
        (FailureClass::Io, UpsFailure::Io),
        (FailureClass::TooManyDevices, UpsFailure::Io),
    ];
    pairs.iter().for_each(|(class, expected)| assert_eq!(ups_failure_of(*class), *expected));
    assert!(UpsFailure::CommandFailed.to_string().contains("upsc"));
    assert!(!UpsFailure::TimedOut.to_string().contains("smartctl"));
    Ok(())
}


fn install(dir: &Path, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let source = dir.join(format!("{name}.src"));
    let target = dir.join(name);
    fs::write(&source, format!("#!/bin/sh\n{body}\n"))?;
    assert!(Command::new("install").arg("-m").arg("755").arg(&source).arg(&target).status()?.success());
    Ok(target)
}


#[test]
fn the_real_runner_passes_one_argument_and_trusts_only_stdout_on_exit_zero() -> TestResult {
    let dir = scratch()?;
    fs::write(dir.path().join("ol.txt"), OL)?;
    let body = format!(
        "echo \"$#:$1\" > {dir}/argv\necho {MARKER} >&2\ncase \"$1\" in bad@*) cat {dir}/ol.txt; exit 1;; *) cat {dir}/ol.txt;; esac",
        dir = dir.path().display()
    );
    let program = install(dir.path(), "upsc", &body)?;
    let all = settings(&["good@host:3493", "bad@host"]);
    let report = run_ups_with(&all, &program, run_smartctl, |_| Instant::now());
    assert_eq!(names(&report.reports), vec!["good@host:3493"]);
    assert_eq!(
        report.failed.iter().map(|(_, class)| *class).collect::<Vec<_>>(),
        vec![UpsFailure::CommandFailed]
    );
    assert!(!format!("{report:?}").contains(MARKER));
    assert_eq!(fs::read_to_string(dir.path().join("argv"))?.trim(), "1:bad@host");
    Ok(())
}


#[test]
fn a_silent_peer_times_out_and_a_flood_is_cut() -> TestResult {
    let dir = scratch()?;
    let hanging = install(dir.path(), "hanging", "sleep 30")?;
    let endless = install(dir.path(), "endless", "yes ups.status:")?;
    let mut one = settings(&["a@h"]);
    one.deadline_seconds = 1;
    let silent = run_ups_with(&one, &hanging, run_smartctl, |_| Instant::now());
    assert_eq!(silent.failed.first().map(|(_, class)| *class), Some(UpsFailure::TimedOut));
    let flood = run_ups_with(&one, &endless, run_smartctl, |_| Instant::now());
    assert_eq!(flood.failed.first().map(|(_, class)| *class), Some(UpsFailure::TooLarge));
    Ok(())
}


#[test]
fn the_production_entry_names_the_program_const() -> TestResult {
    assert_eq!(UPSC_PROGRAM, "/usr/bin/upsc");
    let report = run_ups(&settings(&["a@h"]), const_path_runner);
    assert_eq!(report.reports.len(), 1);
    Ok(())
}


fn const_path_runner(program: &Path, _arguments: &[&str], _cap: u64, _deadline: Duration) -> Result<RunOutput, FailureClass> {
    if program == Path::new(UPSC_PROGRAM) {
        Ok(RunOutput {
            bytes: OL.as_bytes().to_vec(),
            exit_code: Some(0),
        })
    } else {
        Err(FailureClass::ProgramRefused)
    }
}


#[test]
fn the_fake_runner_refuses_a_call_without_its_parts() -> TestResult {
    assert!(fake_runner(Path::new("/"), &["a@h"], 0, Duration::ZERO).is_err());
    assert!(fake_runner(Path::new("/tmp/upsc"), &[], 0, Duration::ZERO).is_err());
    Ok(())
}

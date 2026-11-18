#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use hardware_health::model::{FailureClass, RunOutput, SmartSettings};
use hardware_health::smart_run::{classify_exit, failure_of, is_device_name, is_device_type, run_smartctl, scan_and_report};
use net_topology::model::RunFailure;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use types::TestResult;


const HEALTHY: &str = include_str!("fixtures/ata-healthy.json");


const OPEN_FAILED: &str = include_str!("fixtures/open-failed.json");


const SHORT_DEADLINE: u64 = 5;


const LONG_DEADLINE: u64 = 30;


const COUNT_TWO: usize = 2;


const COUNT_SIX: usize = 6;


const NAME_FILL: usize = 60;


const TYPE_OVER: usize = 33;


const ARGUMENT_COUNT: usize = 3;


const MARKER: &str = "STDERR-MARKER-9F3A";


const PATIENT: Duration = Duration::from_secs(60);


const CAP: u64 = 4096;


const SMALL_CAP: u64 = 10;


const TOO_MANY: usize = 65;


const BIT_OPEN_FAILED: i32 = 2;


const BIT_COMMAND_LINE: i32 = 1;


const BIT_DISK_STATE: i32 = 4;


const BIT_BOTH: i32 = 3;


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


fn fake_runner(program: &Path, arguments: &[&str], _cap: u64, _deadline: Duration) -> Result<RunOutput, FailureClass> {
    let dir = program.parent().unwrap_or(program);
    let log = dir.join("calls.log");
    let mut text = read_or_empty(&log)?;
    text.push_str(&arguments.join(" "));
    text.push('\n');
    fs::write(&log, text)?;
    let stem = match arguments.first() {
        Some(&"--scan-open") => "scan".to_owned(),
        _ => arguments.last().and_then(|name| name.rsplit('/').next()).unwrap_or("").to_owned(),
    };
    let failure = read_or_empty(&dir.join(format!("{stem}.fail")))?;
    match failure.trim() {
        "timed_out" => Err(FailureClass::TimedOut),
        "too_large" => Err(FailureClass::TooLarge),
        _ => {
            let code = read_or_empty(&dir.join(format!("{stem}.code")))?;
            Ok(RunOutput {
                bytes: fs::read(dir.join(format!("{stem}.json")))?,
                exit_code: code.trim().parse().ok(),
            })
        }
    }
}


struct Setup {
    dir: tempfile::TempDir,
    settings: SmartSettings,
}


fn setup(scan: &str) -> Result<Setup, io::Error> {
    let dir = scratch()?;
    fs::write(dir.path().join("scan.json"), scan)?;
    fs::write(dir.path().join("scan.code"), "0")?;
    let settings = SmartSettings {
        program: dir.path().join("smartctl"),
        deadline_seconds: SHORT_DEADLINE,
    };
    Ok(Setup { dir, settings })
}


fn disk(setup: &Setup, name: &str, json: &str, code: &str) -> Result<(), io::Error> {
    fs::write(setup.dir.path().join(format!("{name}.json")), json)?;
    fs::write(setup.dir.path().join(format!("{name}.code")), code)
}


fn calls(setup: &Setup) -> Result<Vec<String>, io::Error> {
    Ok(fs::read_to_string(setup.dir.path().join("calls.log"))?
        .lines()
        .map(str::to_owned)
        .collect())
}


const TWO_DISKS: &str = r#"{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/nvme0","type":"nvme"}]}"#;


#[test]
fn a_scan_of_two_disks_gives_two_reports() -> TestResult {
    let setup = setup(TWO_DISKS)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "nvme0", HEALTHY, "0")?;
    let report = scan_and_report(&setup.settings, fake_runner);
    assert_eq!(report.reports.len(), COUNT_TWO);
    assert_eq!(report.refused_devices, 0);
    assert!(report.failed.is_empty() && report.scan_failed.is_none());
    assert_eq!(
        calls(&setup)?,
        vec!["--scan-open --json=c", "--json=c -a -d sat /dev/sda", "--json=c -a -d nvme /dev/nvme0"]
    );
    Ok(())
}


#[test]
fn hostile_scan_entries_are_refused_alone() -> TestResult {
    let scan = r#"{"devices":[{"name":"--foo","type":"sat"},{"name":"/dev/../etc/passwd","type":"sat"},{"name":"/dev/sda","type":"-x"},
        {"name":5,"type":"sat"},{"name":"/dev/sdb"},{"name":"/dev//sdc","type":"sat"},{"name":"/dev/sda","type":"sat"}]}"#;
    let setup = setup(scan)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    let report = scan_and_report(&setup.settings, fake_runner);
    assert_eq!(report.refused_devices, COUNT_SIX);
    assert_eq!(report.reports.len(), 1);
    assert_eq!(calls(&setup)?.len(), COUNT_TWO);
    Ok(())
}


#[test]
fn too_many_entries_are_refused_before_any_device_run() -> TestResult {
    let entries = vec![r#"{"name":"/dev/sda","type":"sat"}"#; TOO_MANY].join(",");
    let setup = setup(&format!(r#"{{"devices":[{entries}]}}"#))?;
    disk(&setup, "sda", HEALTHY, "0")?;
    let report = scan_and_report(&setup.settings, fake_runner);
    assert_eq!(report.scan_failed, Some(FailureClass::TooManyDevices));
    assert!(report.reports.is_empty());
    assert_eq!(calls(&setup)?.len(), 1);
    Ok(())
}


#[test]
fn exit_bits_decide_failed_or_parsed() -> TestResult {
    let scan = r#"{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/sdb","type":"sat"},{"name":"/dev/sdc","type":"sat"},
        {"name":"/dev/sdd","type":"sat"},{"name":"/dev/sde","type":"sat"}]}"#;
    let setup = setup(scan)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "sdb", OPEN_FAILED, &BIT_OPEN_FAILED.to_string())?;
    disk(&setup, "sdc", HEALTHY, &BIT_DISK_STATE.to_string())?;
    disk(&setup, "sdd", HEALTHY, &BIT_COMMAND_LINE.to_string())?;
    disk(&setup, "sde", HEALTHY, "none")?;
    let report = scan_and_report(&setup.settings, fake_runner);
    let names: Vec<&str> = report.reports.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["/dev/sda", "/dev/sdc"]);
    assert_eq!(
        report.failed,
        vec![
            ("/dev/sdb".to_owned(), FailureClass::OpenFailed),
            ("/dev/sdd".to_owned(), FailureClass::CommandLine),
            ("/dev/sde".to_owned(), FailureClass::Signalled),
        ]
    );
    Ok(())
}


#[test]
fn runner_failures_and_garbage_are_failed_classes() -> TestResult {
    let scan = r#"{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/sdb","type":"sat"},{"name":"/dev/sdc","type":"sat"}]}"#;
    let setup = setup(scan)?;
    fs::write(setup.dir.path().join("sda.fail"), "timed_out")?;
    fs::write(setup.dir.path().join("sdb.fail"), "too_large")?;
    disk(&setup, "sdc", "not json", "0")?;
    let report = scan_and_report(&setup.settings, fake_runner);
    assert_eq!(
        report.failed,
        vec![
            ("/dev/sda".to_owned(), FailureClass::TimedOut),
            ("/dev/sdb".to_owned(), FailureClass::TooLarge),
            ("/dev/sdc".to_owned(), FailureClass::Unparsable),
        ]
    );
    Ok(())
}


#[test]
fn a_failed_scan_is_reported_with_its_class() -> TestResult {
    let broken = setup("not json")?;
    assert_eq!(scan_and_report(&broken.settings, fake_runner).scan_failed, Some(FailureClass::Unparsable));
    let typed = setup(r#"{"devices":[{"name":1,"type":2}], "x": }"#)?;
    assert_eq!(scan_and_report(&typed.settings, fake_runner).scan_failed, Some(FailureClass::Unparsable));
    let wrong_shape = setup(r#"{"devices":[7]}"#)?;
    assert_eq!(
        scan_and_report(&wrong_shape.settings, fake_runner).scan_failed,
        Some(FailureClass::Unparsable)
    );
    let timed = setup("{}")?;
    fs::write(timed.dir.path().join("scan.fail"), "timed_out")?;
    assert_eq!(scan_and_report(&timed.settings, fake_runner).scan_failed, Some(FailureClass::TimedOut));
    let opened = setup("{}")?;
    fs::write(opened.dir.path().join("scan.code"), BIT_BOTH.to_string())?;
    assert_eq!(
        scan_and_report(&opened.settings, fake_runner).scan_failed,
        Some(FailureClass::CommandLine)
    );
    let empty = setup("{}")?;
    let report = scan_and_report(&empty.settings, fake_runner);
    assert!(report.scan_failed.is_none() && report.reports.is_empty());
    Ok(())
}


#[test]
fn the_grammar_of_names_and_types() -> TestResult {
    assert!(is_device_name("/dev/sda") && is_device_name("/dev/disk/by-id/ata_x1"));
    assert!(!is_device_name("/dev/") && !is_device_name("sda") && !is_device_name("/dev/SDA"));
    assert!(!is_device_name("/dev/a b") && !is_device_name("/dev/a//b") && !is_device_name("/dev/a..b"));
    assert!(!is_device_name(&format!("/dev/{}", "a".repeat(NAME_FILL))));
    assert!(is_device_type("sat,12") && is_device_type("megaraid,0") && is_device_type("scsi+x"));
    assert!(!is_device_type("") && !is_device_type("-d") && !is_device_type("SAT") && !is_device_type("a b"));
    assert!(!is_device_type(&"a".repeat(TYPE_OVER)));
    Ok(())
}


#[test]
fn exit_and_failure_mappings() -> TestResult {
    assert_eq!(classify_exit(Some(0)), None);
    assert_eq!(classify_exit(Some(BIT_BOTH)), Some(FailureClass::CommandLine));
    assert_eq!(classify_exit(None), Some(FailureClass::Signalled));
    assert_eq!(failure_of(RunFailure::TimedOut), FailureClass::TimedOut);
    assert_eq!(failure_of(RunFailure::TooLarge), FailureClass::TooLarge);
    assert_eq!(failure_of(RunFailure::Spawn), FailureClass::Spawn);
    assert_eq!(failure_of(RunFailure::Unwaitable), FailureClass::Unwaitable);
    assert_eq!(failure_of(RunFailure::Io), FailureClass::Io);
    assert_eq!(failure_of(RunFailure::Refused), FailureClass::Io);
    assert_eq!(failure_of(RunFailure::Failed { code: None, read: 0 }), FailureClass::Io);
    assert_eq!(FailureClass::from(io::Error::from(io::ErrorKind::Other)), FailureClass::Io);
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
fn the_real_runner_passes_separate_arguments_and_a_cleared_environment() -> TestResult {
    let dir = scratch()?;
    let program = install(dir.path(), "args", "printf '%s\\n' \"$@\"; env")?;
    let output = run_smartctl(&program, &["a b", ";id", "$(x)"], CAP, PATIENT)?;
    let text = String::from_utf8(output.bytes)?;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.get(..ARGUMENT_COUNT), Some(["a b", ";id", "$(x)"].as_slice()));
    assert!(lines.contains(&"LC_ALL=C"));
    assert!(!lines.iter().any(|line| line.starts_with("HOME=") || line.starts_with("PATH=")));
    assert_eq!(output.exit_code, Some(0));
    Ok(())
}


#[test]
fn the_real_runner_keeps_output_on_a_disk_state_exit_and_drops_stderr() -> TestResult {
    let dir = scratch()?;
    let program = install(dir.path(), "state", &format!("echo '{{}}'; echo {MARKER} >&2; exit 4"))?;
    let output = run_smartctl(&program, &[], CAP, PATIENT)?;
    assert_eq!(output.exit_code, Some(BIT_DISK_STATE));
    assert_eq!(output.bytes, b"{}\n");
    assert!(!format!("{output:?}").contains(MARKER));
    Ok(())
}


#[test]
fn the_real_runner_classifies_signal_size_deadline_and_spawn() -> TestResult {
    let dir = scratch()?;
    let killed = install(dir.path(), "killed", "kill -9 $$")?;
    assert_eq!(run_smartctl(&killed, &[], CAP, PATIENT)?.exit_code, None);
    let endless = install(dir.path(), "endless", "yes")?;
    assert_eq!(run_smartctl(&endless, &[], SMALL_CAP, PATIENT), Err(FailureClass::TooLarge));
    let hanging = install(dir.path(), "hanging", "sleep 30")?;
    assert_eq!(run_smartctl(&hanging, &[], CAP, Duration::ZERO), Err(FailureClass::TimedOut));
    assert_eq!(run_smartctl(&dir.path().join("missing"), &[], CAP, PATIENT), Err(FailureClass::Spawn));
    Ok(())
}


#[test]
fn a_real_script_end_to_end_never_leaks_stderr() -> TestResult {
    let dir = scratch()?;
    fs::write(dir.path().join("scan.json"), TWO_DISKS)?;
    fs::write(dir.path().join("disk.json"), HEALTHY)?;
    let body = format!(
        "echo {MARKER} >&2\nif [ \"$1\" = --scan-open ]; then cat {dir}/scan.json; else case \"$5\" in /dev/sda) cat {dir}/disk.json; exit 4;; *) exit 2;; esac; fi",
        dir = dir.path().display()
    );
    let program = install(dir.path(), "smartctl", &body)?;
    let settings = SmartSettings {
        program,
        deadline_seconds: LONG_DEADLINE,
    };
    let report = scan_and_report(&settings, run_smartctl);
    assert_eq!(report.reports.len(), 1);
    assert_eq!(report.failed, vec![("/dev/nvme0".to_owned(), FailureClass::OpenFailed)]);
    assert!(!format!("{report:?}").contains(MARKER));
    Ok(())
}

#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use hardware_health::model::{FailureClass, RunOutput, SmartSettings};
use hardware_health::smart_run::{
    classify_exit, failure_of, is_device_name, is_device_type, run_smartctl, run_with_hook, scan_and_report, scan_and_report_with, system_clock,
    SMARTCTL_PROGRAM,
};
use net_topology::model::RunFailure;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use types::TestResult;


const HEALTHY: &str = include_str!("fixtures/ata-healthy.json");


const OPEN_FAILED: &str = include_str!("fixtures/open-failed.json");


const SHORT_DEADLINE: u64 = 5;


const LONG_DEADLINE: u64 = 30;


const COUNT_TWO: usize = 2;


const COUNT_SIX: usize = 6;


const COUNT_THREE: usize = 3;


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


const PLAIN_MODE: u32 = 0o644;


const EXECUTABLE_MODE: u32 = 0o755;


const NOBODY: u32 = 65_534;


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
    let log = dir.join("calls.log");
    let mut text = read_or_empty(&log)?;
    text.push_str(&arguments.join(" "));
    text.push('\n');
    fs::write(&log, text)?;
    let stem = match arguments.first() {
        Some(&"--scan-open") => "scan".to_owned(),
        _ => arguments
            .last()
            .and_then(|name| name.rsplit('/').next())
            .ok_or_else(|| missing("a device argument"))?
            .to_owned(),
    };
    fs::write(dir.join(format!("{stem}.deadline")), deadline.as_secs().to_string())?;
    let slow = read_or_empty(&dir.join(format!("{stem}.elapsed")))?;
    let ticks = read_or_empty(&dir.join("clock"))?;
    fs::write(dir.join("clock"), (seconds(&ticks)? + seconds(&slow)?).to_string())?;
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
    program: PathBuf,
    settings: SmartSettings,
}


fn setup(scan: &str) -> Result<Setup, io::Error> {
    let dir = scratch()?;
    fs::write(dir.path().join("scan.json"), scan)?;
    fs::write(dir.path().join("scan.code"), "0")?;
    let settings = SmartSettings {
        deadline_seconds: SHORT_DEADLINE,
        round_deadline_seconds: LONG_DEADLINE,
    };
    let program = dir.path().join("smartctl");
    Ok(Setup { dir, program, settings })
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
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
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
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
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
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
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
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
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
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
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
    assert_eq!(
        scan_and_report_with(&broken.settings, &broken.program, fake_runner, fake_clock).scan_failed,
        Some(FailureClass::Unparsable)
    );
    let typed = setup(r#"{"devices":[{"name":1,"type":2}], "x": }"#)?;
    assert_eq!(
        scan_and_report_with(&typed.settings, &typed.program, fake_runner, fake_clock).scan_failed,
        Some(FailureClass::Unparsable)
    );
    let wrong_shape = setup(r#"{"devices":7}"#)?;
    assert_eq!(
        scan_and_report_with(&wrong_shape.settings, &wrong_shape.program, fake_runner, fake_clock).scan_failed,
        Some(FailureClass::Unparsable)
    );
    let timed = setup("{}")?;
    fs::write(timed.dir.path().join("scan.fail"), "timed_out")?;
    assert_eq!(
        scan_and_report_with(&timed.settings, &timed.program, fake_runner, fake_clock).scan_failed,
        Some(FailureClass::TimedOut)
    );
    let opened = setup("{}")?;
    fs::write(opened.dir.path().join("scan.code"), BIT_BOTH.to_string())?;
    assert_eq!(
        scan_and_report_with(&opened.settings, &opened.program, fake_runner, fake_clock).scan_failed,
        Some(FailureClass::CommandLine)
    );
    let empty = setup("{}")?;
    let report = scan_and_report_with(&empty.settings, &empty.program, fake_runner, fake_clock);
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
    assert_eq!(
        run_smartctl(&dir.path().join("missing"), &[], CAP, PATIENT),
        Err(FailureClass::ProgramRefused)
    );
    let plain = dir.path().join("plain");
    fs::write(&plain, "#!/bin/sh\n")?;
    fs::set_permissions(&plain, fs::Permissions::from_mode(PLAIN_MODE))?;
    assert_eq!(run_smartctl(&plain, &[], CAP, PATIENT), Err(FailureClass::ProgramRefused));
    let broken = dir.path().join("broken");
    fs::write(&broken, "#!/nonexistent/interpreter\n")?;
    fs::set_permissions(&broken, fs::Permissions::from_mode(EXECUTABLE_MODE))?;
    assert_eq!(run_smartctl(&broken, &[], CAP, PATIENT), Err(FailureClass::Spawn));
    Ok(())
}


fn swap_program(program: &Path) {
    let swapped = fs::rename(program, program.with_extension("moved"))
        .and_then(|()| fs::write(program, "#!/bin/sh\n"))
        .and_then(|()| fs::set_permissions(program, fs::Permissions::from_mode(EXECUTABLE_MODE)));
    if let Err(error) = swapped {
        tracing::warn!(%error, "the swap failed");
    }
}


fn leave(_program: &Path) {}


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


#[test]
fn a_program_renamed_between_the_check_and_the_spawn_is_refused() -> TestResult {
    let dir = scratch()?;
    let program = install(dir.path(), "swapped", "echo ok")?;
    let refused = run_with_hook(&program, &[], (CAP, PATIENT), (euid(), swap_program));
    assert_eq!(refused, Err(FailureClass::ProgramRefused));
    let untouched = install(dir.path(), "untouched", "echo ok")?;
    assert_eq!(run_with_hook(&untouched, &[], (CAP, PATIENT), (euid(), leave))?.exit_code, Some(0));
    Ok(())
}


#[test]
fn the_production_run_refuses_a_program_owned_by_nobody() -> TestResult {
    let dir = scratch()?;
    let program = install(dir.path(), "nobody", "echo ok")?;
    if euid() == 0 {
        rustix::fs::chown(&program, Some(rustix::fs::Uid::from_raw(NOBODY)), None)?;
        assert_eq!(run_smartctl(&program, &[], CAP, PATIENT), Err(FailureClass::ProgramRefused));
    }
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
        deadline_seconds: LONG_DEADLINE,
        round_deadline_seconds: LONG_DEADLINE,
    };
    let report = scan_and_report_with(&settings, &program, run_smartctl, system_clock);
    assert_eq!(report.reports.len(), 1);
    assert_eq!(report.failed, vec![("/dev/nvme0".to_owned(), FailureClass::OpenFailed)]);
    assert!(!format!("{report:?}").contains(MARKER));
    Ok(())
}


const ROUND_BUDGET: u64 = 10;


const SLOW_RUN: &str = "6";


const THREE_DISKS: &str = r#"{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/sdb","type":"sat"},{"name":"/dev/sdc","type":"sat"}]}"#;


#[test]
fn devices_past_the_round_budget_are_deferred() -> TestResult {
    let mut setup = setup(THREE_DISKS)?;
    setup.settings.round_deadline_seconds = ROUND_BUDGET;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "sdb", HEALTHY, "0")?;
    disk(&setup, "sdc", HEALTHY, "0")?;
    fs::write(setup.dir.path().join("sda.elapsed"), SLOW_RUN)?;
    fs::write(setup.dir.path().join("sdb.elapsed"), SLOW_RUN)?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(report.reports.len(), COUNT_TWO);
    assert_eq!(report.failed, vec![("/dev/sdc".to_owned(), FailureClass::Deferred)]);
    assert_eq!(report.refused_devices, 0);
    assert_eq!(calls(&setup)?.len(), COUNT_TWO + 1);
    Ok(())
}


#[test]
fn timeouts_spend_the_round_budget() -> TestResult {
    let mut setup = setup(THREE_DISKS)?;
    setup.settings.round_deadline_seconds = ROUND_BUDGET;
    fs::write(setup.dir.path().join("sda.fail"), "timed_out")?;
    fs::write(setup.dir.path().join("sdb.fail"), "too_large")?;
    fs::write(setup.dir.path().join("sda.elapsed"), SHORT_DEADLINE.to_string())?;
    fs::write(setup.dir.path().join("sdb.elapsed"), SHORT_DEADLINE.to_string())?;
    disk(&setup, "sdc", HEALTHY, "0")?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(
        report.failed,
        vec![
            ("/dev/sda".to_owned(), FailureClass::TimedOut),
            ("/dev/sdb".to_owned(), FailureClass::TooLarge),
            ("/dev/sdc".to_owned(), FailureClass::Deferred),
        ]
    );
    assert!(report.reports.is_empty());
    assert_eq!(report.refused_devices, 0);
    Ok(())
}


#[test]
fn names_and_types_must_be_short_plain_strings() -> TestResult {
    let long = format!("/dev/{}", "a".repeat(NAME_FILL));
    let scan = format!(
        r#"{{"devices":[{{"name":[0,0,[1]],"type":"sat"}},{{"name":"{long}","type":"sat"}},{{"name":"/dev/sda","type":{{"a":1}}}},
        {{"name":"/dev/sda","type":null}},{{"name":"/dev/sda","type":"sat"}},{{"name":"/dev/sdb\u0000","type":"sat"}}]}}"#
    );
    let setup = setup(&scan)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(report.refused_devices, COUNT_SIX - 1);
    assert_eq!(report.reports.len(), 1);
    Ok(())
}


const SLOW_FAILURE: &str = "4";


#[test]
fn slow_failures_spend_the_round_budget() -> TestResult {
    let mut setup = setup(THREE_DISKS)?;
    setup.settings.round_deadline_seconds = ROUND_BUDGET;
    disk(&setup, "sda", OPEN_FAILED, &BIT_OPEN_FAILED.to_string())?;
    disk(&setup, "sdb", "not json", "0")?;
    disk(&setup, "sdc", HEALTHY, "0")?;
    fs::write(setup.dir.path().join("sda.elapsed"), "6")?;
    fs::write(setup.dir.path().join("sdb.elapsed"), SLOW_FAILURE)?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(
        report.failed,
        vec![
            ("/dev/sda".to_owned(), FailureClass::OpenFailed),
            ("/dev/sdb".to_owned(), FailureClass::Unparsable),
            ("/dev/sdc".to_owned(), FailureClass::Deferred),
        ]
    );
    assert!(report.reports.is_empty());
    assert_eq!(report.refused_devices, 0);
    assert_eq!(calls(&setup)?.len(), COUNT_TWO + 1);
    Ok(())
}


#[test]
fn the_scan_time_counts_against_the_round() -> TestResult {
    let mut setup = setup(TWO_DISKS)?;
    setup.settings.round_deadline_seconds = ROUND_BUDGET;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "nvme0", HEALTHY, "0")?;
    fs::write(setup.dir.path().join("scan.elapsed"), ROUND_BUDGET.to_string())?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert!(report.reports.is_empty());
    assert_eq!(
        report.failed,
        vec![
            ("/dev/sda".to_owned(), FailureClass::Deferred),
            ("/dev/nvme0".to_owned(), FailureClass::Deferred)
        ]
    );
    assert_eq!(calls(&setup)?.len(), 1);
    Ok(())
}


#[test]
fn a_bad_clock_fixture_is_logged_and_the_run_goes_on() -> TestResult {
    let setup = setup(TWO_DISKS)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "nvme0", HEALTHY, "0")?;
    fs::write(setup.dir.path().join("clock"), "x")?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert!(report.scan_failed.is_some() || !report.failed.is_empty());
    Ok(())
}


#[test]
fn duplicate_keys_and_non_objects_refuse_one_entry() -> TestResult {
    let scan = r#"{"devices":[7,null,{"name":"/dev/sda","name":"/dev/sdb","type":"sat"},{"name":"/dev/sda","type":"sat"}]}"#;
    let setup = setup(scan)?;
    disk(&setup, "sda", HEALTHY, "0")?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(report.refused_devices, COUNT_THREE);
    assert_eq!(report.reports.len(), 1);
    Ok(())
}


#[test]
fn the_real_clock_runs_a_real_scan() -> TestResult {
    let dir = scratch()?;
    let program = install(dir.path(), "smartctl", "echo '{}'")?;
    let settings = SmartSettings {
        deadline_seconds: LONG_DEADLINE,
        round_deadline_seconds: LONG_DEADLINE,
    };
    assert!(scan_and_report_with(&settings, &program, run_smartctl, system_clock)
        .scan_failed
        .is_none());
    Ok(())
}


#[test]
fn the_scan_gets_the_round_as_its_deadline() -> TestResult {
    let mut setup = setup(TWO_DISKS)?;
    setup.settings.deadline_seconds = LONG_DEADLINE;
    setup.settings.round_deadline_seconds = ROUND_BUDGET;
    disk(&setup, "sda", HEALTHY, "0")?;
    disk(&setup, "nvme0", HEALTHY, "0")?;
    fs::write(setup.dir.path().join("scan.elapsed"), LONG_DEADLINE.to_string())?;
    let report = scan_and_report_with(&setup.settings, &setup.program, fake_runner, fake_clock);
    assert_eq!(fs::read_to_string(setup.dir.path().join("scan.deadline"))?, ROUND_BUDGET.to_string());
    assert!(report.reports.is_empty());
    assert_eq!(calls(&setup)?.len(), 1);
    Ok(())
}


#[test]
fn the_fake_runner_refuses_a_call_without_its_parts() -> TestResult {
    let dir = scratch()?;
    let no_device = fake_runner(&dir.path().join("smartctl"), &[], 0, Duration::ZERO);
    let no_directory = fake_runner(Path::new("/"), &["--scan-open"], 0, Duration::ZERO);
    assert!(no_device.is_err());
    assert!(no_directory.is_err());
    Ok(())
}


fn const_path_runner(program: &Path, _arguments: &[&str], _cap: u64, _deadline: Duration) -> Result<RunOutput, FailureClass> {
    if program == Path::new(SMARTCTL_PROGRAM) {
        Ok(RunOutput {
            bytes: b"{}".to_vec(),
            exit_code: Some(0),
        })
    } else {
        Err(FailureClass::ProgramRefused)
    }
}


#[test]
fn the_production_scan_runs_the_program_const_only() -> TestResult {
    let settings = SmartSettings {
        deadline_seconds: LONG_DEADLINE,
        round_deadline_seconds: LONG_DEADLINE,
    };
    assert_eq!(SMARTCTL_PROGRAM, "/usr/sbin/smartctl");
    assert!(scan_and_report(&settings, const_path_runner).scan_failed.is_none());
    Ok(())
}

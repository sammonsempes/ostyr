#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/readback.rs"]
mod readback;
#[path = "common/runner.rs"]
mod runner;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use clock::now;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::Outcome;
use core_audit::tenant::PLATFORM_TENANT;
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use core_config::types::SharedAuditFn;
use dns_rpz::cli::{run_round, run_round_with, Session};
use dns_rpz::error::ServiceError;
use dns_rpz::model::{CommandStatus, LoopEnd, Reloader, RoundLoop, RoundOutcome, ServiceSettings};
use dns_rpz::policy::Policy;
use dns_rpz::service::{
    changed_pinned, check_allowlist, exit_code, failed_stage, invalid_settings, one_round, open_settings_engine, read_service_settings,
    round_failed_entry, serve_rounds, service_context, service_readback, service_runner, settings_state, validate_settings, zone_file_matches,
};
use dns_rpz::source::open_source;
use dns_rpz::types::{RunnerFn, WaitFn};
use engine::{audit, context, engine_for, policy_text, replace_file};
use memory::LimitedWriter;
use readback::{stale_readback, zone_listing};
use runner::{failing_runner, succeeding_runner};
use sample::sample_policy;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const INTERVAL: u64 = 60;


const LONGER_INTERVAL: u64 = 120;


const TOO_SHORT: u64 = 59;


const TOO_LONG: u64 = 86_401;


const TWICE: usize = 2;


const THRICE: usize = 3;


const TWO_ROUNDS: u64 = 2;


const MANY_ROUNDS: u64 = 100;


const BIG_FILE: usize = 5_000;


const ROUND_CAP_CODE: u8 = 3;


fn ioc_line(value: &str) -> String {
    format!(
        "{{\"ioc_type\":\"domain\",\"value\":\"{value}\",\"sources\":[],\"first_seen\":\"2026-11-01T00:00:00Z\",\
\"last_seen\":\"2026-11-03T00:00:00Z\",\"confidence\":90,\"tlp\":\"amber\",\"expires_at\":null,\"tags\":{{\"malware\":[],\"actor\":[],\"campaign\":[]}}}}\n"
    )
}


fn service_text(dir: &Path, interval: u64) -> String {
    let base = dir.display();
    format!(
        "policy_file: {base}/policy.yaml\naudit_file: {base}/audit.log\nioc_source: {base}/iocs.jsonl\ncounter_file: {base}/counter\n\
zone_file: {base}/zone.db\ninterval_seconds: {interval}\n"
    )
}


fn write_files(dir: &Path, domain: &str, interval: u64) -> TestResult {
    replace_file(
        &dir.join("policy.yaml"),
        &policy_text(&format!("unbound:\n  zonefile: {}/zone.db\n", dir.display())),
    )?;
    replace_file(&dir.join("service.yaml"), &service_text(dir, interval))?;
    replace_file(&dir.join("iocs.jsonl"), &ioc_line(domain))?;
    Ok(())
}


fn recording_audit(actions: &Arc<Mutex<Vec<String>>>) -> Box<SharedAuditFn> {
    let log = genesis_log(std::io::sink());
    let seen = Arc::clone(actions);
    Box::new(move |entry| {
        if let Ok(mut list) = seen.lock() {
            list.push(entry.action.clone());
        }
        append(&log, entry)
    })
}


fn count_of(actions: &Arc<Mutex<Vec<String>>>, name: &str) -> Result<usize, ServiceError> {
    let list = actions.lock().map_err(|_| ServiceError::Changed)?;
    Ok(list.iter().filter(|action| action.as_str() == name).count())
}


fn settings_engine(dir: &Path) -> Result<ReloadEngine<ServiceSettings>, ServiceError> {
    let service_file = dir.join("service.yaml");
    let first = read_service_settings(&service_file)?;
    open_settings_engine(service_file, &first, audit(), context())
}


/// Unbound serves the new zone exactly when the reload command succeeded.
pub fn simulated_readback(runner: &RunnerFn, zone: &Path, program: &str, arguments: &[String], deadline: Duration) -> std::io::Result<String> {
    match runner(program, arguments, deadline)? {
        CommandStatus::Success => zone_listing(zone),
        CommandStatus::Failed(_) | CommandStatus::TimedOut => stale_readback(program, arguments, deadline),
    }
}


fn drive(
    dir: &Path,
    settings: &ReloadEngine<ServiceSettings>,
    runner: &RunnerFn,
    audit_sink: &SharedAuditFn,
    wait: &WaitFn,
    max_rounds: u64,
    report: &mut dyn Write,
) -> Result<LoopEnd, ServiceError> {
    logging::init_logging();
    let policy = engine_for(&dir.join("policy.yaml"))?;
    let rejected = AtomicU64::new(0);
    let spec = dir.join("iocs.jsonl").display().to_string();
    let open = open_source(&spec, &rejected);
    let zone_context = context();
    let zone = dir.join("zone.db");
    let reloader = Reloader {
        runner,
        readback: &|program: &str, arguments: &[String], deadline: Duration| simulated_readback(runner, &zone, program, arguments, deadline),
        audit: audit_sink,
        context: &zone_context,
    };
    let counter = dir.join("counter");
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &*open,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report,
        reloader: &reloader,
    };
    let failure_context = service_context("zone", "round");
    let round_loop = RoundLoop {
        settings,
        audit: audit_sink,
        context: &failure_context,
    };
    serve_rounds(&mut session, &round_loop, wait, max_rounds)
}


#[test]
fn rounds_follow_the_interval_and_publish_each_change() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let durations = Mutex::new(Vec::new());
    let calls = AtomicUsize::new(0);
    let wait = |interval: Duration| {
        if let Ok(mut list) = durations.lock() {
            list.push(interval);
        }
        let call = calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            replace_file(&dir.path().join("iocs.jsonl"), &ioc_line("second.example.com")).is_err()
        } else {
            true
        }
    };
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::Stopped);
    assert_eq!(
        *durations.lock().map_err(|_| ServiceError::Changed)?,
        vec![Duration::from_secs(INTERVAL); TWICE]
    );
    let zone = fs::read_to_string(dir.path().join("zone.db"))?;
    assert!(
        zone.contains("second.example.com") && !zone.contains("first.example.com") && zone.contains(" 2026110302 "),
        "{zone}"
    );
    assert_eq!(count_of(&actions, "dns-rpz.zone_reload")?, TWICE);
    assert_eq!(count_of(&actions, "dns-rpz.round_failed")?, 0);
    Ok(())
}


#[test]
fn a_failed_round_is_audited_keeps_the_zone_and_the_next_round_runs() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let calls = AtomicUsize::new(0);
    let ioc_file = dir.path().join("iocs.jsonl");
    let zone_file = dir.path().join("zone.db");
    let kept = Mutex::new(Vec::new());
    let wait = |_interval: Duration| {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        match call {
            0 => {
                if let (Ok(bytes), Ok(mut slot)) = (fs::read(&zone_file), kept.lock()) {
                    slot.extend(bytes);
                }
                fs::remove_file(&ioc_file).is_err()
            }
            1 => replace_file(&ioc_file, &ioc_line("third.example.com")).is_err(),
            _ => true,
        }
    };
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::Stopped);
    assert_eq!(count_of(&actions, "dns-rpz.round_failed")?, 1);
    assert_eq!(count_of(&actions, "dns-rpz.zone_reload")?, TWICE);
    let first_zone = kept.lock().map_err(|_| ServiceError::Changed)?.clone();
    assert!(String::from_utf8(first_zone)?.contains("first.example.com"));
    let last_zone = fs::read_to_string(&zone_file)?;
    assert!(last_zone.contains("third.example.com"), "{last_zone}");
    let text = String::from_utf8(report)?;
    assert_eq!(text.matches("failed ").count(), 1, "{text}");
    Ok(())
}


#[test]
fn a_failed_round_leaves_the_previous_zone_whole() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let calls = AtomicUsize::new(0);
    let ioc_file = dir.path().join("iocs.jsonl");
    let wait = |_interval: Duration| {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        call > 0 || fs::remove_file(&ioc_file).is_err()
    };
    let mut report = Vec::new();
    drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    let zone = fs::read_to_string(dir.path().join("zone.db"))?;
    assert!(zone.contains("first.example.com") && zone.contains(" 2026110301 "), "{zone}");
    let leftovers = fs::read_dir(dir.path())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".tmp"))
        .count();
    assert_eq!(leftovers, 0);
    Ok(())
}


#[test]
fn the_round_cap_ends_the_loop() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let wait = |_interval: Duration| false;
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        TWO_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::RoundCap);
    assert_eq!(count_of(&actions, "dns-rpz.zone_reload")?, TWICE);
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains(" 2026110302 "));
    Ok(())
}


#[test]
fn a_failed_reload_is_reported_audited_by_the_reload_and_the_loop_goes_on() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let wait = |_interval: Duration| true;
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &failing_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::Stopped);
    assert_eq!(count_of(&actions, "dns-rpz.zone_reload")?, 1);
    assert_eq!(count_of(&actions, "dns-rpz.round_failed")?, 0);
    assert!(String::from_utf8(report)?.contains("failed reload"));
    Ok(())
}


#[test]
fn the_interval_is_read_live_from_the_service_file() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let durations = Mutex::new(Vec::new());
    let calls = AtomicUsize::new(0);
    let service_file = dir.path().join("service.yaml");
    let settings = settings_engine(dir.path())?;
    let wait = |interval: Duration| {
        if let Ok(mut list) = durations.lock() {
            list.push(interval);
        }
        let call = calls.fetch_add(1, Ordering::SeqCst);
        call > 0
            || replace_file(&service_file, &service_text(dir.path(), LONGER_INTERVAL)).is_err()
            || !matches!(reload(&settings), ReloadOutcome::Applied { .. })
    };
    let mut report = Vec::new();
    drive(
        dir.path(),
        &settings,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    let seen = durations.lock().map_err(|_| ServiceError::Changed)?.clone();
    assert_eq!(seen, vec![Duration::from_secs(INTERVAL), Duration::from_secs(LONGER_INTERVAL)]);
    assert_eq!(current_config(&settings).interval_seconds, LONGER_INTERVAL);
    Ok(())
}


#[test]
fn an_audit_sink_that_fails_does_not_stop_the_loop() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    fs::remove_file(dir.path().join("iocs.jsonl"))?;
    let failing: Box<SharedAuditFn> = Box::new(|_entry| Err(AuditError::LogPoisoned));
    let wait = |_interval: Duration| true;
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*failing,
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::Stopped);
    assert!(String::from_utf8(report)?.contains("failed "));
    Ok(())
}


#[test]
fn a_report_that_cannot_be_written_ends_the_loop_with_an_error() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let wait = |_interval: Duration| true;
    let mut report = LimitedWriter { remaining: 0 };
    let result = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    );
    assert!(matches!(result, Err(ServiceError::Io(_))));
    Ok(())
}


#[test]
fn run_round_names_which_step_failed() -> TestResult {
    logging::init_logging();
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let policy = engine_for(&dir.path().join("policy.yaml"))?;
    let rejected = AtomicU64::new(0);
    let zone_context = context();
    let sink = audit();
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let ioc_path = dir.path().join("iocs.jsonl");
    let spec = ioc_path.display().to_string();
    let open = open_source(&spec, &rejected);
    let outcome = |runner: &RunnerFn| -> Result<RoundOutcome, std::io::Error> {
        let zone_path = dir.path().join("zone.db");
        let reloader = Reloader {
            runner,
            readback: &|program: &str, arguments: &[String], deadline: Duration| simulated_readback(runner, &zone_path, program, arguments, deadline),
            audit: &*sink,
            context: &zone_context,
        };
        let mut report = Vec::new();
        let mut session = Session {
            engine: &policy,
            clock: &now,
            open: &*open,
            rejected: &rejected,
            counter: &counter,
            output: &zone,
            report: &mut report,
            reloader: &reloader,
        };
        run_round(&mut session)
    };
    assert_eq!(outcome(&succeeding_runner)?, RoundOutcome::Published);
    assert_eq!(outcome(&failing_runner)?, RoundOutcome::ReloadFailed);
    fs::remove_file(&ioc_path)?;
    assert_eq!(outcome(&succeeding_runner)?, RoundOutcome::GenerationFailed);
    Ok(())
}


#[test]
fn the_service_settings_are_read_and_validated() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    replace_file(&file, &service_text(dir.path(), INTERVAL))?;
    let settings = read_service_settings(&file)?;
    assert_eq!(settings.interval_seconds, INTERVAL);
    assert!(invalid_settings(&settings).is_empty());
    validate_settings(&settings)?;
    assert!(settings_state(&settings).keys().all(|key| key.starts_with("rpz-service.")));
    Ok(())
}


#[test]
fn every_invalid_setting_is_named() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    replace_file(&file, &service_text(dir.path(), INTERVAL))?;
    let good = read_service_settings(&file)?;
    let cases = [
        (
            "policy_file",
            dns_rpz::model::ServiceSettings {
                policy_file: "policy.yaml".to_owned(),
                ..good.clone()
            },
        ),
        (
            "audit_file",
            dns_rpz::model::ServiceSettings {
                audit_file: String::new(),
                ..good.clone()
            },
        ),
        (
            "ioc_source",
            dns_rpz::model::ServiceSettings {
                ioc_source: "clickhouse:feeds.yaml".to_owned(),
                ..good.clone()
            },
        ),
        (
            "ioc_source",
            dns_rpz::model::ServiceSettings {
                ioc_source: "iocs.jsonl".to_owned(),
                ..good.clone()
            },
        ),
        (
            "counter_file",
            dns_rpz::model::ServiceSettings {
                counter_file: "/".to_owned(),
                ..good.clone()
            },
        ),
        (
            "zone_file",
            dns_rpz::model::ServiceSettings {
                zone_file: "zone.db".to_owned(),
                ..good.clone()
            },
        ),
        (
            "interval_seconds",
            dns_rpz::model::ServiceSettings {
                interval_seconds: TOO_SHORT,
                ..good.clone()
            },
        ),
        (
            "interval_seconds",
            dns_rpz::model::ServiceSettings {
                interval_seconds: TOO_LONG,
                ..good.clone()
            },
        ),
        (
            "interval_seconds",
            dns_rpz::model::ServiceSettings {
                interval_seconds: 0,
                ..good.clone()
            },
        ),
    ];
    for (name, settings) in cases {
        assert_eq!(invalid_settings(&settings), vec![name]);
        assert!(matches!(validate_settings(&settings), Err(ServiceError::Invalid(text)) if text == name));
    }
    let clickhouse = dns_rpz::model::ServiceSettings {
        ioc_source: "clickhouse:/etc/ostyr/feeds.yaml".to_owned(),
        ..good
    };
    assert!(invalid_settings(&clickhouse).is_empty());
    Ok(())
}


#[test]
fn a_file_outside_the_allowlist_or_the_schema_is_refused() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    let good = service_text(dir.path(), INTERVAL);
    let hostile = [
        format!("{good}extra: 1\n"),
        good.replace("interval_seconds: 60", "interval_seconds: !!int 60"),
        good.replace("policy_file:", "base: &anchor 1\npolicy_file:"),
        format!("{good}other: *anchor\n"),
        format!("{good}<<: 1\n"),
        good.replace("/policy.yaml", "/po\\u006cicy.yaml"),
        good.replace("zone_file:", "# comment\nzone_file:"),
        good.replace("zone_file: ", "zone_file: \""),
        good.replace("zone_file: ", "zone_file: |\n  "),
        good.replace('\n', "\r"),
        good.replace("audit_file: ", "audit_file:\t"),
    ];
    for text in hostile {
        replace_file(&file, &text)?;
        let message = read_service_settings(&file).err().map(|error| error.to_string());
        assert!(message.is_some(), "{text}");
    }
    replace_file(&file, &good.replace("audit_file", "audit_path"))?;
    assert!(read_service_settings(&file).is_err());
    replace_file(
        &file,
        &good.lines().filter(|line| !line.starts_with("audit_file")).collect::<Vec<_>>().join("\n"),
    )?;
    assert!(read_service_settings(&file).is_err());
    replace_file(&file, &format!("{good}{}", " ".repeat(BIG_FILE)))?;
    assert!(read_service_settings(&file).is_err());
    assert!(check_allowlist(b"a: b\n", "x").is_ok());
    assert!(check_allowlist(b"a: \"b\"\n", "x").is_err());
    Ok(())
}


#[test]
fn only_the_interval_is_live_the_rest_is_pinned() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    let good = service_text(dir.path(), INTERVAL);
    replace_file(&file, &good)?;
    let first = read_service_settings(&file)?;
    let engine = open_settings_engine(file.clone(), &first, audit(), context())?;
    let pinned = ["policy_file", "audit_file", "ioc_source", "counter_file", "zone_file"];
    for name in pinned {
        let moved = good.replace(
            &format!("{name}: {}", dir.path().display()),
            &format!("{name}: {}/moved", dir.path().display()),
        );
        replace_file(&file, &moved)?;
        assert!(
            matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(name)),
            "{name}"
        );
        assert_eq!(*current_config(&engine), first);
        let candidate = read_service_settings(&file)?;
        assert_eq!(changed_pinned(&first, &candidate), Some(name));
    }
    replace_file(&file, &good.replace("interval_seconds: 60", "interval_seconds: 5"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).interval_seconds, INTERVAL);
    replace_file(&file, &good)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_file_that_changes_between_the_two_reads_is_refused() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("service.yaml");
    replace_file(&file, &service_text(dir.path(), INTERVAL))?;
    let first = read_service_settings(&file)?;
    replace_file(&file, &service_text(dir.path(), LONGER_INTERVAL))?;
    let result = open_settings_engine(file.clone(), &first, audit(), context());
    assert!(matches!(result, Err(ServiceError::Changed)));
    replace_file(&file, "interval_seconds: 1\n")?;
    assert!(matches!(
        open_settings_engine(file, &first, audit(), context()),
        Err(ServiceError::Settings(_))
    ));
    Ok(())
}


#[test]
fn the_service_runs_only_its_own_control_program() -> TestResult {
    let refused = service_runner("/bin/true", &[], Duration::from_secs(1));
    assert!(refused.err().is_some_and(|error| error.to_string().contains("another control program")));
    let arguments = ["--no-such-option".to_owned()];
    let ran = service_runner("unbound-control", &arguments, Duration::from_secs(INTERVAL));
    assert!(!matches!(ran, Ok(CommandStatus::Success)));
    Ok(())
}


#[test]
fn a_policy_zonefile_other_than_the_service_zone_file_skips_the_round() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    replace_file(
        &dir.path().join("policy.yaml"),
        &policy_text("unbound:\n  zonefile: /var/lib/unbound/other.zone\n"),
    )?;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let wait = |_interval: Duration| true;
    let mut report = Vec::new();
    let end = drive(
        dir.path(),
        &settings_engine(dir.path())?,
        &succeeding_runner,
        &*recording_audit(&actions),
        &wait,
        MANY_ROUNDS,
        &mut report,
    )?;
    assert_eq!(end, LoopEnd::Stopped);
    assert_eq!(count_of(&actions, "dns-rpz.round_failed")?, 1);
    assert_eq!(count_of(&actions, "dns-rpz.zone_reload")?, 0);
    assert!(!dir.path().join("zone.db").exists());
    assert!(!dir.path().join("counter").exists());
    Ok(())
}


#[test]
fn only_a_failure_before_the_reload_has_an_audited_stage() -> TestResult {
    assert_eq!(failed_stage(RoundOutcome::GenerationFailed), Some("generation"));
    assert_eq!(failed_stage(RoundOutcome::ZoneFileMismatch), Some("zone_file"));
    assert_eq!(failed_stage(RoundOutcome::Published), None);
    assert_eq!(failed_stage(RoundOutcome::ReloadFailed), None);
    Ok(())
}


#[test]
fn a_failed_round_entry_names_the_stage_and_the_zone() -> TestResult {
    let entry = round_failed_entry(&service_context("zone", "round"), Path::new("/var/zone.db"), "generation");
    assert_eq!(entry.action, "dns-rpz.round_failed");
    assert_eq!(entry.target, "/var/zone.db");
    assert_eq!(entry.outcome, Outcome::Failure);
    assert_eq!(entry.parameters.get("stage").map(String::as_str), Some("generation"));
    Ok(())
}


#[test]
fn the_exit_codes_tell_the_endings_apart() -> TestResult {
    assert_eq!(format!("{:?}", exit_code(Ok(LoopEnd::Stopped))), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(
        format!("{:?}", exit_code(Ok(LoopEnd::RoundCap))),
        format!("{:?}", ExitCode::from(ROUND_CAP_CODE))
    );
    assert_eq!(format!("{:?}", exit_code(Err(ServiceError::Usage))), format!("{:?}", ExitCode::FAILURE));
    assert_eq!(THRICE, TWICE + 1);
    Ok(())
}


fn round_outcome(dir: &Path, policy_override: Option<&Policy>) -> Result<RoundOutcome, Box<dyn std::error::Error>> {
    logging::init_logging();
    let policy = engine_for(&dir.join("policy.yaml"))?;
    let rejected = AtomicU64::new(0);
    let zone_context = context();
    let sink = audit();
    let counter = dir.join("counter");
    let zone = dir.join("zone.db");
    let spec = dir.join("iocs.jsonl").display().to_string();
    let open = open_source(&spec, &rejected);
    let reloader = Reloader {
        runner: &succeeding_runner,
        readback: &|_: &str, _: &[String], _: Duration| zone_listing(&zone),
        audit: &*sink,
        context: &zone_context,
    };
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &*open,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    match policy_override {
        Some(snapshot) => Ok(run_round_with(&mut session, snapshot)?),
        None => Ok(run_round(&mut session)?),
    }
}


#[cfg(unix)]
fn make_fifo(path: &Path) -> TestResult {
    assert!(std::process::Command::new("mkfifo").arg(path).status()?.success());
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_fifo_or_a_device_behind_the_counter_or_the_source_is_a_failed_round_never_a_hang() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    assert_eq!(round_outcome(dir.path(), None)?, RoundOutcome::Published);
    let counter = dir.path().join("counter");
    fs::remove_file(&counter)?;
    make_fifo(&counter)?;
    assert_eq!(round_outcome(dir.path(), None)?, RoundOutcome::GenerationFailed);
    fs::remove_file(&counter)?;
    std::os::unix::fs::symlink("/dev/zero", &counter)?;
    assert_eq!(round_outcome(dir.path(), None)?, RoundOutcome::GenerationFailed);
    fs::remove_file(&counter)?;
    let source = dir.path().join("iocs.jsonl");
    fs::remove_file(&source)?;
    make_fifo(&source)?;
    assert_eq!(round_outcome(dir.path(), None)?, RoundOutcome::GenerationFailed);
    fs::remove_file(&source)?;
    std::os::unix::fs::symlink("/dev/zero", &source)?;
    assert_eq!(round_outcome(dir.path(), None)?, RoundOutcome::GenerationFailed);
    Ok(())
}


#[test]
fn a_round_uses_the_policy_snapshot_it_is_given() -> TestResult {
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let mut snapshot = sample_policy();
    snapshot.zone = "snapshot.example.net".to_owned();
    snapshot.unbound.zonefile = dir.path().join("zone.db").display().to_string();
    round_outcome(dir.path(), Some(&snapshot))?;
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains("$ORIGIN snapshot.example.net."));
    assert!(zone_file_matches(&snapshot, &dir.path().join("zone.db")));
    assert!(!zone_file_matches(&snapshot, &dir.path().join("other.db")));
    Ok(())
}


#[test]
fn the_service_reads_back_only_through_its_own_control_program() -> TestResult {
    let refused = service_readback("/bin/true", &[], Duration::from_secs(1));
    assert!(refused.err().is_some_and(|error| error.to_string().contains("another control program")));
    let arguments = ["--no-such-option".to_owned()];
    assert!(service_readback("unbound-control", &arguments, Duration::from_secs(INTERVAL)).is_err());
    Ok(())
}


#[test]
fn a_round_takes_one_snapshot_for_the_zone_check_and_the_generation() -> TestResult {
    logging::init_logging();
    let dir = tempdir()?;
    write_files(dir.path(), "first.example.com", INTERVAL)?;
    let zone = dir.path().join("zone.db");
    let policy = engine_for(&dir.path().join("policy.yaml"))?;
    let mut draft = sample_policy();
    draft.zone = "snapshot.example.net".to_owned();
    draft.unbound.zonefile = zone.display().to_string();
    let snapshot = Arc::new(draft);
    let reads = AtomicUsize::new(0);
    let reader = |_engine: &ReloadEngine<Policy>| {
        reads.fetch_add(1, Ordering::SeqCst);
        Arc::clone(&snapshot)
    };
    let rejected = AtomicU64::new(0);
    let zone_context = context();
    let sink = audit();
    let counter = dir.path().join("counter");
    let spec = dir.path().join("iocs.jsonl").display().to_string();
    let open = open_source(&spec, &rejected);
    let reloader = Reloader {
        runner: &succeeding_runner,
        readback: &|_: &str, _: &[String], _: Duration| zone_listing(&zone),
        audit: &*sink,
        context: &zone_context,
    };
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &*open,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    let settings = settings_engine(dir.path())?;
    let failure_context = service_context("zone", "round");
    let round_loop = RoundLoop {
        settings: &settings,
        audit: &*sink,
        context: &failure_context,
    };
    assert!(one_round(&mut session, &round_loop, &|_interval: Duration| true, 1, &reader)?);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(fs::read_to_string(&zone)?.contains("$ORIGIN snapshot.example.net."));
    Ok(())
}


#[test]
fn service_context_audits_under_the_platform_tenant() -> TestResult {
    assert_eq!(service_context("zone", "round").tenant, PLATFORM_TENANT);
    Ok(())
}

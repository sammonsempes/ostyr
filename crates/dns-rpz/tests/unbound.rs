#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/runner.rs"]
mod runner;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use dns_rpz::error::{PolicyError, ReloadError};
use dns_rpz::limits::{MAX_CAPTURE_BYTES, NEW_ZONE_ON_DISK};
use dns_rpz::model::{Capture, CommandStatus, ReloadVerdict, Reloader};
use dns_rpz::policy::{validate_policy, Action, Policy};
use dns_rpz::types::{ReadbackFn, RunnerFn};
use dns_rpz::unbound::{
    captured_text, reaped, reload_zone, render_unbound_config, run_capture, run_readback, run_reload, run_with_deadline, served_serial,
};
#[cfg(unix)]
use dns_rpz::unbound::{group_kill_result, run_capture_with};
use fixtures::fixture;
use logging::init_logging;
use runner::{failing_runner, succeeding_runner};
#[cfg(unix)]
use rustix::io::Errno;
use sample::sample_policy;
use std::fs;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const SHORT_DEADLINE: Duration = Duration::from_millis(50);


const LONG_DEADLINE: Duration = Duration::from_secs(60);


#[cfg(unix)]
const INSTANT_DEADLINE: Duration = Duration::from_millis(1);


#[cfg(unix)]
const LEADER_SLEEP_SECONDS: &str = "600";


const OVER_TIMEOUT: u64 = 301;


const OVER_SETTING: usize = 5_000;


const DEFAULT_SECONDS: u64 = 10;


const POLICY_ZONE: &str = "rpz.example.org.";


const SERIAL_SEVEN: u32 = 7;


const SERIAL_NINE: u32 = 9;


const INVALID_BYTE: u8 = 0xff;


const CAPTURE_FACTOR: u64 = 2;


const NEW_SERIAL: u32 = 2_026_110_301;


const POLLS: usize = 200;


const POLL_PAUSE: Duration = Duration::from_millis(25);


const BROKEN_CASES: usize = 8;


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "dns-rpz".to_owned(),
        tenant: "example".to_owned(),
        module: "dns-rpz".to_owned(),
        target: "rpz.example.org".to_owned(),
        request_id: "dns-rpz-zone-reload".to_owned(),
    }
}


struct Shared(Arc<Mutex<Vec<u8>>>);


impl Write for Shared {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn timing_out_runner(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Ok(CommandStatus::TimedOut)
}


fn broken_runner(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Err(io::Error::from(io::ErrorKind::NotFound))
}


fn echoing_runner(program: &str, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    let text = format!("{program} {} {}", arguments.join(" "), deadline.as_secs());
    Ok(CommandStatus::Failed(i32::try_from(text.len()).ok()))
}


fn with_override(action: Option<Action>) -> Policy {
    let mut policy = sample_policy();
    policy.unbound.action_override = action;
    policy
}


#[test]
fn the_default_block_matches_the_golden_snapshot() -> TestResult {
    let mut policy = sample_policy();
    policy.unbound.action_override = Some(Action::Cname("sinkhole.example.org".to_owned()));
    policy.unbound.log_name = Some("ostyr-rpz".to_owned());
    assert_eq!(render_unbound_config(&policy), fs::read_to_string(fixture("expected.unbound.conf"))?);
    Ok(())
}


#[test]
fn each_override_and_the_default_log_name_are_rendered() -> TestResult {
    let plain = render_unbound_config(&with_override(None));
    assert!(
        !plain.contains("override") && plain.contains("rpz-log-name: \"rpz.example.org\""),
        "{plain}"
    );
    for (action, word) in [(Action::Nxdomain, "nxdomain"), (Action::Nodata, "nodata"), (Action::Passthru, "passthru")] {
        let text = render_unbound_config(&with_override(Some(action)));
        assert!(
            text.contains(&format!("    rpz-action-override: {word}\n")) && !text.contains("cname"),
            "{text}"
        );
    }
    Ok(())
}


#[test]
fn the_runner_gets_the_command_the_zone_and_the_deadline() -> TestResult {
    let mut policy = sample_policy();
    policy.unbound.command = "/usr/sbin/unbound-control".to_owned();
    let text = "/usr/sbin/unbound-control auth_zone_reload rpz.example.org 10".len();
    assert!(matches!(run_reload(&policy, &echoing_runner), Err(ReloadError::Failed(Some(code))) if usize::try_from(code)? == text));
    Ok(())
}


#[test]
fn the_runner_outcomes_map_to_results() -> TestResult {
    let policy = sample_policy();
    assert!(run_reload(&policy, &succeeding_runner).is_ok());
    assert!(matches!(run_reload(&policy, &failing_runner), Err(ReloadError::Failed(Some(1)))));
    assert!(matches!(
        run_reload(&policy, &timing_out_runner),
        Err(ReloadError::TimedOut(DEFAULT_SECONDS))
    ));
    assert!(matches!(run_reload(&policy, &broken_runner), Err(ReloadError::Io(_))));
    Ok(())
}


fn listing_of(serial: &'static str) -> impl Fn(&str, &[String], Duration) -> io::Result<String> {
    move |_program, _arguments, _deadline| Ok(format!("other.example.\tserial 7\n{POLICY_ZONE}\tserial {serial}\n"))
}


fn failing_readback(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<String> {
    Err(io::Error::other("no answer"))
}


fn reload_text(runner: &RunnerFn, readback: &ReadbackFn) -> Result<(ReloadVerdict, String), Box<dyn std::error::Error>> {
    init_logging();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let log = genesis_log(Shared(Arc::clone(&buffer)));
    let audit = move |entry| append(&log, entry);
    let zone_context = context();
    let verdict = reload_zone(
        &sample_policy(),
        &Reloader {
            runner,
            readback,
            audit: &audit,
            context: &zone_context,
        },
        NEW_SERIAL,
    );
    let written = buffer.lock().unwrap_or_else(PoisonError::into_inner).clone();
    Ok((verdict, String::from_utf8(written)?))
}


#[test]
fn the_audited_outcome_is_the_one_read_back_from_unbound() -> TestResult {
    let (verdict_first, text_first) = reload_text(&succeeding_runner, &listing_of("2026110301"))?;
    assert_eq!(verdict_first, ReloadVerdict::Applied);
    assert!(
        text_first.contains("dns-rpz.zone_reload") && text_first.contains("applied: Unbound serves serial 2026110301"),
        "{text_first}"
    );
    let (verdict_second, text_second) = reload_text(&timing_out_runner, &listing_of("2026110301"))?;
    assert_eq!(
        verdict_second,
        ReloadVerdict::Applied,
        "a late reload is applied, whatever the command said"
    );
    assert!(
        text_second.contains("applied:") && text_second.contains("did not finish"),
        "{text_second}"
    );
    let (verdict_third, text_third) = reload_text(&failing_runner, &listing_of("2026110301"))?;
    assert_eq!(verdict_third, ReloadVerdict::Applied);
    assert!(text_third.contains("failed with status"), "{text_third}");
    Ok(())
}


#[test]
fn an_old_or_missing_serial_is_failed_and_never_claims_the_previous_zone_serves() -> TestResult {
    let (verdict_first, text_first) = reload_text(&succeeding_runner, &listing_of("2026110200"))?;
    assert_eq!(verdict_first, ReloadVerdict::Failed);
    assert!(
        text_first.contains("failed: Unbound serves serial 2026110200, not 2026110301"),
        "{text_first}"
    );
    assert!(
        text_first.contains(NEW_ZONE_ON_DISK) && !text_first.contains("keeps serving"),
        "{text_first}"
    );
    let (verdict_second, text_second) = reload_text(&timing_out_runner, &|_: &str, _: &[String], _: Duration| {
        Ok("other.example.\tserial 7\n".to_owned())
    })?;
    assert_eq!(verdict_second, ReloadVerdict::Failed);
    assert!(text_second.contains("lists no serial for the zone"), "{text_second}");
    Ok(())
}


#[test]
fn no_answer_from_unbound_is_unknown_and_audited_as_such() -> TestResult {
    let (verdict, text) = reload_text(&succeeding_runner, &failing_readback)?;
    assert_eq!(verdict, ReloadVerdict::Unknown);
    assert!(text.contains("unknown: the served serial could not be read: no answer"), "{text}");
    assert!(text.contains(NEW_ZONE_ON_DISK) && !text.contains("keeps serving"), "{text}");
    Ok(())
}


#[test]
fn an_audit_failure_does_not_hide_the_reload_result() -> TestResult {
    init_logging();
    let audit = |_entry| Err(AuditError::LogPoisoned);
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        readback: &listing_of("2026110301"),
        audit: &audit,
        context: &zone_context,
    };
    assert_eq!(reload_zone(&sample_policy(), &reloader, NEW_SERIAL), ReloadVerdict::Applied);
    Ok(())
}


#[test]
fn the_served_serial_is_read_by_zone_name_only() -> TestResult {
    let listing = "\nother.example.\tserial 7\nRPZ.example.org.\tserial 9\tfetch\nbare.example.\nnoserial.example.\tserial\nbad.example.\tserial x\n";
    assert_eq!(served_serial(listing, "rpz.example.org"), Some(SERIAL_NINE));
    assert_eq!(served_serial(listing, "rpz.example.org."), Some(SERIAL_NINE));
    assert_eq!(served_serial(listing, "other.example"), Some(SERIAL_SEVEN));
    assert_eq!(served_serial(listing, "bare.example"), None);
    assert_eq!(served_serial(listing, "noserial.example"), None);
    assert_eq!(served_serial(listing, "bad.example"), None);
    assert_eq!(served_serial(listing, "absent.example"), None);
    assert_eq!(served_serial("", "rpz.example.org"), None);
    Ok(())
}


fn captured(status: CommandStatus, output: Vec<u8>, cut: bool) -> Capture {
    Capture { status, output, cut }
}


#[test]
fn captured_text_names_each_way_a_command_can_end() -> TestResult {
    assert_eq!(
        captured_text(captured(CommandStatus::Success, b"abc".to_vec(), false)).ok().as_deref(),
        Some("abc")
    );
    assert!(captured_text(captured(CommandStatus::Success, vec![INVALID_BYTE], false)).is_err());
    assert!(captured_text(captured(CommandStatus::Failed(Some(1)), Vec::new(), false))
        .is_err_and(|error| error.to_string().contains("failed with status")));
    assert!(captured_text(captured(CommandStatus::TimedOut, Vec::new(), false)).is_err_and(|error| error.kind() == io::ErrorKind::TimedOut));
    Ok(())
}


#[test]
fn a_cut_listing_is_a_named_cut_never_a_listing_without_a_serial() -> TestResult {
    let failure = captured_text(captured(CommandStatus::Success, b"rpz.example.org.\tserial 7\n".to_vec(), true)).err();
    assert!(failure.is_some_and(|cause| cause.to_string() == format!("read-back cut at {MAX_CAPTURE_BYTES} bytes")));
    let arguments = ["-c".to_owned(), (MAX_CAPTURE_BYTES * CAPTURE_FACTOR).to_string(), "/dev/zero".to_owned()];
    assert!(run_readback("head", &arguments, LONG_DEADLINE).is_err_and(|error| error.to_string().contains("read-back cut at")));
    Ok(())
}


#[test]
fn an_oversized_read_back_is_unknown_with_the_named_reason() -> TestResult {
    let oversized = |_program: &str, _arguments: &[String], deadline: Duration| {
        run_readback(
            "head",
            &["-c".to_owned(), (MAX_CAPTURE_BYTES * CAPTURE_FACTOR).to_string(), "/dev/zero".to_owned()],
            deadline,
        )
    };
    let verdict = reload_text(&succeeding_runner, &oversized)?;
    assert_eq!(verdict.0, ReloadVerdict::Unknown);
    assert!(
        verdict.1.contains(&format!("read-back cut at {MAX_CAPTURE_BYTES} bytes")),
        "{}",
        verdict.1
    );
    assert!(!verdict.1.contains("lists no serial"));
    Ok(())
}


#[test]
fn a_leader_not_reaped_after_the_kill_is_an_error() -> TestResult {
    assert!(reaped(None).is_err_and(|error| error.kind() == io::ErrorKind::TimedOut));
    assert!(reaped(Some(std::process::ExitStatus::default())).is_ok());
    Ok(())
}


#[test]
fn the_real_readback_returns_standard_output_and_names_failures() -> TestResult {
    assert_eq!(run_readback("echo", &["hello".to_owned()], LONG_DEADLINE)?, "hello\n");
    assert!(run_readback("false", &[], LONG_DEADLINE).is_err());
    assert!(run_readback("sleep", &["600".to_owned()], SHORT_DEADLINE).is_err_and(|error| error.kind() == io::ErrorKind::TimedOut));
    Ok(())
}


#[test]
fn a_capture_is_cut_at_the_cap() -> TestResult {
    let arguments = ["-c".to_owned(), (MAX_CAPTURE_BYTES * CAPTURE_FACTOR).to_string(), "/dev/zero".to_owned()];
    let capture = run_capture("head", &arguments, LONG_DEADLINE)?;
    assert_eq!(capture.status, CommandStatus::Success);
    assert_eq!(capture.output.len() as u64, MAX_CAPTURE_BYTES);
    assert!(capture.cut);
    let exact = ["-c".to_owned(), MAX_CAPTURE_BYTES.to_string(), "/dev/zero".to_owned()];
    assert!(!run_capture("head", &exact, LONG_DEADLINE)?.cut);
    Ok(())
}


#[test]
fn a_descendant_left_behind_by_the_command_is_killed_with_its_group() -> TestResult {
    let dir = tempdir()?;
    let script = dir.path().join("wrapper.sh");
    let pid_file = dir.path().join("child.pid");
    fs::write(&script, "sleep 600 > /dev/null 2>&1 &\necho $! > \"$1\"\n")?;
    let arguments = [script.display().to_string(), pid_file.display().to_string()];
    assert_eq!(run_with_deadline("bash", &arguments, LONG_DEADLINE)?, CommandStatus::Success);
    let child_pid = fs::read_to_string(&pid_file)?.trim().to_owned();
    let stat = format!("/proc/{child_pid}/stat");
    let gone = (0..POLLS).any(|_| {
        std::thread::sleep(POLL_PAUSE);
        fs::read_to_string(&stat).map_or(true, |text| text.contains(") Z "))
    });
    assert!(gone, "the background child of the wrapper is still running");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_group_that_is_already_empty_is_not_an_error_but_any_other_failure_is() -> TestResult {
    assert!(group_kill_result(Ok(())).is_ok());
    assert!(group_kill_result(Err(Errno::SRCH)).is_ok());
    assert!(group_kill_result(Err(Errno::PERM)).is_err());
    Ok(())
}


#[test]
fn the_real_runner_reports_success_failure_and_a_missing_command() -> TestResult {
    assert_eq!(run_with_deadline("true", &[], LONG_DEADLINE)?, CommandStatus::Success);
    assert_eq!(run_with_deadline("false", &[], LONG_DEADLINE)?, CommandStatus::Failed(Some(1)));
    assert!(run_with_deadline("/nonexistent/unbound-control", &[], LONG_DEADLINE).is_err());
    Ok(())
}


#[test]
fn a_leader_that_left_its_group_is_killed_at_the_deadline() -> TestResult {
    let script = "setpgrp(0, getpgrp(getppid())); exec 'sleep', '600';".to_owned();
    let arguments = ["-e".to_owned(), script];
    assert_eq!(run_with_deadline("perl", &arguments, SHORT_DEADLINE)?, CommandStatus::TimedOut);
    Ok(())
}


#[test]
fn the_real_runner_kills_a_command_past_its_deadline() -> TestResult {
    assert_eq!(run_with_deadline("sleep", &["600".to_owned()], SHORT_DEADLINE)?, CommandStatus::TimedOut);
    Ok(())
}


#[test]
fn unacceptable_unbound_settings_are_refused() -> TestResult {
    let broken: [fn(&mut Policy); BROKEN_CASES] = [
        |policy| policy.unbound.command = String::new(),
        |policy| policy.unbound.zonefile = "/etc/\"x\"".to_owned(),
        |policy| policy.unbound.zonefile = "/etc/a\nb".to_owned(),
        |policy| policy.unbound.zonefile = "a".repeat(OVER_SETTING),
        |policy| policy.unbound.log_name = Some("back\\slash".to_owned()),
        |policy| policy.unbound.timeout_seconds = 0,
        |policy| policy.unbound.timeout_seconds = OVER_TIMEOUT,
        |policy| policy.unbound.action_override = Some(Action::Cname("Not.Canonical".to_owned())),
    ];
    for change in broken {
        let mut policy = sample_policy();
        change(&mut policy);
        assert!(validate_policy(&policy).is_err());
    }
    let mut policy = sample_policy();
    policy.unbound.timeout_seconds = 0;
    assert!(matches!(validate_policy(&policy), Err(PolicyError::Setting(_))));
    let mut accepted = with_override(Some(Action::Nodata));
    accepted.unbound.log_name = Some("ostyr".to_owned());
    validate_policy(&accepted)?;
    Ok(())
}


#[cfg(unix)]
fn failing_group_kill(child: &mut std::process::Child) -> io::Result<()> {
    Err(io::Error::other(format!("group kill refused for {}", child.id())))
}


#[cfg(unix)]
#[test]
fn a_failed_group_kill_still_kills_and_reaps_the_leader_then_reports_its_error() -> TestResult {
    let arguments = [LEADER_SLEEP_SECONDS.to_owned()];
    let result = run_capture_with("sleep", &arguments, INSTANT_DEADLINE, failing_group_kill);
    let message = result
        .err()
        .map(|error| error.to_string())
        .ok_or("the failed group kill was not reported")?;
    let leader_pid = message
        .strip_prefix("group kill refused for ")
        .ok_or("the group kill error was replaced")?
        .parse::<i32>()?;
    let leader = rustix::process::Pid::from_raw(leader_pid).ok_or("the leader pid is invalid")?;
    assert_eq!(
        rustix::process::test_kill_process(leader),
        Err(Errno::SRCH),
        "the leader {leader_pid} was left running or unreaped"
    );
    Ok(())
}

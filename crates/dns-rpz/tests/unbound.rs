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
use dns_rpz::model::{CommandStatus, Reloader};
use dns_rpz::policy::{validate_policy, Action, Policy};
use dns_rpz::unbound::{reload_zone, render_unbound_config, run_reload, run_with_deadline};
use fixtures::fixture;
use logging::init_logging;
use runner::{failing_runner, succeeding_runner};
use sample::sample_policy;
use std::fs;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use types::TestResult;


const SHORT_DEADLINE: Duration = Duration::from_millis(50);


const LONG_DEADLINE: Duration = Duration::from_secs(60);


const OVER_TIMEOUT: u64 = 301;


const OVER_SETTING: usize = 5_000;


const DEFAULT_SECONDS: u64 = 10;


const TWICE: usize = 2;


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


#[test]
fn a_reload_is_logged_and_audited_whatever_the_result() -> TestResult {
    init_logging();
    let policy = sample_policy();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let log = genesis_log(Shared(Arc::clone(&buffer)));
    let audit = move |entry| append(&log, entry);
    let zone_context = context();
    let reload_with = |runner| {
        reload_zone(
            &policy,
            &Reloader {
                runner,
                audit: &audit,
                context: &zone_context,
            },
        )
    };
    assert!(reload_with(&succeeding_runner).is_ok());
    assert!(reload_with(&failing_runner).is_err());
    let text = String::from_utf8(buffer.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert_eq!(text.matches("dns-rpz.zone_reload").count(), TWICE, "{text}");
    assert!(text.contains("reloaded") && text.contains("failed with status"), "{text}");
    Ok(())
}


#[test]
fn an_audit_failure_does_not_hide_the_reload_result() -> TestResult {
    init_logging();
    let audit = |_entry| Err(AuditError::LogPoisoned);
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        audit: &audit,
        context: &zone_context,
    };
    assert!(reload_zone(&sample_policy(), &reloader).is_ok());
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

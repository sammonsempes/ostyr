use crate::suite::common::TestResult;
use app_health::error::NtpError;
use app_health::grammar::is_unit_name_with;
use app_health::journal::log_excerpt;
use app_health::model::{ActiveState, LoadState, ServiceResult, ServiceRun, TimerExpectation, TimerHealth, TimerState};
use app_health::timers::{assess_timer, load_timer_expectations, parse_service_result, parse_timer_show, service_unit};
use std::io::Read;


const TIMER: &str = "demo.timer";


const SERVICE: &str = "demo.service";


const MAX_SHOW: u64 = 4096;


const MAX_TIMERS: usize = 512;


const HUGE_VALUE: usize = 10_000_000;


const MAX_AGE: u64 = 3600;


const EPOCH_SECONDS: u64 = 100;


const EXIT_SECONDS: u64 = 5;


const UNKNOWN_TIMER_FIELDS: usize = 2;


const NOW: u64 = 1_800_000_000;


const SKEW: u64 = 300;


const MIN_AGE_LIMIT: u64 = 60;


const MAX_AGE_LIMIT: u64 = 31_536_000;


const LINE_LIMIT: usize = 65_536;


const LOADED_TIMERS: usize = 2;


const LAB_TIMER_OK: &str = include_str!("../fixtures/lab-timer-ok.txt");


const LAB_TIMER_BAD: &str = include_str!("../fixtures/lab-timer-bad.txt");


const LAB_TIMER_NEVER: &str = include_str!("../fixtures/lab-timer-never.txt");


const LAB_TIMER_MISSING: &str = include_str!("../fixtures/lab-timer-missing.txt");


const LAB_TIMER_UNIX: &str = include_str!("../fixtures/lab-timer-unix-ok.txt");


const LAB_SERVICE_OK: &str = include_str!("../fixtures/lab-service-ok.txt");


const LAB_SERVICE_BAD: &str = include_str!("../fixtures/lab-service-bad.txt");


const LAB_SERVICE_NEVER: &str = include_str!("../fixtures/lab-service-never.txt");


const LAB_SERVICE_MISSING: &str = include_str!("../fixtures/lab-service-missing.txt");


const LAB_SERVICE_UNIX: &str = include_str!("../fixtures/lab-service-unix-ok.txt");


const LAB_TRIGGER: u64 = 1_794_518_853;


const LAB_EXIT: u64 = 1_794_518_854;


const LAB_NEXT_2099: u64 = 4_070_908_800;


const UNIX_TRIGGER: u64 = 1_794_442_914;


const UNIX_NEXT: u64 = 1_794_528_636;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


fn timer_show(load: &str, active: &str, last: &str, next: &str) -> String {
    format!("Id={TIMER}\nLoadState={load}\nActiveState={active}\nLastTriggerUSec={last}\nNextElapseUSecRealtime={next}\n")
}


fn service_show(result: &str, status: &str, exit: &str) -> String {
    format!("Id={SERVICE}\nResult={result}\nExecMainStatus={status}\nExecMainExitTimestamp={exit}\n")
}


fn expectation() -> TimerExpectation {
    TimerExpectation {
        timer: TIMER.to_string(),
        service: None,
        max_age_seconds: MAX_AGE,
    }
}


fn timer_state(load: LoadState, active: ActiveState, last: Option<u64>) -> TimerState {
    TimerState {
        load: Some(load),
        active: Some(active),
        last_trigger_unix: last,
        next_elapse_unix: None,
        unknown_values: 0,
    }
}


fn run(result: Option<ServiceResult>, status: u32) -> ServiceRun {
    ServiceRun {
        result,
        exec_main_status: status,
        last_exit_unix: None,
        unknown_values: 0,
    }
}


fn good_run() -> ServiceRun {
    run(Some(ServiceResult::Success), 0)
}


fn good_timer(last: Option<u64>) -> TimerState {
    timer_state(LoadState::Loaded, ActiveState::Active, last)
}


fn malformed<Item>(result: Result<Item, NtpError>, wanted: &str) {
    assert!(matches!(result, Err(NtpError::Malformed { reason }) if reason == wanted), "{wanted}");
}


fn document(count: usize, extra: &str) -> String {
    let item = format!("  - timer: {TIMER}\n    max_age_seconds: {MAX_AGE}\n{extra}");
    format!("timers:\n{}", item.repeat(count))
}


#[test]
fn expectations_load_and_default_the_service() -> TestResult {
    let text = format!("timers:\n  - timer: a.timer\n    max_age_seconds: {MAX_AGE}\n  - timer: b.timer\n    service: other.service\n    max_age_seconds: {MIN_AGE_LIMIT}\n");
    let loaded = load_timer_expectations(&text, "t.yaml")?;
    assert_eq!(loaded.len(), LOADED_TIMERS);
    assert_eq!(loaded.first().map(service_unit).as_deref(), Some("a.service"));
    assert_eq!(loaded.get(1).map(service_unit).as_deref(), Some("other.service"));
    Ok(())
}


#[test]
fn timer_count_is_bounded() -> TestResult {
    assert_eq!(load_timer_expectations(&document(MAX_TIMERS, ""), "t")?.len(), MAX_TIMERS);
    let refused = load_timer_expectations(&document(MAX_TIMERS + 1, ""), "t");
    assert!(matches!(refused, Err(NtpError::OutOfRange { field: "timers" })));
    Ok(())
}


#[test]
fn hostile_expectations_are_refused() -> TestResult {
    let cases = [
        ("  - timer: a.service\n    max_age_seconds: 3600\n", "timer"),
        ("  - timer: \"-x.timer\"\n    max_age_seconds: 3600\n", "timer"),
        ("  - timer: a.timer\n    service: a.timer\n    max_age_seconds: 3600\n", "service"),
        ("  - timer: a.timer\n    service: \"-a.service\"\n    max_age_seconds: 3600\n", "service"),
        ("  - timer: a.timer\n    max_age_seconds: 0\n", "max_age_seconds"),
        ("  - timer: a.timer\n    max_age_seconds: 59\n", "max_age_seconds"),
        ("  - timer: a.timer\n    max_age_seconds: 31536001\n", "max_age_seconds"),
    ];
    cases.iter().for_each(|(item, field)| {
        let result = load_timer_expectations(&format!("timers:\n{item}"), "t");
        assert!(matches!(result, Err(NtpError::OutOfRange { field: got }) if got == *field), "{item}");
    });
    let top = format!("timers:\n  - timer: a.timer\n    max_age_seconds: {MAX_AGE_LIMIT}\n");
    assert_eq!(load_timer_expectations(&top, "t")?.len(), 1);
    Ok(())
}


#[test]
fn unknown_keys_and_oversized_files_are_refused() -> TestResult {
    let extra = document(1, "    extra: 1\n");
    assert!(matches!(load_timer_expectations(&extra, "t"), Err(NtpError::Config(_))));
    let negative = document(1, "").replace(&MAX_AGE.to_string(), "-5");
    assert!(matches!(load_timer_expectations(&negative, "t"), Err(NtpError::Config(_))));
    let huge = format!("{}#{}\n", document(1, ""), "x".repeat(HUGE_VALUE));
    assert!(matches!(load_timer_expectations(&huge, "t"), Err(NtpError::Oversized { .. })));
    Ok(())
}


#[test]
fn suffix_grammar() -> TestResult {
    assert!(is_unit_name_with("a.timer", ".timer"));
    assert!(!is_unit_name_with("a.service", ".timer"));
    assert!(!is_unit_name_with(".timer", ".timer"));
    Ok(())
}


#[test]
fn timer_show_parses_every_form() -> TestResult {
    let parsed = parse_timer_show(timer_show("loaded", "active", "@100", "").as_bytes(), MAX_SHOW, TIMER)?;
    assert_eq!(parsed.last_trigger_unix, Some(EPOCH_SECONDS));
    assert_eq!(parsed.next_elapse_unix, None);
    assert_eq!(
        (parsed.load, parsed.active, parsed.unknown_values),
        (Some(LoadState::Loaded), Some(ActiveState::Active), 0)
    );
    let human = parse_timer_show(
        timer_show("loaded", "active", "Thu 1970-01-01 00:01:40 UTC", "").as_bytes(),
        MAX_SHOW,
        TIMER,
    )?;
    assert_eq!(human.last_trigger_unix, Some(EPOCH_SECONDS));
    Ok(())
}


#[test]
fn unknown_timer_values_are_none_and_counted() -> TestResult {
    let parsed = parse_timer_show(timer_show("weird", "odd", "", "").as_bytes(), MAX_SHOW, TIMER)?;
    assert_eq!((parsed.load, parsed.active, parsed.unknown_values), (None, None, UNKNOWN_TIMER_FIELDS));
    Ok(())
}


#[test]
fn bad_timestamps_are_malformed() -> TestResult {
    let bad = [
        "n/a",
        "@",
        "@-1",
        "@+1",
        "@1.5",
        "@x",
        "100",
        "@99999999999999999999999",
        "Thu 2026-11-12 21:27:33 CET",
        "Thu 1969-12-31 23:59:59 UTC",
    ];
    bad.iter().for_each(|text| {
        malformed(
            parse_timer_show(timer_show("loaded", "active", text, "").as_bytes(), MAX_SHOW, TIMER),
            "bad timestamp",
        );
        let service = service_show("success", "0", text);
        malformed(parse_service_result(service.as_bytes(), MAX_SHOW, SERVICE), "bad timestamp");
    });
    Ok(())
}


#[test]
fn malformed_timer_and_service_shapes() -> TestResult {
    let good = timer_show("loaded", "active", "@1", "@2");
    malformed(
        parse_timer_show(format!("{good}Id={TIMER}\n").as_bytes(), MAX_SHOW, TIMER),
        "duplicate key",
    );
    malformed(
        parse_timer_show(format!("{good}Other=1\n").as_bytes(), MAX_SHOW, TIMER),
        "unexpected line",
    );
    malformed(parse_timer_show(format!("{good}\n").as_bytes(), MAX_SHOW, TIMER), "unexpected line");
    malformed(
        parse_timer_show(good.replace('\n', "\r\n").as_bytes(), MAX_SHOW, TIMER),
        "unexpected line",
    );
    malformed(parse_timer_show(format!("Id={TIMER}\n").as_bytes(), MAX_SHOW, TIMER), "missing key");
    malformed(parse_timer_show(good.as_bytes(), MAX_SHOW, "other.timer"), "unexpected unit");
    let service = service_show("success", "0", "");
    malformed(
        parse_service_result(format!("{service}Id={SERVICE}\n").as_bytes(), MAX_SHOW, SERVICE),
        "duplicate key",
    );
    malformed(parse_service_result(service.as_bytes(), MAX_SHOW, "other.service"), "unexpected unit");
    malformed(
        parse_service_result(service.replace('\n', "\r\n").as_bytes(), MAX_SHOW, SERVICE),
        "unexpected line",
    );
    malformed(
        parse_service_result(timer_show("loaded", "active", "", "").as_bytes(), MAX_SHOW, TIMER),
        "unexpected line",
    );
    Ok(())
}


#[test]
fn service_status_is_digits_only() -> TestResult {
    ["-1", "+1", "", "1.5", "99999999999", "x"].iter().for_each(|bad| {
        malformed(
            parse_service_result(service_show("success", bad, "").as_bytes(), MAX_SHOW, SERVICE),
            "bad counter",
        );
    });
    Ok(())
}


#[test]
fn every_service_result_parses_and_unknown_is_none() -> TestResult {
    let known = [
        ("success", ServiceResult::Success),
        ("protocol", ServiceResult::Protocol),
        ("timeout", ServiceResult::Timeout),
        ("exit-code", ServiceResult::ExitCode),
        ("signal", ServiceResult::Signal),
        ("core-dump", ServiceResult::CoreDump),
        ("watchdog", ServiceResult::Watchdog),
        ("start-limit-hit", ServiceResult::StartLimitHit),
        ("resources", ServiceResult::Resources),
        ("oom-kill", ServiceResult::OomKill),
        ("exec-condition", ServiceResult::ExecCondition),
    ];
    known.iter().try_for_each(|(word, expected)| {
        parse_service_result(service_show(word, "0", "@5").as_bytes(), MAX_SHOW, SERVICE).map(|parsed| {
            assert_eq!(
                (parsed.result, parsed.unknown_values, parsed.last_exit_unix),
                (Some(*expected), 0, Some(EXIT_SECONDS)),
                "{word}"
            );
        })
    })?;
    let unknown = parse_service_result(service_show("mystery", "0", "").as_bytes(), MAX_SHOW, SERVICE)?;
    assert_eq!((unknown.result, unknown.unknown_values), (None, 1));
    Ok(())
}


#[test]
fn oversized_and_unreadable_input_is_refused() -> TestResult {
    let huge = timer_show("loaded", "active", &"a".repeat(HUGE_VALUE), "");
    assert!(matches!(
        parse_timer_show(huge.as_bytes(), MAX_SHOW, TIMER),
        Err(NtpError::Oversized { .. })
    ));
    assert!(matches!(parse_timer_show(FailingReader, MAX_SHOW, TIMER), Err(NtpError::Read(_))));
    assert!(matches!(parse_service_result(FailingReader, MAX_SHOW, SERVICE), Err(NtpError::Read(_))));
    Ok(())
}


#[test]
fn age_boundary_and_never_triggered() -> TestResult {
    let want = expectation();
    let at_limit = good_timer(Some(NOW - MAX_AGE));
    assert_eq!(assess_timer(&want, &at_limit, &good_run(), NOW), TimerHealth::Healthy);
    let past = good_timer(Some(NOW - MAX_AGE - 1));
    assert_eq!(assess_timer(&want, &past, &good_run(), NOW), TimerHealth::Overdue);
    assert_eq!(assess_timer(&want, &good_timer(None), &good_run(), NOW), TimerHealth::Overdue);
    Ok(())
}


#[test]
fn future_trigger_boundary_is_a_blind_spot() -> TestResult {
    let want = expectation();
    let within = good_timer(Some(NOW + SKEW));
    assert_eq!(assess_timer(&want, &within, &good_run(), NOW), TimerHealth::Healthy);
    let beyond = good_timer(Some(NOW + SKEW + 1));
    assert_eq!(assess_timer(&want, &beyond, &good_run(), NOW), TimerHealth::BlindSpot);
    let far = good_timer(Some(u64::MAX));
    assert_eq!(assess_timer(&want, &far, &good_run(), u64::MAX), TimerHealth::Healthy);
    assert_eq!(assess_timer(&want, &far, &good_run(), NOW), TimerHealth::BlindSpot);
    Ok(())
}


#[test]
fn failed_runs_are_never_healthy() -> TestResult {
    let want = expectation();
    let fresh = good_timer(Some(NOW));
    assert_eq!(
        assess_timer(&want, &fresh, &run(Some(ServiceResult::ExitCode), 1), NOW),
        TimerHealth::LastRunFailed
    );
    assert_eq!(
        assess_timer(&want, &fresh, &run(Some(ServiceResult::Success), 1), NOW),
        TimerHealth::LastRunFailed
    );
    assert_eq!(assess_timer(&want, &fresh, &run(None, 0), NOW), TimerHealth::LastRunFailed);
    Ok(())
}


#[test]
fn inactive_and_unknown_active_are_never_healthy() -> TestResult {
    let want = expectation();
    let stopped = timer_state(LoadState::Loaded, ActiveState::Inactive, Some(NOW));
    assert_eq!(assess_timer(&want, &stopped, &good_run(), NOW), TimerHealth::Inactive);
    let mut unknown = good_timer(Some(NOW));
    unknown.active = None;
    assert_eq!(assess_timer(&want, &unknown, &good_run(), NOW), TimerHealth::Inactive);
    Ok(())
}


#[test]
fn precedence_pairs() -> TestResult {
    let want = expectation();
    let old = NOW - MAX_AGE - 1;
    let missing = timer_state(LoadState::NotFound, ActiveState::Inactive, None);
    let failed = run(Some(ServiceResult::ExitCode), 1);
    assert_eq!(assess_timer(&want, &missing, &failed, NOW), TimerHealth::NotFound);
    let stale_failed = timer_state(LoadState::Loaded, ActiveState::Inactive, Some(old));
    assert_eq!(assess_timer(&want, &stale_failed, &failed, NOW), TimerHealth::LastRunFailed);
    assert_eq!(assess_timer(&want, &stale_failed, &good_run(), NOW), TimerHealth::Overdue);
    let future_inactive = timer_state(LoadState::Loaded, ActiveState::Inactive, Some(NOW + SKEW + 1));
    assert_eq!(assess_timer(&want, &future_inactive, &good_run(), NOW), TimerHealth::BlindSpot);
    Ok(())
}


fn lab_health(timer: &str, timer_text: &str, service: &str, service_text: &str) -> Result<TimerHealth, Box<dyn std::error::Error>> {
    let want = TimerExpectation {
        timer: timer.to_string(),
        service: None,
        max_age_seconds: MAX_AGE,
    };
    let timer_state = parse_timer_show(timer_text.as_bytes(), MAX_SHOW, timer)?;
    let service_state = parse_service_result(service_text.as_bytes(), MAX_SHOW, service)?;
    assert_eq!(service_unit(&want), service);
    Ok(assess_timer(&want, &timer_state, &service_state, LAB_TRIGGER + 1))
}


#[test]
fn lab_captures_parse_and_assess() -> TestResult {
    assert_eq!(
        lab_health("ostyr-ok.timer", LAB_TIMER_OK, "ostyr-ok.service", LAB_SERVICE_OK)?,
        TimerHealth::Healthy
    );
    assert_eq!(
        lab_health("ostyr-bad.timer", LAB_TIMER_BAD, "ostyr-bad.service", LAB_SERVICE_BAD)?,
        TimerHealth::LastRunFailed
    );
    assert_eq!(
        lab_health("ostyr-never.timer", LAB_TIMER_NEVER, "ostyr-never.service", LAB_SERVICE_NEVER)?,
        TimerHealth::Overdue
    );
    assert_eq!(
        lab_health("ostyr-missing.timer", LAB_TIMER_MISSING, "ostyr-missing.service", LAB_SERVICE_MISSING)?,
        TimerHealth::NotFound
    );
    let ok = parse_timer_show(LAB_TIMER_OK.as_bytes(), MAX_SHOW, "ostyr-ok.timer")?;
    assert_eq!(ok.last_trigger_unix, Some(LAB_TRIGGER));
    let service = parse_service_result(LAB_SERVICE_OK.as_bytes(), MAX_SHOW, "ostyr-ok.service")?;
    assert_eq!(service.last_exit_unix, Some(LAB_EXIT));
    let never = parse_timer_show(LAB_TIMER_NEVER.as_bytes(), MAX_SHOW, "ostyr-never.timer")?;
    assert_eq!(never.next_elapse_unix, Some(LAB_NEXT_2099));
    Ok(())
}


#[test]
fn lab_unix_timestamp_captures_parse() -> TestResult {
    let timer = parse_timer_show(LAB_TIMER_UNIX.as_bytes(), MAX_SHOW, "logrotate.timer")?;
    assert_eq!((timer.last_trigger_unix, timer.next_elapse_unix), (Some(UNIX_TRIGGER), Some(UNIX_NEXT)));
    let service = parse_service_result(LAB_SERVICE_UNIX.as_bytes(), MAX_SHOW, "logrotate.service")?;
    assert_eq!(service.result, Some(ServiceResult::Success));
    Ok(())
}


const ROCKY_TRIGGER: u64 = 1_794_519_071;


#[test]
fn lab_rocky_captures_match_ubuntu_forms() -> TestResult {
    let health = |name: &str, timer_text: &str, service_text: &str| {
        let want = TimerExpectation {
            timer: format!("ostyr-{name}.timer"),
            service: None,
            max_age_seconds: MAX_AGE,
        };
        let timer = parse_timer_show(timer_text.as_bytes(), MAX_SHOW, &want.timer)?;
        let service = parse_service_result(service_text.as_bytes(), MAX_SHOW, &service_unit(&want))?;
        Ok::<_, NtpError>((assess_timer(&want, &timer, &service, ROCKY_TRIGGER + 1), timer))
    };
    let (ok, timer) = health(
        "ok",
        include_str!("../fixtures/lab-rocky-timer-ok.txt"),
        include_str!("../fixtures/lab-rocky-service-ok.txt"),
    )?;
    assert_eq!((ok, timer.last_trigger_unix), (TimerHealth::Healthy, Some(ROCKY_TRIGGER)));
    let (bad, _) = health(
        "bad",
        include_str!("../fixtures/lab-rocky-timer-bad.txt"),
        include_str!("../fixtures/lab-rocky-service-bad.txt"),
    )?;
    assert_eq!(bad, TimerHealth::LastRunFailed);
    let (never, _) = health(
        "never",
        include_str!("../fixtures/lab-rocky-timer-never.txt"),
        include_str!("../fixtures/lab-rocky-service-never.txt"),
    )?;
    assert_eq!(never, TimerHealth::Overdue);
    let (missing, _) = health(
        "missing",
        include_str!("../fixtures/lab-rocky-timer-missing.txt"),
        include_str!("../fixtures/lab-rocky-service-missing.txt"),
    )?;
    assert_eq!(missing, TimerHealth::NotFound);
    Ok(())
}


#[test]
fn line_cap_has_an_upper_bound() -> TestResult {
    let at_limit = log_excerpt("a\n".as_bytes(), 1, LINE_LIMIT)?;
    assert_eq!(at_limit.lines.len(), 1);
    let refused = log_excerpt("a\n".as_bytes(), 1, LINE_LIMIT + 1);
    assert!(matches!(refused, Err(NtpError::OutOfRange { field: "max_bytes" })));
    Ok(())
}

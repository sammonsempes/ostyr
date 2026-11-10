use crate::support::{append, lines, scoped_logging};
use crate::types::TestResult;
use agent_channel::app::shared_log_audit;
use agent_channel::types::PauseFuture;
use agent_linux::error::{SensorError, SourceError};
use agent_linux::model::SensorSettings;
use agent_linux::sensor::{
    active_state, classify, export_progress, is_bad, monotonic_seconds, observe, parse_show, restart, restart_arguments, restart_entry, run_bounded,
    run_command, run_sensor, run_with_deadline, sensor_event_line, show_arguments, state_name, step, tick, valid_sub_state, Action, ActiveState,
    Observation, Progress, SensorEnv, SensorEvent, SensorState, Supervisor, Unit, HOUR_SECONDS, MAX_EVENTS_PER_HOUR, MAX_OUTPUT_BYTES,
    MIN_RESTART_INTERVAL_SECONDS,
};
use agent_linux::types::RunFuture;
use arc_swap::ArcSwap;
use core_audit::log::open_file_log;
use core_audit::model::Outcome;
use core_config::types::SharedAuditFn;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;


const WINDOW: u64 = 30;


const INTERVAL: u64 = 10;


const TICK: u64 = 10;


const PID: u32 = 7;


const CAP: u64 = 2;


const CAP_LEN: usize = 2;


const FOUR: u64 = 4;


const LONG_SUB: usize = 64;


const OVER_SUB: usize = 33;


const EXPORT_BYTES: u64 = 3;


const FLAPS: u64 = 400;


const NINE: u64 = 9;


const DAY: u64 = 86_400;


const SHORT: Duration = Duration::from_millis(50);


fn stepped(supervisor: &Supervisor, observation: &Observation, now: u64, config: &SensorSettings) -> (Supervisor, Action) {
    step(supervisor, observation, now, now, config)
}


fn settings(max_restarts: u64) -> SensorSettings {
    SensorSettings {
        window_seconds: WINDOW,
        interval_seconds: INTERVAL,
        max_restarts_per_hour: max_restarts,
    }
}


fn show_text(active: &str, pid: u32) -> String {
    format!("ActiveState={active}\nSubState=running\nExecMainPID={pid}\n")
}


fn progress(size: u64) -> Progress {
    Progress {
        ino: 1,
        size,
        mtime: 0,
        mtime_nsec: 0,
    }
}


pub fn fake_run(program: PathBuf, arguments: Vec<String>) -> RunFuture {
    Box::pin(async move {
        match arguments.first().map(String::as_str) {
            Some("show") => Ok(fs::read_to_string(&program)?),
            _ => {
                append(&program.with_extension("starts"), "x\n")?;
                if program.with_extension("fail").exists() {
                    Err(SensorError::Exit(Some(1)))
                } else {
                    Ok(String::new())
                }
            }
        }
    })
}


fn environment(dir: &Path) -> SensorEnv {
    SensorEnv {
        systemctl: dir.join("show"),
        export: dir.join("export.json"),
        spool: dir.join("spool"),
        tenant: "t1".to_owned(),
        run: fake_run,
    }
}


fn start_count(dir: &Path) -> usize {
    fs::read_to_string(dir.join("show.starts")).map_or(0, |text| text.lines().count())
}


fn event_states(path: &Path) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    lines(path)?
        .iter()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)?;
            let sensor = value.pointer("/agent/sensor").ok_or("no sensor field")?;
            let field = |name: &str| sensor.get(name).and_then(|text| text.as_str()).unwrap_or("").to_owned();
            Ok((field("state"), field("previous")))
        })
        .collect()
}


#[test]
fn show_output_is_parsed_strictly() -> TestResult {
    let unit = parse_show(&show_text("active", PID))?;
    assert_eq!(
        unit,
        Unit {
            active: ActiveState::Active,
            sub_state: "running".to_owned(),
            pid: PID
        }
    );
    assert!(parse_show("ExecMainPID=1\nSubState=dead\nActiveState=inactive\n").is_ok());
    let bad = [
        "",
        "ActiveState=active\nSubState=running\n",
        "ActiveState=active\nSubState=running\nExecMainPID=1\nExecMainPID=2\n",
        "ActiveState=active\nSubState=running\nExecMainPID=1\nOther=1\n",
        "ActiveState=active\nSubState=running\nExecMainPID=1\nnoequals\n",
        "ActiveState=weird\nSubState=running\nExecMainPID=1\n",
        "ActiveState=active\nSubState=run ning\nExecMainPID=1\n",
        "ActiveState=active\nSubState=\nExecMainPID=1\n",
        "ActiveState=active\nSubState=running\nExecMainPID=-1\n",
        "ActiveState=active\nSubState=running\nExecMainPID=99999999999\n",
        "ActiveState=active\nSubState=running\nExecMainPID=0x1\n",
        "ActiveState=active\nSubState=running\nOther=1\n",
        "SubState=running\nExecMainPID=1\nOther=1\n",
    ];
    bad.iter()
        .for_each(|text| assert!(matches!(parse_show(text), Err(SensorError::Parse)), "{text}"));
    let long = format!("ActiveState=active\nSubState={}\nExecMainPID=1\n", "a".repeat(LONG_SUB));
    assert!(parse_show(&long).is_err());
    assert!(!valid_sub_state(&"b".repeat(OVER_SUB)));
    assert!(valid_sub_state("start-pre"));
    Ok(())
}


#[test]
fn active_states_and_names() -> TestResult {
    assert_eq!(active_state("active")?, ActiveState::Active);
    ["inactive", "failed", "deactivating"]
        .iter()
        .try_for_each(|name| active_state(name).map(|state| assert_eq!(state, ActiveState::Down)))?;
    ["activating", "reloading", "maintenance", "refreshing"]
        .iter()
        .try_for_each(|name| active_state(name).map(|state| assert_eq!(state, ActiveState::Transitional)))?;
    assert!(active_state("x").is_err());
    let names = [SensorState::Unknown, SensorState::Running, SensorState::Stopped, SensorState::Stalled].map(state_name);
    assert_eq!(names, ["unknown", "running", "stopped", "stalled"]);
    assert!(is_bad(SensorState::Stopped) && is_bad(SensorState::Stalled));
    assert!(!is_bad(SensorState::Running) && !is_bad(SensorState::Unknown));
    assert_eq!(show_arguments().first().map(String::as_str), Some("show"));
    assert_eq!(restart_arguments(), vec!["restart".to_owned(), "tetragon.service".to_owned()]);
    Ok(())
}


#[test]
fn a_unit_is_classified_down_up_or_unknown() -> TestResult {
    let unit = |active, pid| Unit {
        active,
        sub_state: "x".to_owned(),
        pid,
    };
    let seen = Some(progress(1));
    assert_eq!(classify(&unit(ActiveState::Transitional, PID), seen), Observation::Unknown);
    assert_eq!(classify(&unit(ActiveState::Down, PID), seen), Observation::Down);
    assert_eq!(classify(&unit(ActiveState::Active, 0), seen), Observation::Down);
    assert_eq!(classify(&unit(ActiveState::Active, PID), seen), Observation::Up(seen));
    Ok(())
}


#[test]
fn export_progress_reads_the_file_and_a_missing_file_is_no_progress() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("export.json");
    assert_eq!(export_progress(&path), None);
    append(&path, "abc")?;
    let first = export_progress(&path);
    assert_eq!(first.map(|seen| seen.size), Some(EXPORT_BYTES));
    append(&path, "d")?;
    assert_ne!(export_progress(&path), first);
    Ok(())
}


#[test]
fn a_running_sensor_with_progress_stays_quiet_and_a_stall_is_reported_once() -> TestResult {
    let config = settings(CAP);
    let first = Supervisor::default();
    let (one, act_one) = stepped(&first, &Observation::Up(Some(progress(1))), 0, &config);
    assert_eq!((one.state, act_one.event, act_one.restart), (SensorState::Running, None, false));
    let (two, act_two) = stepped(&one, &Observation::Up(Some(progress(1))), WINDOW - 1, &config);
    assert_eq!((two.state, act_two.event), (SensorState::Running, None));
    let (three, act_three) = stepped(&two, &Observation::Up(Some(progress(1))), WINDOW, &config);
    assert_eq!(three.state, SensorState::Stalled);
    let event = act_three.event.ok_or("no event")?;
    assert_eq!(
        (event.state, event.previous, event.since, event.suppressed),
        (SensorState::Stalled, SensorState::Running, WINDOW, 0)
    );
    assert!(act_three.restart);
    let (four, act_four) = stepped(&three, &Observation::Up(Some(progress(1))), WINDOW + TICK, &config);
    assert_eq!(
        (four.state, four.since, act_four.event, act_four.restart),
        (SensorState::Stalled, WINDOW, None, false)
    );
    let (five, act_five) = stepped(&four, &Observation::Up(Some(progress(CAP))), WINDOW + TICK * CAP, &config);
    assert_eq!(five.state, SensorState::Running);
    assert_eq!(act_five.event.map(|seen| seen.previous), Some(SensorState::Stalled));
    assert!(!act_five.restart);
    Ok(())
}


#[test]
fn a_missing_export_file_stalls_after_the_window_and_unknown_changes_nothing() -> TestResult {
    let config = settings(1);
    let (one, _) = stepped(&Supervisor::default(), &Observation::Up(None), 0, &config);
    let (unknown, act_unknown) = stepped(&one, &Observation::Unknown, 1, &config);
    assert_eq!(
        (unknown.state, unknown.known, act_unknown.event, act_unknown.restart),
        (SensorState::Unknown, SensorState::Running, None, false)
    );
    let (two, act_stalled) = stepped(&unknown, &Observation::Up(None), WINDOW, &config);
    assert_eq!(
        (two.state, act_stalled.event.map(|seen| seen.state)),
        (SensorState::Stalled, Some(SensorState::Stalled))
    );
    let (down, act_down) = stepped(&two, &Observation::Down, WINDOW + 1, &config);
    assert_eq!(
        act_down.event.map(|seen| (seen.state, seen.previous)),
        Some((SensorState::Stopped, SensorState::Stalled))
    );
    assert!(!act_down.restart);
    assert_eq!(down.progress_at, None);
    let (_, from_start) = stepped(&Supervisor::default(), &Observation::Down, 0, &config);
    assert_eq!(from_start.event.map(|seen| seen.previous), Some(SensorState::Unknown));
    assert!(from_start.restart);
    Ok(())
}


#[test]
fn restarts_are_spaced_and_capped_per_hour() -> TestResult {
    let config = settings(CAP);
    let cycle = |supervisor: &Supervisor, now: u64| {
        let (down, stopped) = stepped(supervisor, &Observation::Down, now, &config);
        let (up, _) = stepped(&down, &Observation::Up(Some(progress(now))), now + 1, &config);
        (up, stopped.restart)
    };
    let (one, first) = cycle(&Supervisor::default(), 0);
    let (two, too_soon) = cycle(&one, MIN_RESTART_INTERVAL_SECONDS - CAP);
    let (three, second) = cycle(&two, MIN_RESTART_INTERVAL_SECONDS * CAP);
    let (four, capped) = cycle(&three, MIN_RESTART_INTERVAL_SECONDS * FOUR);
    assert_eq!((first, too_soon, second, capped), (true, false, true, false));
    assert_eq!(four.restarts.len(), CAP_LEN);
    let (_, later) = cycle(&four, HOUR_SECONDS + MIN_RESTART_INTERVAL_SECONDS * CAP);
    assert!(later);
    let (_, none) = stepped(&Supervisor::default(), &Observation::Down, 0, &settings(0));
    assert!(!none.restart);
    Ok(())
}


#[test]
fn a_sensor_flapping_every_tick_keeps_events_and_restarts_bounded() -> TestResult {
    let config = settings(CAP);
    let (last, events, restarts, suppressed) =
        (0..FLAPS).fold((Supervisor::default(), 0, 0, 0), |(supervisor, events, restarts, suppressed), now| {
            let observation = if now % CAP == 0 {
                Observation::Down
            } else {
                Observation::Up(Some(progress(now)))
            };
            let (next, action) = stepped(&supervisor, &observation, now, &config);
            (
                next,
                events + usize::from(action.event.is_some()),
                restarts + usize::from(action.restart),
                suppressed + u64::from(action.suppressed),
            )
        });
    assert_eq!(events, MAX_EVENTS_PER_HOUR);
    assert_eq!(restarts, CAP_LEN);
    assert!(suppressed > 0);
    assert!(last.events.len() <= MAX_EVENTS_PER_HOUR && last.restarts.len() <= CAP_LEN);
    assert!(last.suppressed > 0);
    let next_hour = HOUR_SECONDS + FLAPS;
    let (after, action) = stepped(&last, &Observation::Down, next_hour, &config);
    let event = action.event.ok_or("no event after the hour")?;
    assert_eq!(event.suppressed, last.suppressed);
    assert_eq!(after.suppressed, 0);
    Ok(())
}


#[test]
fn the_event_line_names_sensor_state_previous_and_since() -> TestResult {
    let line = sensor_event_line(&SensorEvent {
        state: SensorState::Stopped,
        previous: SensorState::Running,
        since: NINE,
        suppressed: 0,
    });
    let value: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!(value.pointer("/event/kind").and_then(|kind| kind.as_str()), Some("agent.sensor"));
    assert_eq!(value.pointer("/agent/sensor/name").and_then(|name| name.as_str()), Some("tetragon"));
    assert_eq!(value.pointer("/agent/sensor/state").and_then(|name| name.as_str()), Some("stopped"));
    assert_eq!(value.pointer("/agent/sensor/previous").and_then(|name| name.as_str()), Some("running"));
    assert_eq!(value.pointer("/agent/sensor/since").and_then(|name| name.as_u64()), Some(NINE));
    assert_eq!(restart_entry("t", SensorState::Stalled, "restarted").outcome, Outcome::Success);
    assert_eq!(restart_entry("t", SensorState::Stalled, "failed").outcome, Outcome::Failure);
    Ok(())
}


#[tokio::test]
async fn observe_reads_the_unit_and_the_export_and_a_failure_is_unknown() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let env = environment(dir.path());
    assert_eq!(observe(&env).await, Observation::Unknown);
    fs::write(&env.systemctl, show_text("active", PID))?;
    assert_eq!(observe(&env).await, Observation::Up(None));
    append(&env.export, "line\n")?;
    assert!(matches!(observe(&env).await, Observation::Up(Some(seen)) if seen.size == "line\n".len() as u64));
    fs::write(&env.systemctl, show_text("inactive", 0))?;
    assert_eq!(observe(&env).await, Observation::Down);
    fs::write(&env.systemctl, show_text("activating", 0))?;
    assert_eq!(observe(&env).await, Observation::Unknown);
    fs::write(&env.systemctl, "garbage")?;
    assert_eq!(observe(&env).await, Observation::Unknown);
    Ok(())
}


#[tokio::test]
async fn a_scripted_run_spools_one_event_per_transition_and_restarts_within_the_rules() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let env = environment(dir.path());
    let audit_log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&audit_log);
    let active = show_text("active", PID);
    let inactive = show_text("inactive", 0);
    let steps: Vec<(String, bool)> = vec![
        (active.clone(), true),
        (active.clone(), false),
        (active.clone(), false),
        (active.clone(), false),
        (active.clone(), false),
        (active.clone(), true),
        (inactive.clone(), false),
        (active.clone(), true),
        (inactive.clone(), false),
        ("garbage".to_owned(), false),
        (inactive, false),
    ];
    let total = steps.len() as u64;
    let counter = Arc::new(AtomicU64::new(0));
    let (show, export) = (env.systemctl.clone(), env.export.clone());
    let paused = Arc::clone(&counter);
    let script = steps.clone();
    let pause = move |_: Duration| -> PauseFuture {
        let next = paused.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some((text, grow)) = usize::try_from(next).ok().and_then(|index| script.get(index)) {
            fs::write(&show, text)
                .inspect_err(|error| tracing::warn!(%error, "script step failed"))
                .ok();
            if *grow {
                append(&export, "more\n")
                    .inspect_err(|error| tracing::warn!(%error, "script step failed"))
                    .ok();
            }
        }
        Box::pin(async {})
    };
    let ticked = Arc::clone(&counter);
    let clock = move || ticked.load(Ordering::SeqCst) * TICK;
    let first = steps.first().ok_or("no steps")?;
    fs::write(&env.systemctl, &first.0)?;
    append(&env.export, "first\n")?;
    let shared = Arc::new(ArcSwap::from_pointee(settings(CAP)));
    let last = run_sensor(&shared, &env, audit.as_ref(), total, &pause, &clock, &clock).await?;
    let events = event_states(&env.spool)?;
    let expected = [
        ("stalled", "running"),
        ("running", "stalled"),
        ("stopped", "running"),
        ("running", "stopped"),
        ("stopped", "running"),
    ]
    .map(|(state, previous)| (state.to_owned(), previous.to_owned()));
    assert_eq!(events, expected);
    assert_eq!(start_count(dir.path()), CAP_LEN);
    assert_eq!(last.known, SensorState::Stopped);
    let audited = fs::read_to_string(dir.path().join("audit"))?;
    assert_eq!(audited.matches("sensor.restart").count(), CAP_LEN);
    assert!(audited.contains("agent_linux_sensor"));
    Ok(())
}


#[tokio::test]
async fn a_failed_restart_is_audited_as_failed_and_a_failing_audit_is_logged() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let env = environment(dir.path());
    fs::write(dir.path().join("show.fail"), "")?;
    let audit_log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&audit_log);
    restart(&env, audit.as_ref(), SensorState::Stopped).await;
    assert!(fs::read_to_string(dir.path().join("audit"))?.contains("failed"));
    let refusing: Box<SharedAuditFn> = Box::new(|_| Err(std::io::Error::other("refused").into()));
    restart(&env, refusing.as_ref(), SensorState::Stalled).await;
    assert_eq!(start_count(dir.path()), CAP_LEN);
    Ok(())
}


#[tokio::test]
async fn a_spool_that_cannot_be_written_stops_the_tick_with_an_error() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let env = SensorEnv {
        spool: dir.path().to_path_buf(),
        ..environment(dir.path())
    };
    fs::write(&env.systemctl, show_text("inactive", 0))?;
    let audit_log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&audit_log);
    let outcome = tick(&env, audit.as_ref(), &settings(1), Supervisor::default(), 0, 0).await;
    assert!(matches!(outcome, Err(SourceError::Io(_))));
    assert_eq!(start_count(dir.path()), 0);
    Ok(())
}


#[tokio::test]
async fn real_commands_are_bounded_in_output_time_and_status() -> TestResult {
    let ok = run_bounded(PathBuf::from("/bin/echo"), vec!["hello".to_owned()]).await?;
    assert_eq!(ok, "hello\n");
    assert!(matches!(
        run_bounded(PathBuf::from("/usr/bin/yes"), Vec::new()).await,
        Err(SensorError::TooLarge(limit)) if limit == MAX_OUTPUT_BYTES
    ));
    assert!(matches!(
        run_bounded(PathBuf::from("/bin/false"), Vec::new()).await,
        Err(SensorError::Exit(Some(1)))
    ));
    assert!(matches!(
        run_bounded(PathBuf::from("/usr/bin/printf"), vec!["\\377".to_owned()]).await,
        Err(SensorError::Utf8(_))
    ));
    assert!(matches!(
        run_bounded(PathBuf::from("/nonexistent/systemctl"), Vec::new()).await,
        Err(SensorError::Io(_))
    ));
    assert!(matches!(
        run_with_deadline(PathBuf::from("/usr/bin/sleep"), vec!["30".to_owned()], SHORT).await,
        Err(SensorError::Timeout)
    ));
    assert_eq!(run_command(PathBuf::from("/bin/echo"), vec!["x".to_owned()]).await?, "x\n");
    Ok(())
}


#[tokio::test]
async fn events_over_the_hourly_cap_are_cut_and_counted_not_spooled() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let env = environment(dir.path());
    fs::write(&env.systemctl, show_text("inactive", 0))?;
    let audit_log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&audit_log);
    let full = Supervisor {
        events: vec![0; MAX_EVENTS_PER_HOUR],
        ..Supervisor::default()
    };
    let next = tick(&env, audit.as_ref(), &settings(CAP), full, 1, 1).await?;
    assert_eq!(next.suppressed, 1);
    assert!(!env.spool.exists());
    Ok(())
}


#[test]
fn a_stop_after_the_hourly_cap_is_reported_once_when_the_window_slides() -> TestResult {
    let config = settings(CAP);
    let full = Supervisor {
        events: vec![0; MAX_EVENTS_PER_HOUR],
        reported: SensorState::Running,
        known: SensorState::Running,
        state: SensorState::Running,
        ..Supervisor::default()
    };
    let (held, cut) = stepped(&full, &Observation::Down, 1, &config);
    assert_eq!((cut.event, cut.suppressed, held.suppressed), (None, true, 1));
    let (still, quiet) = stepped(&held, &Observation::Down, TICK, &config);
    assert_eq!((quiet.event, quiet.suppressed, still.suppressed), (None, false, 1));
    let (sent, event) = stepped(&still, &Observation::Down, HOUR_SECONDS + 1, &config);
    let reported = event.event.ok_or("the stop was never reported")?;
    assert_eq!(
        (reported.state, reported.previous, reported.suppressed, sent.suppressed),
        (SensorState::Stopped, SensorState::Running, 1, 0)
    );
    let (_, again) = stepped(&sent, &Observation::Down, HOUR_SECONDS + TICK, &config);
    assert_eq!(again.event, None);
    Ok(())
}


#[test]
fn a_wall_clock_stepped_back_neither_hides_a_stall_nor_freezes_the_windows() -> TestResult {
    let config = settings(CAP);
    let day = DAY;
    let (one, _) = step(&Supervisor::default(), &Observation::Up(Some(progress(1))), 0, day * CAP, &config);
    let (two, stalled) = step(&one, &Observation::Up(Some(progress(1))), WINDOW, day, &config);
    let event = stalled.event.ok_or("the stall was hidden")?;
    assert_eq!((two.state, event.state, event.since), (SensorState::Stalled, SensorState::Stalled, day));
    let (three, restarted) = step(&two, &Observation::Down, WINDOW + 1, 1, &config);
    assert!(!restarted.restart);
    let (_, later) = step(&three, &Observation::Down, WINDOW + MIN_RESTART_INTERVAL_SECONDS, 0, &config);
    assert!(later.restart);
    assert!(monotonic_seconds() > 0);
    assert!(monotonic_seconds() >= monotonic_seconds().saturating_sub(1));
    Ok(())
}


#[test]
fn a_restart_refused_by_the_interval_is_retried_until_it_runs() -> TestResult {
    let config = settings(FOUR);
    let (one, first) = stepped(&Supervisor::default(), &Observation::Down, 0, &config);
    let (up, _) = stepped(&one, &Observation::Up(Some(progress(1))), 1, &config);
    let (two, early) = stepped(&up, &Observation::Down, TICK, &config);
    assert!(two.restart_due);
    let (three, ready) = stepped(&two, &Observation::Down, MIN_RESTART_INTERVAL_SECONDS, &config);
    let (_, after) = stepped(&three, &Observation::Down, MIN_RESTART_INTERVAL_SECONDS + TICK, &config);
    assert_eq!((first.restart, early.restart, ready.restart, after.restart), (true, false, true, false));
    let (back, _) = stepped(&two, &Observation::Up(Some(progress(CAP))), TICK + 1, &config);
    assert!(!back.restart_due);
    Ok(())
}


#[test]
fn an_unknown_state_held_past_the_window_is_reported_once_and_its_end_too() -> TestResult {
    let config = settings(CAP);
    let (one, _) = stepped(&Supervisor::default(), &Observation::Up(Some(progress(1))), 0, &config);
    let (two, early) = stepped(&one, &Observation::Unknown, 1, &config);
    let (three, due) = stepped(&two, &Observation::Unknown, WINDOW + 1, &config);
    let event = due.event.ok_or("unknown was not reported")?;
    assert_eq!((event.state, event.previous), (SensorState::Unknown, SensorState::Running));
    let (four, again) = stepped(&three, &Observation::Unknown, WINDOW * CAP, &config);
    assert_eq!((early.event, again.event), (None, None));
    let (five, back) = stepped(&four, &Observation::Up(Some(progress(CAP))), WINDOW * CAP + 1, &config);
    let ended = back.event.ok_or("the end of unknown was not reported")?;
    assert_eq!(
        (ended.state, ended.previous, five.loud_unknown),
        (SensorState::Running, SensorState::Unknown, false)
    );
    let (_, quiet) = stepped(&five, &Observation::Up(Some(progress(FOUR))), WINDOW * CAP + TICK, &config);
    assert_eq!(quiet.event, None);
    let full = Supervisor {
        events: vec![0; MAX_EVENTS_PER_HOUR],
        ..Supervisor::default()
    };
    let (held, _) = stepped(&full, &Observation::Unknown, 1, &config);
    let (kept, cut) = stepped(&held, &Observation::Unknown, WINDOW + 1, &config);
    assert_eq!((cut.event, cut.suppressed, kept.suppressed), (None, false, 0));
    Ok(())
}

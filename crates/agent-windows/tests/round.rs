#[path = "common/engine.rs"]
mod engine;
#[path = "common/types.rs"]
mod types;


use agent_windows::defender::POWERSHELL_PATH;
use agent_windows::error::{PollError, RunError};
use agent_windows::model::{PollEnv, RunEnd, RunRequest, MAX_EVENTS_PER_POLL, SECURITY, SYSMON, WEVTUTIL_PATH};
use agent_windows::round::{
    apply_settings, defender_due, next_waited, reload_once_per_refusal, run_round, run_rounds, spool_defender_line, DefenderStep, RoundReport,
    RoundState,
};
use agent_windows::settings::{observation, Settings, MIN_OUTPUT_BYTES, MIN_SPOOL_BYTES, SETTINGS_FILE};
use agent_windows::types::{Runner, SharedObserved};
use core_config::reload::{current_config, reload, ReloadEngine};
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use types::TestResult;


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish()).is_ok());


const TIME: &str = "2026-11-03T10:00:00.1234567Z";


const BOM: [u8; 2] = [0xFF, 0xFE];


const LINE_LIMIT: usize = 524_288;


const LOCK_ATTEMPTS: u32 = 10;


const OLD_DEADLINE: u64 = 20;


const NEW_DEADLINE: u64 = 7;


const OLD_OUTPUT: usize = 4_194_304;


const NEW_BATCH: u32 = 3;


const BATCH_SEVEN: u32 = 7;


const BATCH_EIGHT: u32 = 8;


const SHORT_LOG: u64 = 5;


const LONG_LOG: u64 = 50;


const LONGER_LOG: u64 = 200;


const POLL_SECONDS: u64 = 100;


const DEFENDER_SECONDS: u64 = 300;


const DEFAULT_POLL: u64 = 10;


const BOTH: usize = 2;


const BOTH_U64: u64 = 2;


const FIVE_ROUNDS: u32 = 5;


const THREE_ROUNDS: u32 = 3;


const TWO_ROUNDS: u32 = 2;


const LAST_ROUND: usize = 2;


const ENV_DEADLINE: u64 = 9;


const QUERY_INDEX: usize = 2;


const COUNT_INDEX: usize = 3;


const SLOW_POLL: u64 = 300;


const OVER_CAP_FILL: usize = 2_097_152;


const DEFENDER_TARGET: &str = "defender";


#[derive(Debug, Clone, PartialEq, Eq)]
struct Logged {
    round: usize,
    target: String,
    deadline: u64,
    max_bytes: usize,
    count: Option<String>,
}


struct Lab {
    directory: tempfile::TempDir,
    path: PathBuf,
    spool: PathBuf,
    state: PathBuf,
    observed: SharedObserved,
}


fn lab(file: &str) -> Result<Lab, Box<dyn std::error::Error>> {
    LazyLock::force(&LOGGING);
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let state = directory.path().join("state");
    fs::create_dir_all(&state)?;
    let spool_dir = directory.path().join("spool-dir");
    fs::create_dir_all(&spool_dir)?;
    let path = state.join(SETTINGS_FILE);
    fs::write(&path, file)?;
    Ok(Lab {
        spool: spool_dir.join("spool"),
        directory,
        path,
        state,
        observed: SharedObserved::default(),
    })
}


fn security(record: u64) -> String {
    format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>\
         <EventID>4625</EventID><TimeCreated SystemTime='{TIME}'/><EventRecordID>{record}</EventRecordID><Channel>Security</Channel>\
         <Computer>WIN-01</Computer></System><EventData><Data Name='TargetUserName'>bob</Data><Data Name='Status'>0xC000006D</Data>\
         <Data Name='IpAddress'>10.0.0.9</Data></EventData></Event>"
    )
}


fn wide(text: &str) -> Vec<u8> {
    BOM.into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect()
}


fn numbers(query: &str) -> (u64, u64) {
    let digits: Vec<u64> = query
        .split(|found: char| !found.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect();
    (digits.first().copied().unwrap_or(0), digits.get(1).copied().unwrap_or(0))
}


fn serve(newest: u64, request: &RunRequest<'_>) -> String {
    let query = request.args.get(QUERY_INDEX).cloned().unwrap_or_else(String::new);
    let count: u64 = request
        .args
        .get(COUNT_INDEX)
        .map_or(1, |found| found.trim_start_matches("/c:").parse().unwrap_or(1));
    if request.program == POWERSHELL_PATH || request.args.get(1).is_some_and(|name| name == SYSMON.name) {
        String::new()
    } else if request.args.iter().any(|arg| arg == "/rd:true") {
        security(newest)
    } else if query.contains("EventRecordID=") {
        security(numbers(&query).0)
    } else {
        let (after, upper) = numbers(&query);
        (after + 1..=upper.min(after + count)).map(security).collect()
    }
}


fn logged(round: usize, request: &RunRequest<'_>) -> Logged {
    let target = if request.program == POWERSHELL_PATH {
        DEFENDER_TARGET.to_owned()
    } else {
        request.args.get(1).cloned().unwrap_or_else(String::new)
    };
    Logged {
        round,
        target,
        deadline: request.deadline_seconds,
        max_bytes: request.max_bytes,
        count: request.args.iter().find(|arg| arg.starts_with("/c:")).cloned(),
    }
}


struct Hooks<'a> {
    newest: &'a Cell<u64>,
    on_request: &'a mut dyn FnMut(usize, &RunRequest<'_>),
    after_round: &'a mut dyn FnMut(usize),
    fail_security: bool,
}


struct Outcome {
    reports: Result<Vec<RoundReport>, PollError>,
    log: Vec<Logged>,
    waits: Vec<u64>,
    round: RoundState,
}


fn drive(lab: &Lab, engine: &ReloadEngine<Settings>, rounds: u32, hooks: Hooks<'_>) -> Outcome {
    drive_in(lab, engine, rounds, hooks, RoundState::default())
}


fn drive_in(lab: &Lab, engine: &ReloadEngine<Settings>, rounds: u32, hooks: Hooks<'_>, previous: RoundState) -> Outcome {
    let round_index = Cell::new(0usize);
    let log: RefCell<Vec<Logged>> = RefCell::new(Vec::new());
    let Hooks {
        newest,
        on_request,
        after_round,
        fail_security,
    } = hooks;
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        log.borrow_mut().push(logged(round_index.get(), request));
        on_request(round_index.get(), request);
        sink(&wide(&serve(newest.get(), request)));
        if fail_security && request.args.get(1).is_some_and(|name| name == SECURITY.name) {
            Err(RunError::Reader)
        } else {
            Ok(RunEnd::Done)
        }
    };
    let mut seen = SeenIds::new();
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool: &lab.spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: OLD_OUTPUT,
        deadline_seconds: 1,
        max_spool_bytes: 1,
        max_batch: 1,
        seen: &mut seen,
    };
    let mut round = previous;
    let mut waits: Vec<u64> = Vec::new();
    let reports = run_rounds(engine, &lab.observed, rounds, &mut env, &mut round, &mut |seconds| {
        waits.push(seconds);
        after_round(round_index.get());
        round_index.set(round_index.get() + 1);
    });
    Outcome {
        reports,
        log: log.into_inner(),
        waits,
        round,
    }
}


fn quiet() -> (Cell<u64>, impl FnMut(usize, &RunRequest<'_>), impl FnMut(usize)) {
    (Cell::new(SHORT_LOG), |_: usize, _: &RunRequest<'_>| (), |_: usize| ())
}


fn targets(outcome: &Outcome, round: usize) -> Vec<String> {
    outcome
        .log
        .iter()
        .filter(|entry| entry.round == round)
        .map(|entry| entry.target.clone())
        .collect()
}


fn open(lab: &Lab) -> Result<(ReloadEngine<Settings>, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let denied = Arc::new(AtomicUsize::new(0));
    Ok((engine::open_at(&lab.path, Arc::clone(&denied), Arc::clone(&lab.observed))?, denied))
}


fn spool_text(lab: &Lab) -> String {
    fs::read_to_string(&lab.spool).unwrap_or_else(|_| String::new())
}


fn put(path: &Path, text: &str) {
    assert!(fs::write(path, text).is_ok());
}


#[test]
fn a_round_polls_both_channels_runs_the_defender_once_and_waits_once() -> TestResult {
    let lab = lab("poll_interval_seconds: 10\n")?;
    let (engine, _) = open(&lab)?;
    let (newest, mut on_request, mut after_round) = quiet();
    let outcome = drive(
        &lab,
        &engine,
        1,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    let reports = outcome.reports.as_ref().map_err(|error| error.to_string())?;
    let report = reports.first().ok_or("no report")?;
    assert_eq!(report.polled.iter().map(|(key, _)| *key).collect::<Vec<_>>(), vec!["sysmon", "security"]);
    assert!(report.defender);
    assert_eq!(outcome.waits, vec![DEFAULT_POLL]);
    assert_eq!(targets(&outcome, 0).first().map(String::as_str), Some(SYSMON.name));
    assert!(targets(&outcome, 0).iter().any(|target| target == DEFENDER_TARGET));
    assert_eq!(spool_text(&lab).matches("ostyr.windows.defender").count(), 1);
    assert_eq!(outcome.round.channels.len(), BOTH);
    Ok(())
}


#[test]
fn the_defender_runs_when_its_interval_has_passed_in_poll_seconds() -> TestResult {
    let lab = lab(&format!(
        "poll_interval_seconds: {POLL_SECONDS}\ndefender_interval_seconds: {DEFENDER_SECONDS}\nchannels: [sysmon]\n"
    ))?;
    let (engine, _) = open(&lab)?;
    let (newest, mut on_request, mut after_round) = quiet();
    let outcome = drive(
        &lab,
        &engine,
        FIVE_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    let flags: Vec<bool> = outcome.reports?.iter().map(|report| report.defender).collect();
    assert_eq!(flags, vec![true, false, false, true, false]);
    assert_eq!(outcome.waits, vec![POLL_SECONDS; usize::try_from(FIVE_ROUNDS)?]);
    assert_eq!(spool_text(&lab).matches("ostyr.windows.defender").count(), BOTH);
    assert!(defender_due(None, DEFENDER_SECONDS));
    assert!(!defender_due(Some(DEFENDER_SECONDS - 1), DEFENDER_SECONDS));
    assert!(defender_due(Some(DEFENDER_SECONDS), DEFENDER_SECONDS));
    assert_eq!(next_waited(None, false, POLL_SECONDS), POLL_SECONDS);
    assert_eq!(next_waited(Some(POLL_SECONDS), false, POLL_SECONDS), BOTH_U64 * POLL_SECONDS);
    assert_eq!(next_waited(Some(POLL_SECONDS), true, POLL_SECONDS), POLL_SECONDS);
    assert_eq!(next_waited(Some(u64::MAX), false, POLL_SECONDS), u64::MAX);
    Ok(())
}


#[test]
fn a_channel_removed_live_is_no_longer_polled() -> TestResult {
    let lab = lab(&format!("deadline_seconds: {OLD_DEADLINE}\n"))?;
    let (engine, _) = open(&lab)?;
    let newest = Cell::new(SHORT_LOG);
    let path = lab.path.clone();
    let mut on_request = |_: usize, _: &RunRequest<'_>| ();
    let mut after_round = |round: usize| {
        if round == 0 {
            put(&path, &format!("deadline_seconds: {OLD_DEADLINE}\nchannels: [security]\n"));
        }
    };
    let outcome = drive(
        &lab,
        &engine,
        TWO_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    outcome.reports.as_ref().map_err(|error| error.to_string())?;
    assert!(targets(&outcome, 0).iter().any(|target| target == SYSMON.name));
    assert!(!targets(&outcome, 1).iter().any(|target| target == SYSMON.name));
    assert!(targets(&outcome, 1).iter().any(|target| target == SECURITY.name));
    Ok(())
}


#[test]
fn a_bad_value_keeps_the_old_snapshot_and_a_good_change_applies() -> TestResult {
    let lab = lab(&format!("deadline_seconds: {OLD_DEADLINE}\nchannels: [security]\n"))?;
    let (engine, denied) = open(&lab)?;
    let newest = Cell::new(SHORT_LOG);
    let path = lab.path.clone();
    let mut on_request = |_: usize, _: &RunRequest<'_>| ();
    let mut after_round = |round: usize| match round {
        0 => {
            newest.set(LONG_LOG);
            put(&path, "deadline_seconds: 0\nchannels: [security]\n");
        }
        1 => {
            newest.set(LONGER_LOG);
            put(
                &path,
                &format!("deadline_seconds: {NEW_DEADLINE}\nchannels: [security]\nbatch: {NEW_BATCH}\nmax_output_bytes: {MIN_OUTPUT_BYTES}\n"),
            );
        }
        _ => (),
    };
    let outcome = drive(
        &lab,
        &engine,
        THREE_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    outcome.reports.as_ref().map_err(|error| error.to_string())?;
    let deadlines = |round: usize| -> Vec<u64> {
        outcome
            .log
            .iter()
            .filter(|entry| entry.round == round && entry.target != DEFENDER_TARGET)
            .map(|entry| entry.deadline)
            .collect()
    };
    assert!(deadlines(0).iter().chain(deadlines(1).iter()).all(|deadline| *deadline == OLD_DEADLINE));
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    assert!(deadlines(LAST_ROUND).iter().all(|deadline| *deadline == NEW_DEADLINE));
    let counts = |round: usize| -> Vec<Option<String>> {
        outcome
            .log
            .iter()
            .filter(|entry| entry.round == round)
            .map(|entry| entry.count.clone())
            .collect()
    };
    let wanted = Some(format!("/c:{NEW_BATCH}"));
    assert!(counts(LAST_ROUND).contains(&wanted));
    assert!(!counts(1).contains(&wanted));
    assert!(outcome
        .log
        .iter()
        .filter(|entry| entry.round == LAST_ROUND && entry.target != DEFENDER_TARGET)
        .all(|entry| entry.max_bytes == MIN_OUTPUT_BYTES));
    assert_eq!(outcome.round.channels.get("security").map(|state| state.batch), Some(NEW_BATCH));
    assert_eq!(current_config(&engine).deadline_seconds, NEW_DEADLINE);
    Ok(())
}


#[test]
fn a_round_reads_one_snapshot_even_when_the_file_is_swapped_in_the_middle() -> TestResult {
    let lab = lab(&format!("deadline_seconds: {OLD_DEADLINE}\nbatch: 200\n"))?;
    let (engine, _) = open(&lab)?;
    let newest = Cell::new(LONG_LOG);
    let path = lab.path.clone();
    let swapped = Cell::new(false);
    let mut on_request = |round: usize, request: &RunRequest<'_>| {
        if round == 0 && !swapped.get() && request.args.get(1).is_some_and(|name| name == SYSMON.name) {
            swapped.set(true);
            put(
                &path,
                &format!("deadline_seconds: {NEW_DEADLINE}\nchannels: [sysmon]\nbatch: {NEW_BATCH}\n"),
            );
            reload(&engine);
        }
    };
    let mut after_round = |_: usize| ();
    let outcome = drive(
        &lab,
        &engine,
        TWO_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    outcome.reports.as_ref().map_err(|error| error.to_string())?;
    assert!(swapped.get());
    assert_eq!(current_config(&engine).deadline_seconds, NEW_DEADLINE);
    let first: Vec<&Logged> = outcome
        .log
        .iter()
        .filter(|entry| entry.round == 0 && entry.target != DEFENDER_TARGET)
        .collect();
    assert!(first.iter().any(|entry| entry.target == SECURITY.name));
    assert!(first.iter().all(|entry| entry.deadline == OLD_DEADLINE));
    let wanted = Some("/c:200".to_owned());
    assert!(first.iter().any(|entry| entry.count == wanted));
    let second = targets(&outcome, 1);
    assert!(second.iter().all(|target| target != SECURITY.name));
    assert!(outcome
        .log
        .iter()
        .filter(|entry| entry.round == 1 && entry.target != DEFENDER_TARGET)
        .all(|entry| entry.deadline == NEW_DEADLINE));
    Ok(())
}


#[test]
fn a_failing_poll_ends_the_round_without_the_wait() -> TestResult {
    let lab = lab("poll_interval_seconds: 10\n")?;
    let (engine, _) = open(&lab)?;
    let (newest, mut on_request, mut after_round) = quiet();
    let outcome = drive(
        &lab,
        &engine,
        1,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: true,
        },
    );
    assert!(matches!(outcome.reports, Err(PollError::Run(_))));
    assert!(outcome.waits.is_empty());
    assert!(!targets(&outcome, 0).iter().any(|target| target == DEFENDER_TARGET));
    Ok(())
}


#[test]
fn a_defender_line_that_cannot_be_spooled_ends_the_round_without_the_wait() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let (engine, _) = open(&lab)?;
    let newest = Cell::new(SHORT_LOG);
    let spool_dir = lab.directory.path().join("spool-dir");
    let mut on_request = |_: usize, request: &RunRequest<'_>| {
        if request.program == POWERSHELL_PATH {
            assert!(fs::remove_dir_all(&spool_dir).is_ok());
        }
    };
    let mut after_round = |_: usize| ();
    let outcome = drive(
        &lab,
        &engine,
        1,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    assert!(matches!(outcome.reports, Err(PollError::Spool(_))));
    assert!(outcome.waits.is_empty());
    Ok(())
}


#[test]
fn run_round_applies_the_snapshot_to_the_environment() -> TestResult {
    let lab = lab(&format!(
        "channels: [sysmon]\nbatch: {NEW_BATCH}\ndeadline_seconds: {ENV_DEADLINE}\nmax_spool_bytes: {MIN_SPOOL_BYTES}\n"
    ))?;
    let (engine, _) = open(&lab)?;
    let mut run = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> { Ok(RunEnd::Done) };
    let mut seen = SeenIds::new();
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool: &lab.spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: 1,
        deadline_seconds: 1,
        max_spool_bytes: 1,
        max_batch: MAX_EVENTS_PER_POLL,
        seen: &mut seen,
    };
    let mut round = RoundState::default();
    let report = run_round(&engine, &mut env, &mut round, &mut |_| ())?;
    assert_eq!(report.polled.len(), 1);
    assert_eq!(
        (env.max_batch, env.deadline_seconds, env.max_spool_bytes),
        (NEW_BATCH, ENV_DEADLINE, MIN_SPOOL_BYTES)
    );
    apply_settings(&mut env, &Settings::default());
    assert_eq!(env.max_batch, MAX_EVENTS_PER_POLL);
    Ok(())
}


#[test]
fn a_defender_line_is_refused_when_the_spool_is_already_over_the_cap() -> TestResult {
    let lab = lab(&format!(
        "channels: [sysmon]\npoll_interval_seconds: {SLOW_POLL}\ndefender_interval_seconds: {DEFENDER_SECONDS}\nmax_spool_bytes: {MIN_SPOOL_BYTES}\n"
    ))?;
    let (engine, _) = open(&lab)?;
    let full = "x\n".repeat(OVER_CAP_FILL / BOTH);
    fs::write(&lab.spool, &full)?;
    let (newest, mut on_request, mut after_round) = quiet();
    let outcome = drive(
        &lab,
        &engine,
        FIVE_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    let reports = outcome.reports?;
    assert_eq!(reports.len(), usize::try_from(FIVE_ROUNDS)?);
    assert!(reports.iter().all(|report| !report.defender && report.defender_spool_full == 1));
    assert!(outcome.log.iter().all(|entry| entry.target != DEFENDER_TARGET));
    assert!(reports
        .iter()
        .all(|report| report.polled.iter().all(|(_, totals)| totals.iter().all(|polled| polled.spool_full == 1))));
    assert_eq!(spool_text(&lab), full);
    assert!(outcome.round.defender_blocked);
    Ok(())
}


#[test]
fn the_defender_line_fits_again_once_the_spool_has_room() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let mut run = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> { Ok(RunEnd::Done) };
    let mut seen = SeenIds::new();
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool: &lab.spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: 1,
        deadline_seconds: 1,
        max_spool_bytes: MIN_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen: &mut seen,
    };
    fs::write(&lab.spool, "x\n".repeat(OVER_CAP_FILL / BOTH))?;
    let mut blocked = false;
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::NoRoom);
    assert!(blocked);
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::NoRoom);
    assert!(blocked);
    fs::remove_file(&lab.spool)?;
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::Appended);
    assert!(!blocked);
    assert_eq!(spool_text(&lab).matches("ostyr.windows.defender").count(), 1);
    Ok(())
}


#[test]
fn a_bad_file_kept_for_five_rounds_is_refused_and_audited_once() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let (engine, denied) = open(&lab)?;
    put(&lab.path, "batch: 0x1f4\n");
    let (newest, mut on_request, mut after_round) = quiet();
    let outcome = drive(
        &lab,
        &engine,
        FIVE_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
    );
    outcome.reports.as_ref().map_err(|error| error.to_string())?;
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    assert!(observation(&lab.observed).refused.is_some());
    assert_eq!(current_config(&engine).batch, MAX_EVENTS_PER_POLL);
    put(&lab.path, "batch: 0x1f5\n");
    let again = drive_in(
        &lab,
        &engine,
        TWO_ROUNDS,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
        outcome.round,
    );
    again.reports.as_ref().map_err(|error| error.to_string())?;
    assert_eq!(denied.load(Ordering::SeqCst), BOTH);
    put(&lab.path, &format!("batch: {NEW_BATCH}\n"));
    let fixed = drive_in(
        &lab,
        &engine,
        1,
        Hooks {
            newest: &newest,
            on_request: &mut on_request,
            after_round: &mut after_round,
            fail_security: false,
        },
        again.round,
    );
    fixed.reports.as_ref().map_err(|error| error.to_string())?;
    assert!(observation(&lab.observed).refused.is_none());
    assert_eq!(current_config(&engine).batch, NEW_BATCH);
    assert_eq!(denied.load(Ordering::SeqCst), BOTH);
    Ok(())
}


#[test]
fn an_unreadable_settings_file_is_refused_once_per_distinct_error() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let (engine, denied) = open(&lab)?;
    fs::remove_file(&lab.path)?;
    (0..THREE_ROUNDS).for_each(|_| reload_once_per_refusal(&engine, &lab.observed));
    assert!(matches!(observation(&lab.observed).refused, Some(Err(_))));
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    Ok(())
}


#[test]
fn a_spool_whose_size_cannot_be_read_ends_the_defender_line_with_an_error() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let mut run = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> { Ok(RunEnd::Done) };
    let mut seen = SeenIds::new();
    let blocker = lab.directory.path().join("blocker");
    fs::write(&blocker, "x")?;
    let spool = blocker.join("spool");
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool: &spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: 1,
        deadline_seconds: 1,
        max_spool_bytes: MIN_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen: &mut seen,
    };
    let mut blocked = false;
    assert!(matches!(spool_defender_line(&mut env, &mut blocked), Err(PollError::SpoolSize(_))));
    Ok(())
}


#[test]
fn a_good_file_refused_by_a_failing_audit_is_applied_once_the_audit_recovers() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let denied = Arc::new(AtomicUsize::new(0));
    let audit_down = Arc::new(AtomicBool::new(false));
    let engine = engine::open_with(&lab.path, Arc::clone(&denied), Arc::clone(&lab.observed), Arc::clone(&audit_down))?;
    audit_down.store(true, Ordering::SeqCst);
    put(&lab.path, &format!("batch: {NEW_BATCH}\n"));
    (0..THREE_ROUNDS).for_each(|_| reload_once_per_refusal(&engine, &lab.observed));
    assert!(observation(&lab.observed).refused.is_none());
    assert_eq!(current_config(&engine).batch, MAX_EVENTS_PER_POLL);
    audit_down.store(false, Ordering::SeqCst);
    reload_once_per_refusal(&engine, &lab.observed);
    assert_eq!(current_config(&engine).batch, NEW_BATCH);
    assert_eq!(denied.load(Ordering::SeqCst), 0);
    Ok(())
}


#[test]
fn an_empty_settings_file_is_refused_and_remembered() -> TestResult {
    let lab = lab(&format!("batch: {BATCH_SEVEN}\n"))?;
    let (engine, denied) = open(&lab)?;
    put(&lab.path, "");
    (0..THREE_ROUNDS).for_each(|_| reload_once_per_refusal(&engine, &lab.observed));
    assert_eq!(current_config(&engine).batch, BATCH_SEVEN);
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    assert!(observation(&lab.observed).refused.is_some());
    Ok(())
}


#[test]
fn a_file_that_returns_to_the_refused_bytes_is_not_audited_again() -> TestResult {
    let lab = lab(&format!("batch: {BATCH_SEVEN}\n"))?;
    let (engine, denied) = open(&lab)?;
    put(&lab.path, "batch: 0\n");
    reload_once_per_refusal(&engine, &lab.observed);
    put(&lab.path, &format!("batch: {BATCH_EIGHT}\n"));
    reload_once_per_refusal(&engine, &lab.observed);
    assert_eq!(current_config(&engine).batch, BATCH_EIGHT);
    put(&lab.path, "batch: 0\n");
    reload_once_per_refusal(&engine, &lab.observed);
    assert_eq!(denied.load(Ordering::SeqCst), BOTH);
    assert_eq!(current_config(&engine).batch, BATCH_EIGHT);
    Ok(())
}


#[test]
fn a_bad_file_that_comes_back_after_the_good_one_is_audited_again() -> TestResult {
    let lab = lab(&format!("batch: {BATCH_SEVEN}\n"))?;
    let (engine, denied) = open(&lab)?;
    put(&lab.path, "batch: 0\n");
    reload_once_per_refusal(&engine, &lab.observed);
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    put(&lab.path, &format!("batch: {BATCH_SEVEN}\n"));
    reload_once_per_refusal(&engine, &lab.observed);
    assert!(observation(&lab.observed).refused.is_none());
    put(&lab.path, "batch: 0\n");
    reload_once_per_refusal(&engine, &lab.observed);
    assert_eq!(denied.load(Ordering::SeqCst), BOTH);
    assert_eq!(current_config(&engine).batch, BATCH_SEVEN);
    Ok(())
}


fn defender_env<'a>(lab: &'a Lab, run: Runner<'a>, seen: &'a mut SeenIds) -> PollEnv<'a> {
    PollEnv {
        run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool: &lab.spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: 1,
        deadline_seconds: 1,
        max_spool_bytes: MIN_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen,
    }
}


#[test]
fn the_defender_is_not_run_without_room_and_its_wait_is_kept() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let runs = Cell::new(0usize);
    let mut run = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        runs.set(runs.get() + 1);
        Ok(RunEnd::Done)
    };
    let mut seen = SeenIds::new();
    let mut env = defender_env(&lab, &mut run, &mut seen);
    let full = usize::try_from(MIN_SPOOL_BYTES)?;
    fs::write(&lab.spool, vec![b'x'; full])?;
    let mut blocked = false;
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::NoRoom);
    assert_eq!(runs.get(), 0);
    assert_eq!(next_waited(Some(DEFENDER_SECONDS), false, DEFAULT_POLL), DEFENDER_SECONDS + DEFAULT_POLL);
    Ok(())
}


#[test]
fn a_round_without_room_does_not_reset_the_defender_wait_and_retries() -> TestResult {
    let lab = lab(&format!(
        "channels: [sysmon]\ndefender_interval_seconds: {DEFENDER_SECONDS}\nmax_spool_bytes: {MIN_SPOOL_BYTES}\n"
    ))?;
    let (engine, _) = open(&lab)?;
    fs::write(&lab.spool, vec![b'x'; usize::try_from(MIN_SPOOL_BYTES)?])?;
    let runs = Cell::new(0usize);
    let mut run = |request: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        if request.program == POWERSHELL_PATH {
            runs.set(runs.get() + 1);
        }
        Ok(RunEnd::Done)
    };
    let mut seen = SeenIds::new();
    let mut env = defender_env(&lab, &mut run, &mut seen);
    let mut round = RoundState::default();
    let first = run_round(&engine, &mut env, &mut round, &mut |_| ())?;
    assert_eq!((first.defender, first.defender_spool_full, round.defender_waited), (false, 1, None));
    assert!(defender_due(round.defender_waited, DEFENDER_SECONDS));
    fs::remove_file(&lab.spool)?;
    let second = run_round(&engine, &mut env, &mut round, &mut |_| ())?;
    assert!(second.defender);
    assert_eq!(round.defender_waited, Some(DEFAULT_POLL));
    assert_eq!(runs.get(), 1);
    Ok(())
}


#[test]
fn a_line_that_does_not_fit_the_room_left_is_refused_after_the_run() -> TestResult {
    let lab = lab("channels: [sysmon]\n")?;
    let mut run = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> { Ok(RunEnd::Done) };
    let mut seen = SeenIds::new();
    let mut env = defender_env(&lab, &mut run, &mut seen);
    fs::write(&lab.spool, vec![b'x'; usize::try_from(MIN_SPOOL_BYTES)? - 1])?;
    let mut blocked = false;
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::Refused);
    assert!(blocked);
    assert_eq!(spool_defender_line(&mut env, &mut blocked)?, DefenderStep::Refused);
    assert!(blocked);
    Ok(())
}

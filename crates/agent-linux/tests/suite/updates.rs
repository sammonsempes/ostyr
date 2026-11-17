use crate::support::lines;
use crate::types::TestResult;
use agent_channel::types::PauseFuture;
use agent_linux::cursor::{open_state_dir, read_counter};
use agent_linux::error::{SensorError, SourceError};
use agent_linux::model::{CommandSpec, Failure, Manager, SourceSettings, UpdateEnv, UpdateSettings};
use agent_linux::sensor::{run_spec_deadline, run_spec_with, run_update_command};
use agent_linux::types::{SharedSource, SharedUpdates, SpoolLock, UpdateFuture, UpdateRunFn};
use agent_linux::updates::{
    child_environment, collect_apt, collect_dnf, command, event_line, failure_of_command, failure_of_inventory, lists_age, next_run_id, outcome_name,
    publish, run_updates, skip_name, summary_line, DNF_CHECK_UPDATE_AVAILABLE,
};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use patch_inventory::error::InventoryError;
use patch_inventory::limits::default_limits;
use patch_inventory::model::{Limits, SkipReason, Update};
use patch_inventory::types::SkipCounts;
use rustix::process::Pid;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tempfile::{tempdir, TempDir};


const APT_LISTING: &[u8] = include_bytes!("../../../patch-inventory/tests/fixtures/apt-security.txt");


const DNF_UPDATEINFO: &[u8] = include_bytes!("../../../patch-inventory/tests/fixtures/dnf-updateinfo.txt");


const DNF_CHECK: &[u8] = include_bytes!("../../../patch-inventory/tests/fixtures/dnf-check-update.txt");


const INVALID_BYTE: u8 = 0xff;


const LINE_LIMIT: usize = 1_000_000;


const FAILURE_KINDS: usize = 4;


const CODE_AVAILABLE: i32 = DNF_CHECK_UPDATE_AVAILABLE;


const TWO: u64 = 2;


const THREE: u64 = 3;


const ELAPSED: u64 = 100;


const RUN_ID: u64 = 7;


const ENV_CAP: u64 = 4_096;


const INHERITED_CAP: u64 = 1_048_576;


const STRING_ROUNDS: usize = 2;


const APT_UPDATES: usize = 4;


const NOW: u64 = 4_000_000_000;


const INTERVAL: u64 = 300;


const DEADLINE: u64 = 5;


const SHORT_DEADLINE: Duration = Duration::from_millis(100);


const LONG_SLEEP_SECONDS: &str = "30";


const TINY_SPOOL: u64 = 100;


const TINY_LINE_LIMIT: usize = 20;


const SMALL_CAP: u64 = 10;


struct Fixture {
    dir: TempDir,
    env: UpdateEnv,
}


fn fixture(run: fn(CommandSpec, Duration) -> UpdateFuture) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let lists = dir.path().join("lists");
    fs::create_dir(&lists)?;
    fs::create_dir(lists.join("partial"))?;
    fs::write(lists.join("archive_noble_InRelease"), "x")?;
    let cursor = dir.path().join("cursor");
    let env = UpdateEnv {
        lists_dir: lists,
        spool: dir.path().join("spool"),
        sending: dir.path().join("spool.sending"),
        counter_file: dir.path().join("cursor.updates-run"),
        state: Arc::new(open_state_dir(&cursor)?),
        lock: SpoolLock::default(),
        tenant: "t1".to_owned(),
        device_id: "d1".to_owned(),
        line_limit: LINE_LIMIT,
        limits: default_limits(),
        run,
    };
    Ok(Fixture { dir, env })
}


fn updates_of(manager: Manager) -> SharedUpdates {
    Arc::new(ArcSwap::from_pointee(UpdateSettings {
        manager,
        interval_seconds: INTERVAL,
        deadline_seconds: DEADLINE,
    }))
}


fn source_of(max_spool_bytes: u64) -> SharedSource {
    Arc::new(ArcSwap::from_pointee(SourceSettings {
        max_spool_bytes,
        ..SourceSettings::default()
    }))
}


fn answer(bytes: &'static [u8]) -> UpdateFuture {
    Box::pin(async move { Ok(bytes.to_vec()) })
}


fn failing(error: SensorError) -> UpdateFuture {
    Box::pin(async move { Err(error) })
}


fn apt_ok(_: CommandSpec, _: Duration) -> UpdateFuture {
    answer(APT_LISTING)
}


fn dnf_ok(spec: CommandSpec, _: Duration) -> UpdateFuture {
    if spec.arguments.iter().any(|argument| argument == "updateinfo") {
        answer(DNF_UPDATEINFO)
    } else {
        answer(DNF_CHECK)
    }
}


fn timed_out(_: CommandSpec, _: Duration) -> UpdateFuture {
    failing(SensorError::Timeout)
}


fn too_large(_: CommandSpec, _: Duration) -> UpdateFuture {
    failing(SensorError::TooLarge(1))
}


fn exited(_: CommandSpec, _: Duration) -> UpdateFuture {
    failing(SensorError::Exit(Some(1)))
}


fn not_spawned(_: CommandSpec, _: Duration) -> UpdateFuture {
    failing(SensorError::Io(io::Error::other("no such program")))
}


fn quiet(_: Duration) -> PauseFuture {
    Box::pin(async {})
}


async fn run_rounds(fixture: &Fixture, updates: &SharedUpdates, source: &SharedSource, rounds: u64) -> Result<u64, SourceError> {
    run_updates(updates, source, &fixture.env, rounds, &quiet, &|| 0, &|| NOW).await
}


fn parsed(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(lines(path)?
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<Vec<Value>, _>>()?)
}


fn at<'a>(line: &'a Value, pointer: &str) -> Option<&'a Value> {
    line.pointer(pointer)
}


fn detail<'a>(line: &'a Value, name: &str) -> Option<&'a Value> {
    line.get("ostyr")?.get("update")?.get(name)
}


#[tokio::test]
async fn apt_updates_become_events_and_a_summary_with_one_run_id() -> TestResult {
    let fixture = fixture(apt_ok)?;
    assert_eq!(run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?, 1);
    let records = parsed(&fixture.env.spool)?;
    assert_eq!(records.len(), APT_UPDATES + 1);
    assert!(records.iter().all(|line| detail(line, "run_id") == Some(&Value::from(1))));
    let first = records.first().ok_or("no line")?;
    assert_eq!(at(first, "/event/dataset"), Some(&Value::from("ostyr.updates")));
    assert_eq!(at(first, "/event/kind"), Some(&Value::from("state")));
    assert_eq!(at(first, "/event/category/0"), Some(&Value::from("package")));
    assert_eq!(at(first, "/event/type/0"), Some(&Value::from("info")));
    assert!(at(first, "/package/name").is_some_and(Value::is_string));
    assert!(at(first, "/package/version").is_some_and(Value::is_string));
    assert_eq!(detail(first, "security"), Some(&Value::Bool(true)));
    assert!(detail(first, "origin").is_some());
    assert!(detail(first, "advisory").is_none());
    let summary = records.last().ok_or("no summary")?;
    assert_eq!(at(summary, "/event/dataset"), Some(&Value::from("ostyr.updates.summary")));
    assert_eq!(detail(summary, "count"), Some(&Value::from(APT_UPDATES)));
    assert_eq!(detail(summary, "outcome"), Some(&Value::from("ok")));
    assert!(detail(summary, "lists_age_seconds").is_some());
    assert_eq!(fs::read_to_string(&fixture.env.counter_file)?, "1\n");
    Ok(())
}


#[tokio::test]
async fn dnf_updates_carry_advisories_and_no_lists_age() -> TestResult {
    let fixture = fixture(dnf_ok)?;
    run_rounds(&fixture, &updates_of(Manager::Dnf), &source_of(u64::MAX), 1).await?;
    let records = parsed(&fixture.env.spool)?;
    let summary = records.last().ok_or("no summary")?;
    assert_eq!(detail(summary, "outcome"), Some(&Value::from("ok")));
    assert!(detail(summary, "lists_age_seconds").is_none());
    assert_eq!(detail(summary, "count"), Some(&Value::from(records.len() - 1)));
    assert!(records.len() > 1);
    assert!(records.iter().any(|line| detail(line, "advisory").is_some()));
    Ok(())
}


#[tokio::test]
async fn every_failed_run_appends_only_a_summary_with_its_outcome() -> TestResult {
    let cases: [(UpdateRunFn, &str); FAILURE_KINDS] = [
        (timed_out, "timed_out"),
        (too_large, "too_large"),
        (exited, "exit"),
        (not_spawned, "spawn"),
    ];
    for (run, outcome) in cases {
        for manager in [Manager::Apt, Manager::Dnf] {
            let fixture = fixture(run)?;
            assert_eq!(run_rounds(&fixture, &updates_of(manager), &source_of(u64::MAX), 1).await?, 1);
            let records = parsed(&fixture.env.spool)?;
            assert_eq!(records.len(), 1);
            let summary = records.first().ok_or("no summary")?;
            assert_eq!(detail(summary, "outcome"), Some(&Value::from(outcome)));
            assert_eq!(detail(summary, "count"), Some(&Value::from(0)));
        }
    }
    Ok(())
}


#[tokio::test]
async fn output_over_the_line_count_is_a_too_large_run() -> TestResult {
    let mut fixture = fixture(apt_ok)?;
    fixture.env.limits = Limits {
        max_lines: 1,
        ..default_limits()
    };
    assert!(matches!(collect_apt(&fixture.env, SHORT_DEADLINE).await, Err(Failure::TooLarge)));
    assert!(matches!(collect_dnf(&fixture.env, SHORT_DEADLINE).await, Err(Failure::TooLarge)));
    Ok(())
}


#[test]
fn errors_map_to_the_outcomes() -> TestResult {
    assert_eq!(
        failure_of_command(SensorError::Utf8(
            String::from_utf8(vec![INVALID_BYTE]).err().ok_or("valid")?.utf8_error()
        )),
        Failure::Exit
    );
    assert_eq!(failure_of_command(SensorError::Parse), Failure::Exit);
    assert_eq!(failure_of_command(SensorError::Exit(None)), Failure::Exit);
    assert_eq!(failure_of_inventory(&InventoryError::Read(io::Error::other("x"))), Failure::Spawn);
    assert_eq!(failure_of_inventory(&InventoryError::TooLarge { limit: 1 }), Failure::TooLarge);
    assert_eq!(failure_of_inventory(&InventoryError::TooManyLines { limit: 1 }), Failure::TooLarge);
    assert_eq!(
        [Failure::TimedOut, Failure::TooLarge, Failure::Exit, Failure::Spawn].map(outcome_name),
        ["timed_out", "too_large", "exit", "spawn"]
    );
    assert_eq!(
        [
            SkipReason::Malformed,
            SkipReason::ControlCharacters,
            SkipReason::LineTooLong,
            SkipReason::UnparsableVersion
        ]
        .map(skip_name),
        ["malformed", "control_characters", "line_too_long", "unparsable_version"]
    );
    Ok(())
}


#[test]
fn commands_have_fixed_programs_arguments_and_environment() -> TestResult {
    let spec = command("/usr/bin/dnf", &["-q", "check-update"], &[0, DNF_CHECK_UPDATE_AVAILABLE], SMALL_CAP);
    assert_eq!(spec.arguments, vec!["-q".to_owned(), "check-update".to_owned()]);
    assert_eq!(spec.accepted_codes, vec![0, CODE_AVAILABLE]);
    assert_eq!(spec.max_output, SMALL_CAP);
    assert_eq!(
        child_environment(),
        vec![
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("PATH".to_owned(), "/usr/sbin:/usr/bin:/sbin:/bin".to_owned())
        ]
    );
    Ok(())
}


fn documented(program: &str, arguments: &[&str], codes: &[i32]) -> CommandSpec {
    CommandSpec {
        program: PathBuf::from(program),
        arguments: arguments.iter().map(|argument| (*argument).to_owned()).collect(),
        environment: Some(child_environment()),
        accepted_codes: codes.to_vec(),
        max_output: default_limits().max_bytes as u64,
    }
}


fn only_documented(spec: CommandSpec, _: Duration) -> UpdateFuture {
    if spec == documented("/usr/bin/apt", &["list", "--upgradable"], &[0]) {
        answer(APT_LISTING)
    } else if spec == documented("/usr/bin/dnf", &["-q", "updateinfo", "list", "--updates"], &[0]) {
        answer(DNF_UPDATEINFO)
    } else if spec == documented("/usr/bin/dnf", &["-q", "check-update"], &[0, DNF_CHECK_UPDATE_AVAILABLE]) {
        answer(DNF_CHECK)
    } else {
        failing(SensorError::Exit(None))
    }
}


#[tokio::test]
async fn the_agent_runs_exactly_the_documented_commands() -> TestResult {
    let fixture = fixture(only_documented)?;
    run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?;
    run_rounds(&fixture, &updates_of(Manager::Dnf), &source_of(u64::MAX), 1).await?;
    let outcomes: Vec<Value> = parsed(&fixture.env.spool)?
        .into_iter()
        .filter(|line| at(line, "/event/dataset") == Some(&Value::from("ostyr.updates.summary")))
        .filter_map(|line| detail(&line, "outcome").cloned())
        .collect();
    assert_eq!(outcomes, vec![Value::from("ok"), Value::from("ok")]);
    Ok(())
}


#[tokio::test]
async fn a_run_over_the_spool_bound_appends_only_a_spool_full_summary() -> TestResult {
    let fixture = fixture(apt_ok)?;
    run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(TINY_SPOOL), 1).await?;
    let records = parsed(&fixture.env.spool)?;
    assert_eq!(records.len(), 1);
    let summary = records.first().ok_or("no summary")?;
    assert_eq!(detail(summary, "outcome"), Some(&Value::from("spool_full")));
    assert_eq!(detail(summary, "count"), Some(&Value::from(0)));
    Ok(())
}


#[tokio::test]
async fn events_over_the_line_limit_are_counted_not_spooled() -> TestResult {
    let mut fixture = fixture(apt_ok)?;
    fixture.env.line_limit = TINY_LINE_LIMIT;
    run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?;
    let records = parsed(&fixture.env.spool)?;
    assert_eq!(records.len(), 1);
    let summary = records.first().ok_or("no summary")?;
    assert_eq!(at(summary, "/ostyr/update/skipped/event_too_long"), Some(&Value::from(APT_UPDATES)));
    assert_eq!(detail(summary, "count"), Some(&Value::from(0)));
    Ok(())
}


#[tokio::test]
async fn manager_none_runs_nothing() -> TestResult {
    let fixture = fixture(exited)?;
    assert_eq!(run_rounds(&fixture, &updates_of(Manager::None), &source_of(u64::MAX), TWO).await?, 0);
    assert!(!fixture.env.spool.exists());
    assert!(!fixture.env.counter_file.exists());
    Ok(())
}


static SWAPPED: OnceLock<SharedUpdates> = OnceLock::new();


fn swapping(_: CommandSpec, _: Duration) -> UpdateFuture {
    SWAPPED
        .get()
        .into_iter()
        .for_each(|shared| shared.store(Arc::new(UpdateSettings::default())));
    answer(APT_LISTING)
}


#[tokio::test]
async fn a_swap_during_a_run_applies_to_the_next_run_only() -> TestResult {
    let fixture = fixture(swapping)?;
    let shared = updates_of(Manager::Apt);
    SWAPPED.set(Arc::clone(&shared)).map_err(|_| "set twice")?;
    assert_eq!(run_rounds(&fixture, &shared, &source_of(u64::MAX), TWO).await?, 1);
    assert_eq!(parsed(&fixture.env.spool)?.len(), APT_UPDATES + 1);
    assert_eq!(shared.load().manager, Manager::None);
    Ok(())
}


#[tokio::test]
async fn the_pause_is_the_interval_minus_the_time_the_run_took() -> TestResult {
    let fixture = fixture(apt_ok)?;
    let pauses = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&pauses);
    let pause = move |delay: Duration| -> PauseFuture {
        recorded.lock().push(delay);
        Box::pin(async {})
    };
    let ticks = std::sync::atomic::AtomicU64::new(0);
    let clock = move || ticks.fetch_add(ELAPSED, std::sync::atomic::Ordering::SeqCst);
    run_updates(
        &updates_of(Manager::Apt),
        &source_of(u64::MAX),
        &fixture.env,
        TWO,
        &pause,
        &clock,
        &|| NOW,
    )
    .await?;
    assert_eq!(*pauses.lock(), vec![Duration::from_secs(INTERVAL - ELAPSED); STRING_ROUNDS]);
    Ok(())
}


#[tokio::test]
async fn run_ids_persist_and_increase_across_restarts() -> TestResult {
    let first = fixture(apt_ok)?;
    run_rounds(&first, &updates_of(Manager::Apt), &source_of(u64::MAX), TWO).await?;
    let restarted = Fixture {
        env: UpdateEnv {
            state: Arc::new(open_state_dir(&first.dir.path().join("cursor"))?),
            ..first.env.clone()
        },
        dir: first.dir,
    };
    run_rounds(&restarted, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?;
    let ids: Vec<u64> = parsed(&restarted.env.spool)?
        .iter()
        .filter(|line| at(line, "/event/dataset") == Some(&Value::from("ostyr.updates.summary")))
        .filter_map(|line| detail(line, "run_id").and_then(Value::as_u64))
        .collect();
    assert_eq!(ids, vec![1, TWO, THREE]);
    assert_eq!(read_counter(&restarted.env.state, &restarted.env.counter_file)?, THREE);
    Ok(())
}


#[tokio::test]
async fn a_run_id_that_cannot_be_persisted_appends_nothing() -> TestResult {
    let mut fixture = fixture(apt_ok)?;
    fixture.env.counter_file = PathBuf::from("/");
    assert_eq!(run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?, 0);
    assert!(!fixture.env.spool.exists());
    fs::write(fixture.dir.path().join("cursor.updates-run"), format!("{}\n", u64::MAX))?;
    fixture.env.counter_file = fixture.dir.path().join("cursor.updates-run");
    assert!(matches!(
        next_run_id(&fixture.env.state, &fixture.env.counter_file),
        Err(SourceError::Counter(_))
    ));
    assert_eq!(run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await?, 0);
    fs::write(&fixture.env.counter_file, "garbage")?;
    assert!(matches!(
        read_counter(&fixture.env.state, &fixture.env.counter_file),
        Err(SourceError::Counter(_))
    ));
    assert!(!fixture.env.spool.exists());
    Ok(())
}


#[test]
fn a_spool_that_cannot_be_measured_fails_the_run() -> TestResult {
    let mut fixture = fixture(apt_ok)?;
    fixture.env.spool = fixture.dir.path().join("spool-file").join("below");
    fs::write(fixture.dir.path().join("spool-file"), "x")?;
    let collected = Ok(patch_inventory::model::Inventory {
        updates: Vec::new(),
        skipped: SkipCounts::new(),
    });
    assert!(publish(&fixture.env, Manager::Dnf, &SourceSettings::default(), &collected, NOW).is_err());
    Ok(())
}


#[tokio::test]
async fn a_failing_spool_write_ends_the_loop() -> TestResult {
    let mut fixture = fixture(apt_ok)?;
    fs::create_dir(fixture.dir.path().join("spool-dir"))?;
    fixture.env.spool = fixture.dir.path().join("spool-dir");
    assert!(run_rounds(&fixture, &updates_of(Manager::Apt), &source_of(u64::MAX), 1).await.is_err());
    Ok(())
}


#[test]
fn the_lists_age_is_read_from_the_newest_regular_file() -> TestResult {
    let fixture = fixture(apt_ok)?;
    let age = lists_age(&fixture.env.lists_dir, u64::MAX).ok_or("no age")?;
    assert!(age > NOW);
    assert_eq!(lists_age(&fixture.env.lists_dir, 0), Some(0));
    let empty = fixture.dir.path().join("empty");
    fs::create_dir(&empty)?;
    assert_eq!(lists_age(&empty, NOW), None);
    assert_eq!(lists_age(&fixture.dir.path().join("absent"), NOW), None);
    Ok(())
}


#[test]
fn an_event_has_only_the_fields_it_knows() -> TestResult {
    let bare = Update {
        tenant: "t".to_owned(),
        device_id: "d".to_owned(),
        package: "curl".to_owned(),
        architecture: "amd64".to_owned(),
        installed_version: None,
        candidate_version: "2".to_owned(),
        origin: None,
        security: false,
        advisory_id: None,
        severity: None,
    };
    let bare_line: Value = serde_json::from_str(&event_line(RUN_ID, &bare))?;
    assert!(at(&bare_line, "/package/version").is_none());
    assert!(at(&bare_line, "/ostyr/update/origin").is_none());
    assert!(at(&bare_line, "/ostyr/update/severity").is_none());
    let full = Update {
        installed_version: Some("1".to_owned()),
        origin: Some("noble".to_owned()),
        advisory_id: Some("RLSA-1".to_owned()),
        severity: Some("important".to_owned()),
        ..bare
    };
    let full_line: Value = serde_json::from_str(&event_line(RUN_ID, &full))?;
    assert_eq!(at(&full_line, "/package/version"), Some(&Value::from("1")));
    assert_eq!(at(&full_line, "/ostyr/update/severity"), Some(&Value::from("important")));
    let skipped: SkipCounts = [(SkipReason::Malformed, STRING_ROUNDS)].into_iter().collect();
    let summary: Value = serde_json::from_str(&summary_line(RUN_ID, "ok", 1, &skipped, 0, None))?;
    assert_eq!(at(&summary, "/ostyr/update/skipped/malformed"), Some(&Value::from(STRING_ROUNDS)));
    assert!(at(&summary, "/ostyr/update/skipped/event_too_long").is_none());
    Ok(())
}


#[tokio::test]
async fn the_environment_is_cleared_to_exactly_two_variables() -> TestResult {
    let spec = CommandSpec {
        program: PathBuf::from("/usr/bin/env"),
        arguments: Vec::new(),
        environment: Some(child_environment()),
        accepted_codes: vec![0],
        max_output: ENV_CAP,
    };
    let output = run_spec_with(spec.clone(), refused_kill).await?;
    let mut variables: Vec<String> = String::from_utf8(output)?.lines().map(str::to_owned).collect();
    variables.sort();
    assert_eq!(variables, vec!["LC_ALL=C".to_owned(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_owned()]);
    let inherited = CommandSpec {
        environment: None,
        max_output: INHERITED_CAP,
        ..spec
    };
    let inherited_output = run_spec_with(inherited, refused_kill).await?;
    assert!(String::from_utf8(inherited_output)?.lines().count() > STRING_ROUNDS);
    Ok(())
}


fn refused_kill(_: Pid) -> rustix::io::Result<()> {
    Err(rustix::io::Errno::SRCH)
}


#[tokio::test]
async fn the_runner_accepts_only_listed_codes_caps_output_and_enforces_the_deadline() -> TestResult {
    let spec = |program: &str, arguments: &[&str], codes: &[i32], cap: u64| CommandSpec {
        program: PathBuf::from(program),
        arguments: arguments.iter().map(|argument| (*argument).to_owned()).collect(),
        environment: None,
        accepted_codes: codes.to_vec(),
        max_output: cap,
    };
    assert!(run_spec_with(spec("/bin/false", &[], &[0, 1], SMALL_CAP), refused_kill).await.is_ok());
    assert!(matches!(
        run_spec_with(spec("/bin/false", &[], &[0], SMALL_CAP), refused_kill).await,
        Err(SensorError::Exit(Some(1)))
    ));
    assert!(matches!(
        run_spec_with(spec("/usr/bin/yes", &[], &[0], SMALL_CAP), refused_kill).await,
        Err(SensorError::TooLarge(_))
    ));
    assert!(matches!(
        run_spec_with(spec("/nonexistent/program", &[], &[0], SMALL_CAP), refused_kill).await,
        Err(SensorError::Io(_))
    ));
    assert!(matches!(
        run_spec_deadline(spec("/bin/sleep", &[LONG_SLEEP_SECONDS], &[0], SMALL_CAP), SHORT_DEADLINE).await,
        Err(SensorError::Timeout)
    ));
    assert_eq!(
        run_update_command(spec("/bin/echo", &["hi"], &[0], SMALL_CAP), Duration::from_secs(DEADLINE)).await?,
        b"hi\n".to_vec()
    );
    Ok(())
}


#[tokio::test]
async fn a_grandchild_holding_the_pipe_is_killed_with_the_group() -> TestResult {
    let dir = tempdir()?;
    let script = dir.path().join("forker.sh");
    fs::write(&script, format!("#!/bin/sh\nsleep {LONG_SLEEP_SECONDS} &\nsleep {LONG_SLEEP_SECONDS}\n"))?;
    let spec = CommandSpec {
        program: PathBuf::from("/bin/sh"),
        arguments: vec![script.display().to_string()],
        environment: None,
        accepted_codes: vec![0],
        max_output: SMALL_CAP,
    };
    assert!(matches!(run_spec_deadline(spec, SHORT_DEADLINE).await, Err(SensorError::Timeout)));
    Ok(())
}

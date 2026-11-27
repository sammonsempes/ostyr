#[path = "winget_support/types.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use agent_windows::error::{PollError, RunError};
use agent_windows::model::{PollEnv, RunEnd, RunRequest, MAX_EVENTS_PER_POLL, WEVTUTIL_PATH};
use agent_windows::round::{run_winget_step, DefenderStep, RoundState, WingetHooks};
use agent_windows::settings::{Settings, MIN_SPOOL_BYTES};
use agent_windows::winget::{
    error_exit_code, error_name, failure_lines, inventory_lines, skip_name, summary_line, update_line, winget_arguments, winget_environment,
    winget_lines, SummaryFacts, WINGET_ARGUMENTS, WINGET_DEADLINE_SECONDS,
};
use agent_windows::winget_find::{FindError, Located};
use agent_windows::winget_round::{current_run_id, lines_that_fit, run_id_from, spool_winget};
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use patch_inventory::error::{InventoryError, WingetError};
use patch_inventory::limits::{default_limits, MAX_INPUT_BYTES};
use patch_inventory::model::{CliInventory, Update, WingetSkip};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use support::{Answer, Runs};
use types::TestResult;


const ONE: &[u8] = include_bytes!("../../patch-inventory/tests/fixtures/winget-cli-en-one.txt");


const TWO: &[u8] = include_bytes!("../../patch-inventory/tests/fixtures/winget-cli-en-two.txt");


const NONE: &[u8] = include_bytes!("../../patch-inventory/tests/fixtures/winget-cli-en-none.txt");


const MSSTORE: &[u8] = include_bytes!("../../patch-inventory/tests/fixtures/winget-cli-en-msstore.txt");


const PINNED: &[u8] = include_bytes!("../../patch-inventory/tests/fixtures/winget-cli-en-pinned.txt");


const WINGET_PATH: &str = r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.6.10121.0_x64__8wekyb3d8bbwe\winget.exe";


const VCLIBS: &str = r"C:\Program Files\WindowsApps\Microsoft.VCLibs.140.00.UWPDesktop_14.0.33519.0_x64__8wekyb3d8bbwe";


const RUN_ID: u64 = 77;


const LINE_LIMIT: usize = 524_288;


const LOCK_ATTEMPTS: u32 = 10;


const TWO_UPDATES: usize = 2;


const SOURCE_OPEN_EXIT: i32 = -1_978_335_157;


const OTHER_EXIT: i32 = 5;


const TINY_LIMIT: usize = 10;


const BIG_PENDING: u64 = 1_000;


const SMALL_LIMIT: u64 = 100;


const ONE_HOUR: u64 = 3_600;


const POLL: u64 = 10;


const EPOCH_PLUS: u64 = 12_345;


const EXPECTED_DEADLINE: u64 = 900;


const FILLED: usize = 300;


const TIGHT: u64 = 700;


const MID_LIMIT: u64 = 500;


const CASE_COUNT: usize = 4;


const SPOOL_NAME: &str = "spool";


fn located() -> Result<Located, FindError> {
    Ok(Located {
        winget: WINGET_PATH.to_owned(),
        vclibs_dir: VCLIBS.to_owned(),
    })
}


fn locate_ok() -> Result<Located, FindError> {
    located()
}


fn locate_missing() -> Result<Located, FindError> {
    Err(FindError::NotFound)
}


fn fixed_id() -> u64 {
    RUN_ID
}


fn outcome_of(line: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(line)
}


fn summary_of(lines: &[String]) -> Result<Value, Box<dyn std::error::Error>> {
    let last = lines.last().ok_or("no line")?;
    let value = outcome_of(last)?;
    Ok(value.get("ostyr").and_then(|ostyr| ostyr.get("update")).cloned().ok_or("no summary")?)
}


fn answer(output: &'static [u8], end: Result<RunEnd, RunError>) -> Answer {
    let mut pending = Some(end);
    Box::new(move |_, sink| {
        sink(output);
        pending.take().unwrap_or(Ok(RunEnd::Done))
    })
}


#[test]
fn a_captured_table_gives_one_line_per_update_and_a_summary_with_the_same_count() -> TestResult {
    let mut runner = answer(TWO, Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    assert_eq!(run.updates, TWO_UPDATES);
    assert_eq!(run.lines.len(), TWO_UPDATES + 1);
    let summary = summary_of(&run.lines)?;
    assert_eq!(summary.get("count").and_then(Value::as_u64), Some(TWO_UPDATES as u64));
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("ok"));
    assert_eq!(summary.get("run_id").and_then(Value::as_u64), Some(RUN_ID));
    assert!(summary.get("stale_source").is_none());
    let first = run.lines.first().ok_or("no update")?;
    let event = outcome_of(first)?;
    assert_eq!(event.pointer("/event/dataset").and_then(Value::as_str), Some("ostyr.updates"));
    assert_eq!(event.pointer("/ostyr/update/origin").and_then(Value::as_str), Some("winget"));
    assert_eq!(event.pointer("/ostyr/update/run_id").and_then(Value::as_u64), Some(RUN_ID));
    assert!(event.pointer("/package/name").and_then(Value::as_str).is_some());
    assert!(event.pointer("/package/version").and_then(Value::as_str).is_some());
    Ok(())
}


#[test]
fn the_preamble_of_a_stale_source_is_reported_on_the_summary() -> TestResult {
    let mut text = b"Failed in attempting to update the source: winget\r\n".to_vec();
    text.extend_from_slice(ONE);
    let leaked: &'static [u8] = Box::leak(text.into_boxed_slice());
    let mut runner = answer(leaked, Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    let summary = summary_of(&run.lines)?;
    assert_eq!(summary.get("stale_source").and_then(Value::as_bool), Some(true));
    assert!(summary.get("preamble_lines").and_then(Value::as_u64).is_some_and(|count| count > 0));
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("ok"));
    Ok(())
}


#[test]
fn a_parser_error_is_one_named_summary_and_no_update_line() -> TestResult {
    let mut runner = answer(b"not a table\r\nnor this\r\n", Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    assert_eq!(run.updates, 0);
    assert_eq!(run.lines.len(), 1);
    let summary = summary_of(&run.lines)?;
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("unrecognised_layout"));
    assert_eq!(summary.get("count").and_then(Value::as_u64), Some(0));
    Ok(())
}


#[test]
fn a_line_break_inside_the_table_refuses_the_whole_run_loudly() -> TestResult {
    let forged: Vec<u8> = ONE.iter().map(|byte| if *byte == b'.' { b'\r' } else { *byte }).collect();
    let leaked: &'static [u8] = Box::leak(forged.into_boxed_slice());
    let mut runner = answer(leaked, Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    assert_eq!(run.updates, 0);
    let summary = summary_of(&run.lines)?;
    assert_ne!(summary.get("outcome").and_then(Value::as_str), Some("ok"));
    Ok(())
}


#[test]
fn nothing_to_upgrade_is_an_ok_summary_of_zero() -> TestResult {
    let mut runner = answer(NONE, Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    let summary = summary_of(&run.lines)?;
    assert_eq!((run.updates, run.lines.len()), (0, 1));
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("ok"));
    Ok(())
}


#[test]
fn a_pinned_package_sentence_is_never_read_as_a_row() -> TestResult {
    let mut runner = answer(PINNED, Ok(RunEnd::Done));
    let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    let summary = summary_of(&run.lines)?;
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("ok"));
    Ok(())
}


#[test]
fn a_non_zero_exit_passes_its_code_to_the_parser() -> TestResult {
    let mut open_failed = answer(MSSTORE, Ok(RunEnd::Failed(Some(SOURCE_OPEN_EXIT))));
    let first = summary_of(&winget_lines(&mut open_failed, &located(), RUN_ID, LINE_LIMIT).lines)?;
    assert_eq!(first.get("outcome").and_then(Value::as_str), Some("source_open_failed"));
    let mut other = answer(MSSTORE, Ok(RunEnd::Failed(Some(OTHER_EXIT))));
    let second = summary_of(&winget_lines(&mut other, &located(), RUN_ID, LINE_LIMIT).lines)?;
    assert_eq!(second.get("outcome").and_then(Value::as_str), Some("exit_nonzero"));
    assert_eq!(second.get("exit_code").and_then(Value::as_i64), Some(i64::from(OTHER_EXIT)));
    Ok(())
}


#[test]
fn a_run_without_an_exit_code_the_cap_the_deadline_and_a_spawn_failure_are_named_outcomes() -> TestResult {
    let cases: [(Result<RunEnd, RunError>, &str); CASE_COUNT] = [
        (Ok(RunEnd::Failed(None)), "no_exit_code"),
        (Ok(RunEnd::Capped), "output_capped"),
        (Ok(RunEnd::Deadline), "deadline"),
        (Err(RunError::Reader), "spawn_failed"),
    ];
    cases.into_iter().try_for_each(|(end, name)| -> TestResult {
        let mut runner = answer(ONE, end);
        let run = winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
        assert_eq!((run.updates, run.lines.len()), (0, 1));
        let summary = summary_of(&run.lines)?;
        assert_eq!(summary.get("outcome").and_then(Value::as_str), Some(name));
        assert!(summary.get("exit_code").is_none());
        Ok(())
    })
}


#[test]
fn a_missing_program_runs_nothing_and_is_named() -> TestResult {
    let runs = Cell::new(0usize);
    let mut runner = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        runs.set(runs.get() + 1);
        Ok(RunEnd::Done)
    };
    let run = winget_lines(&mut runner, &locate_missing(), RUN_ID, LINE_LIMIT);
    let summary = summary_of(&run.lines)?;
    assert_eq!(runs.get(), 0);
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("winget_not_found"));
    Ok(())
}


#[test]
fn the_program_arguments_environment_cap_and_deadline_equal_the_consts() -> TestResult {
    let seen: Runs = RefCell::new(Vec::new());
    let mut runner = |request: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        seen.borrow_mut().push((
            request.program.to_owned(),
            request.args.to_vec(),
            request.environment.map_or_else(Vec::new, |pairs| {
                pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
            }),
            request.max_bytes,
            request.deadline_seconds,
        ));
        Ok(RunEnd::Done)
    };
    winget_lines(&mut runner, &located(), RUN_ID, LINE_LIMIT);
    let runs = seen.borrow();
    let (program, args, environment, max_bytes, deadline) = runs.first().ok_or("no run")?;
    assert_eq!(program, WINGET_PATH);
    assert_eq!(
        args,
        &["upgrade", "--source", "winget", "--accept-source-agreements", "--disable-interactivity"]
            .map(str::to_owned)
            .to_vec()
    );
    assert_eq!(
        environment,
        &vec![
            ("PATH".to_owned(), VCLIBS.to_owned()),
            ("SystemRoot".to_owned(), r"C:\Windows".to_owned())
        ]
    );
    assert_eq!(*max_bytes, MAX_INPUT_BYTES);
    assert_eq!(*max_bytes, default_limits().max_bytes);
    assert_eq!(*deadline, WINGET_DEADLINE_SECONDS);
    assert_eq!(WINGET_DEADLINE_SECONDS, EXPECTED_DEADLINE);
    assert_eq!(winget_arguments().len(), WINGET_ARGUMENTS.len());
    assert_eq!(winget_environment(VCLIBS).len(), TWO_UPDATES);
    Ok(())
}


fn update(name: &str, version: &str) -> Update {
    Update {
        tenant: "t".to_owned(),
        device_id: "d".to_owned(),
        package: name.to_owned(),
        architecture: "any".to_owned(),
        installed_version: Some(version.to_owned()),
        candidate_version: "9.9".to_owned(),
        origin: Some("winget".to_owned()),
        security: false,
        advisory_id: None,
        severity: None,
    }
}


fn inventory(updates: Vec<Update>, skips: &[(WingetSkip, usize)], preamble: usize) -> CliInventory {
    CliInventory {
        updates,
        skipped: skips.iter().copied().collect(),
        preamble_lines: preamble,
    }
}


#[test]
fn a_hostile_name_reaches_the_spool_only_escaped_by_json() -> TestResult {
    let hostile = update("A.B\r\n\u{1b}[31m\"}{\"event\":1", "1.0");
    let line = update_line(RUN_ID, &hostile);
    assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
    let parsed = outcome_of(&line)?;
    assert_eq!(parsed.pointer("/package/name").and_then(Value::as_str), Some(hostile.package.as_str()));
    Ok(())
}


#[test]
fn an_update_without_an_installed_version_has_no_version_field() -> TestResult {
    let mut unknown = update("A.B", "1.0");
    unknown.installed_version = None;
    let parsed = outcome_of(&update_line(RUN_ID, &unknown))?;
    assert!(parsed.pointer("/package/version").is_none());
    Ok(())
}


#[test]
fn a_table_of_malformed_rows_only_is_never_ok() -> TestResult {
    let run = inventory_lines(RUN_ID, LINE_LIMIT, &inventory(Vec::new(), &[(WingetSkip::Malformed, TWO_UPDATES)], 0));
    let summary = summary_of(&run.lines)?;
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("all_rows_malformed"));
    assert_eq!(
        summary.pointer("/skipped/winget_malformed").and_then(Value::as_u64),
        Some(TWO_UPDATES as u64)
    );
    let other = inventory_lines(RUN_ID, LINE_LIMIT, &inventory(Vec::new(), &[(WingetSkip::Duplicate, 1)], 0));
    assert_eq!(summary_of(&other.lines)?.get("outcome").and_then(Value::as_str), Some("ok"));
    let mixed = inventory_lines(
        RUN_ID,
        LINE_LIMIT,
        &inventory(vec![update("A.B", "1.0")], &[(WingetSkip::Malformed, 1)], 0),
    );
    assert_eq!(summary_of(&mixed.lines)?.get("outcome").and_then(Value::as_str), Some("ok"));
    Ok(())
}


#[test]
fn an_event_line_over_the_limit_is_skipped_and_counted() -> TestResult {
    let run = inventory_lines(RUN_ID, TINY_LIMIT, &inventory(vec![update("A.B", "1.0")], &[], 0));
    let summary = summary_of(&run.lines)?;
    assert_eq!((run.updates, run.lines.len()), (0, 1));
    assert_eq!(summary.pointer("/skipped/event_too_long").and_then(Value::as_u64), Some(1));
    Ok(())
}


#[test]
fn every_skip_and_error_has_its_own_name() -> TestResult {
    let skips = [
        WingetSkip::Malformed,
        WingetSkip::UnknownInstalledVersion,
        WingetSkip::Duplicate,
        WingetSkip::Truncated,
        WingetSkip::LineTooLong,
        WingetSkip::ControlCharacters,
    ];
    let names: Vec<&str> = skips.iter().map(|skip| skip_name(*skip)).collect();
    assert!(names.iter().all(|name| name.starts_with("winget_")));
    assert_eq!(names.iter().collect::<std::collections::BTreeSet<_>>().len(), skips.len());
    let errors = [
        WingetError::Input(InventoryError::TooLarge { limit: 1 }),
        WingetError::Input(InventoryError::TooManyLines { limit: 1 }),
        WingetError::Encoding,
        WingetError::SourceOpenFailed,
        WingetError::Exit { code: 1 },
        WingetError::UnrecognisedLayout,
        WingetError::TooManyTables { limit: 1 },
        WingetError::TooManyUpdates { limit: 1 },
        WingetError::FooterUnreadable,
        WingetError::FooterMissing,
        WingetError::RowAfterTableEnd,
        WingetError::LineBreakInTable,
        WingetError::FooterTooLarge,
        WingetError::FooterMismatch {
            footer: 1,
            rows: TWO_UPDATES,
        },
    ];
    let error_names: std::collections::BTreeSet<&str> = errors.iter().map(error_name).collect();
    assert_eq!(error_names.len(), errors.len());
    assert_eq!(error_exit_code(&WingetError::Exit { code: OTHER_EXIT }), Some(OTHER_EXIT));
    assert_eq!(error_exit_code(&WingetError::Encoding), None);
    Ok(())
}


#[test]
fn the_summary_carries_the_truncation_and_the_exit_code_only_when_set() -> TestResult {
    let bare = summary_of(&[failure_lines(RUN_ID, "x", None).lines.concat()])?;
    assert!(bare.get("truncated").is_none() && bare.get("exit_code").is_none());
    let facts = SummaryFacts {
        truncated: 1,
        exit_code: Some(1),
        ..SummaryFacts::default()
    };
    let full = summary_of(&[summary_line(&facts)])?;
    assert_eq!(full.get("truncated").and_then(Value::as_u64), Some(1));
    assert_eq!(full.get("exit_code").and_then(Value::as_i64), Some(1));
    Ok(())
}


#[test]
fn the_run_id_is_the_epoch_second_and_a_clock_before_the_epoch_is_zero() -> TestResult {
    assert_eq!(run_id_from(UNIX_EPOCH + Duration::from_secs(EPOCH_PLUS)), EPOCH_PLUS);
    assert_eq!(run_id_from(UNIX_EPOCH - Duration::from_secs(1)), 0);
    assert!(current_run_id() > EPOCH_PLUS);
    Ok(())
}


#[test]
fn lines_that_do_not_fit_become_the_spool_full_summary_and_then_nothing() -> TestResult {
    let lines = vec!["x".repeat(BIG_PENDING as usize)];
    let kept = lines_that_fit(lines.clone(), RUN_ID, 0, SMALL_LIMIT).ok_or("empty spool takes one run")?;
    assert_eq!(kept, lines);
    let replaced = lines_that_fit(lines.clone(), RUN_ID, 1, MID_LIMIT).ok_or("replacement")?;
    assert_eq!(replaced.len(), 1);
    let summary = summary_of(&replaced)?;
    assert_eq!(summary.get("outcome").and_then(Value::as_str), Some("spool_full"));
    assert!(lines_that_fit(lines, RUN_ID, BIG_PENDING, BIG_PENDING).is_none());
    Ok(())
}


struct Lab {
    spool: std::path::PathBuf,
    state: std::path::PathBuf,
    _directory: tempfile::TempDir,
}


fn lab() -> Result<Lab, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    Ok(Lab {
        spool: directory.path().join(SPOOL_NAME),
        state: directory.path().to_path_buf(),
        _directory: directory,
    })
}


fn env_of<'a>(lab: &'a Lab, run: agent_windows::types::Runner<'a>, seen: &'a mut SeenIds, spool: &'a Path) -> PollEnv<'a> {
    PollEnv {
        run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &lab.state,
        spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: 1,
        deadline_seconds: 1,
        max_spool_bytes: MIN_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen,
    }
}


fn hooks() -> WingetHooks {
    WingetHooks {
        locate: locate_ok,
        run_id: fixed_id,
    }
}


#[test]
fn a_run_is_appended_in_one_write_and_the_step_reports_appended() -> TestResult {
    let lab = lab()?;
    let mut runner = answer(TWO, Ok(RunEnd::Done));
    let mut seen = SeenIds::new();
    let mut env = env_of(&lab, &mut runner, &mut seen, &lab.spool);
    let mut blocked = true;
    assert_eq!(spool_winget(&mut env, &hooks(), &mut blocked)?, DefenderStep::Appended);
    assert!(!blocked);
    let text = fs::read_to_string(&lab.spool)?;
    assert_eq!(text.lines().count(), TWO_UPDATES + 1);
    Ok(())
}


#[test]
fn a_full_spool_runs_nothing_and_warns_once() -> TestResult {
    let lab = lab()?;
    let runs = Cell::new(0usize);
    let mut runner = |_: &RunRequest<'_>, _: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        runs.set(runs.get() + 1);
        Ok(RunEnd::Done)
    };
    let mut seen = SeenIds::new();
    let mut env = env_of(&lab, &mut runner, &mut seen, &lab.spool);
    fs::write(&lab.spool, vec![b'x'; usize::try_from(MIN_SPOOL_BYTES)?])?;
    let mut blocked = false;
    assert_eq!(spool_winget(&mut env, &hooks(), &mut blocked)?, DefenderStep::NoRoom);
    assert!(blocked);
    assert_eq!(spool_winget(&mut env, &hooks(), &mut blocked)?, DefenderStep::NoRoom);
    assert_eq!(runs.get(), 0);
    Ok(())
}


#[test]
fn a_run_that_does_not_fit_is_the_spool_full_summary_and_a_summary_that_does_not_fit_is_refused() -> TestResult {
    let lab = lab()?;
    let mut runner = answer(TWO, Ok(RunEnd::Done));
    let mut seen = SeenIds::new();
    let mut env = env_of(&lab, &mut runner, &mut seen, &lab.spool);
    env.max_spool_bytes = TIGHT;
    fs::write(&lab.spool, vec![b'x'; FILLED])?;
    let mut blocked = false;
    assert_eq!(spool_winget(&mut env, &hooks(), &mut blocked)?, DefenderStep::Appended);
    let text = fs::read_to_string(&lab.spool)?;
    assert!(text.contains("spool_full"));
    let mut second = answer(TWO, Ok(RunEnd::Done));
    let mut seen_again = SeenIds::new();
    let mut env_again = env_of(&lab, &mut second, &mut seen_again, &lab.spool);
    env_again.max_spool_bytes = text.len() as u64 + 1;
    let mut blocked_again = false;
    assert_eq!(spool_winget(&mut env_again, &hooks(), &mut blocked_again)?, DefenderStep::Refused);
    assert!(blocked_again);
    assert_eq!(spool_winget(&mut env_again, &hooks(), &mut blocked_again)?, DefenderStep::Refused);
    Ok(())
}


#[test]
fn a_spool_that_is_a_directory_is_a_named_error() -> TestResult {
    let lab = lab()?;
    let mut runner = answer(TWO, Ok(RunEnd::Done));
    let mut seen = SeenIds::new();
    let directory = lab.state.join("dir");
    fs::create_dir(&directory)?;
    let mut env = env_of(&lab, &mut runner, &mut seen, &directory);
    let mut blocked = false;
    assert!(matches!(spool_winget(&mut env, &hooks(), &mut blocked), Err(PollError::SpoolSize(_))));
    Ok(())
}


#[test]
fn an_append_failure_is_a_spool_error() -> TestResult {
    let lab = lab()?;
    let mut runner = answer(TWO, Ok(RunEnd::Done));
    let mut seen = SeenIds::new();
    let missing = lab.state.join("absent").join(SPOOL_NAME);
    let mut env = env_of(&lab, &mut runner, &mut seen, &missing);
    let mut blocked = false;
    assert!(matches!(spool_winget(&mut env, &hooks(), &mut blocked), Err(PollError::Spool(_))));
    Ok(())
}


#[test]
fn the_cadence_runs_when_due_waits_otherwise_and_stays_off_without_hooks() -> TestResult {
    let lab = lab()?;
    let runs = Cell::new(0usize);
    let mut runner = |_: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        runs.set(runs.get() + 1);
        sink(NONE);
        Ok(RunEnd::Done)
    };
    let mut seen = SeenIds::new();
    let mut env = env_of(&lab, &mut runner, &mut seen, &lab.spool);
    let settings = Settings {
        updates_interval_seconds: ONE_HOUR,
        poll_interval_seconds: POLL,
        ..Settings::default()
    };
    let mut off = RoundState::default();
    assert!(!run_winget_step(&mut env, &mut off, &settings)?);
    let mut round = RoundState {
        winget: Some(hooks()),
        ..RoundState::default()
    };
    assert!(run_winget_step(&mut env, &mut round, &settings)?);
    assert_eq!(round.winget_waited, Some(POLL));
    assert!(!run_winget_step(&mut env, &mut round, &settings)?);
    assert_eq!(round.winget_waited, Some(POLL + POLL));
    assert_eq!(runs.get(), 1);
    round.winget_waited = Some(ONE_HOUR);
    assert!(run_winget_step(&mut env, &mut round, &settings)?);
    assert_eq!(runs.get(), TWO_UPDATES);
    fs::write(&lab.spool, vec![b'x'; usize::try_from(MIN_SPOOL_BYTES)?])?;
    round.winget_waited = Some(ONE_HOUR);
    assert!(!run_winget_step(&mut env, &mut round, &settings)?);
    assert_eq!(round.winget_waited, Some(ONE_HOUR));
    assert_eq!(runs.get(), TWO_UPDATES);
    Ok(())
}

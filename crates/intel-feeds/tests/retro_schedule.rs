#[path = "common/types.rs"]
mod types;


use intel_feeds::config::{ClickhouseConfig, FeedsFile, RetroSection};
use intel_feeds::retro::{Gap, RetroError, RetroRun, RetroSummary};
use intel_feeds::retro_alerts::AlertsError;
use intel_feeds::retro_schedule::{
    due_in, pass, round, run_schedule, window_of, Hooks, RoundFailure, RoundOutcome, ScheduleState, WAIT_SLICE_SECONDS,
};
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::Duration;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const DICTIONARY_PORT: u16 = 9440;


const TIMEOUT_MS: u64 = 5_000;


const MATCHES: usize = 3;


const EXEC_SECONDS: u32 = 30;


const READ_ROWS: u64 = 1_000_000;


const GROUP_ROWS: u64 = 10_000;


const FAR_FUTURE: OffsetDateTime = datetime!(9999-12-31 23:59:59 UTC);


const HOUR: i64 = 3_600;


const TEN: i64 = 10;


const PAIR: usize = 2;


const PAIR_RUNS: u32 = 2;


const PASS_CAP: u64 = 300;


const T0: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const INTERVAL: u64 = 600;


const WINDOW: u64 = 900;


const MARGIN: u64 = 300;


fn section() -> RetroSection {
    RetroSection {
        reader: ClickhouseConfig {
            url: "http://127.0.0.1:8123".to_owned(),
            user: "retro_reader".to_owned(),
            password_file: "/nonexistent/password".into(),
            ca_file: None,
            database: "ostyr".to_owned(),
            table: "iocs".to_owned(),
            dictionary: "ioc_trie".to_owned(),
            dictionary_user: "ostyr_dict".to_owned(),
            dictionary_port: DICTIONARY_PORT,
            timeout_ms: TIMEOUT_MS,
            tenant: "tenant-a".to_owned(),
        },
        events_database: "ostyr".to_owned(),
        events_table: "events".to_owned(),
        max_matches: MATCHES,
        max_execution_seconds: EXEC_SECONDS,
        max_rows_to_read: READ_ROWS,
        max_rows_to_group_by: GROUP_ROWS,
        interval_seconds: INTERVAL,
        window_seconds: WINDOW,
        margin_seconds: MARGIN,
        pg_settings: "pg.yaml".into(),
    }
}


fn run_of(start: OffsetDateTime, end: OffsetDateTime, gap: Option<Gap>) -> RetroRun {
    RetroRun {
        groups: Vec::new(),
        summary: RetroSummary {
            tenant: "tenant-a".to_owned(),
            window_start: start,
            window_end: end,
            groups: 0,
            more_than: None,
            truncated: false,
            not_an_ip: 0,
            gap,
        },
    }
}


fn after(seconds: i64) -> OffsetDateTime {
    T0 + time::Duration::seconds(seconds)
}


#[test]
fn the_window_ends_now_and_covers_the_interval_plus_the_margin() -> TestResult {
    let (start, end) = window_of(&section(), T0).ok_or("window")?;
    assert_eq!((start, end), (after(-(WINDOW as i64)), T0));
    let mut huge = section();
    huge.window_seconds = u64::MAX;
    assert_eq!(window_of(&huge, T0), None);
    huge.window_seconds = i64::MAX as u64;
    assert_eq!(window_of(&huge, T0), None);
    Ok(())
}


#[test]
fn a_round_is_due_when_the_interval_since_the_last_start_has_passed() -> TestResult {
    let mut state = ScheduleState::default();
    assert_eq!(due_in(&section(), &state, T0), None);
    state.last_started = Some(T0);
    assert_eq!(due_in(&section(), &state, after(1)), Some(Duration::from_secs(INTERVAL - 1)));
    assert_eq!(due_in(&section(), &state, after(INTERVAL as i64)), None);
    assert_eq!(due_in(&section(), &state, after(INTERVAL as i64 + 1)), None);
    let mut unbounded = section();
    unbounded.interval_seconds = u64::MAX;
    assert_eq!(due_in(&unbounded, &state, T0), None);
    state.last_started = Some(FAR_FUTURE);
    assert_eq!(due_in(&section(), &state, T0), None);
    Ok(())
}


#[test]
fn a_good_round_moves_the_cursor_and_a_failed_one_does_not() -> TestResult {
    let calls = RefCell::new(Vec::new());
    let ok = |_settings: &_, start, end, previous: Option<OffsetDateTime>| {
        calls.borrow_mut().push((start, end, previous));
        Ok(run_of(start, end, None))
    };
    let (first, outcome) = round(&section(), ScheduleState::default(), T0, &ok, &|_, _| Ok(0));
    assert_eq!(first.previous_end, Some(T0));
    assert_eq!(first.last_started, Some(T0));
    assert!(matches!(outcome, RoundOutcome::Done { report, .. } if report.inserted == 0));
    let (_second, _) = round(&section(), first.clone(), after(INTERVAL as i64), &ok, &|_, _| Ok(0));
    assert_eq!(calls.borrow().get(1).map(|call| call.2), Some(Some(T0)));
    let failing = |_: &_, _, _, _| Err(RetroError::Timeout);
    let (kept, failed) = round(&section(), first.clone(), after(INTERVAL as i64), &failing, &|_, _| Ok(0));
    assert_eq!(kept.previous_end, Some(T0));
    assert_eq!(kept.last_started, Some(after(INTERVAL as i64)));
    assert!(matches!(failed, RoundOutcome::Failed(RoundFailure::Run(RetroError::Timeout))));
    let (stuck, store_failed) = round(&section(), ScheduleState::default(), T0, &ok, &|_, _| {
        Err(alerts::error::StoreError::Busy)
    });
    assert_eq!(stuck.previous_end, None);
    assert!(matches!(store_failed, RoundOutcome::Failed(RoundFailure::Store(AlertsError::Insert(_)))));
    let mut huge = section();
    huge.window_seconds = u64::MAX;
    let (_, window) = round(&huge, ScheduleState::default(), T0, &ok, &|_, _| Ok(0));
    assert!(matches!(window, RoundOutcome::Failed(RoundFailure::Window)));
    Ok(())
}


#[test]
fn a_gap_is_logged_and_the_summary_keeps_it() -> TestResult {
    let gap = Gap {
        from: after(-HOUR),
        to: after(-(WINDOW as i64)),
    };
    let found = |_: &_, start, end, _| Ok(run_of(start, end, Some(gap)));
    let (_, outcome) = round(&section(), ScheduleState::default(), T0, &found, &|_, _| Ok(0));
    assert!(matches!(outcome, RoundOutcome::Done { summary, .. } if summary.gap == Some(gap)));
    Ok(())
}


fn hooks_run<'a>(
    config: &'a (dyn Fn() -> Option<Arc<FeedsFile>> + 'a),
    clock: &'a (dyn Fn() -> OffsetDateTime + 'a),
    wait: &'a (dyn Fn(Duration) + 'a),
    stop: &'a (dyn Fn() -> bool + 'a),
    run: &'a intel_feeds::types::RunRetroFn<'a>,
    insert: &'a intel_feeds::types::AlertInsertFn<'a>,
) -> Hooks<'a> {
    hooks_saving(config, clock, wait, stop, run, insert, &|_, _| Ok(()))
}


fn hooks_saving<'a>(
    config: &'a (dyn Fn() -> Option<Arc<FeedsFile>> + 'a),
    clock: &'a (dyn Fn() -> OffsetDateTime + 'a),
    wait: &'a (dyn Fn(Duration) + 'a),
    stop: &'a (dyn Fn() -> bool + 'a),
    run: &'a intel_feeds::types::RunRetroFn<'a>,
    insert: &'a intel_feeds::types::AlertInsertFn<'a>,
    save: &'a intel_feeds::types::SaveEndFn<'a>,
) -> Hooks<'a> {
    Hooks {
        snapshot: config,
        clock,
        wait,
        stop,
        run,
        insert,
        save,
    }
}


#[test]
fn passes_wait_when_idle_or_not_due_and_run_when_due() -> TestResult {
    let with_section = Arc::new(FeedsFile {
        retro: Some(section()),
        ..FeedsFile::default()
    });
    let without = Arc::new(FeedsFile::default());
    let current: RefCell<Option<Arc<FeedsFile>>> = RefCell::new(None);
    let now = Cell::new(T0);
    let waited = RefCell::new(Vec::new());
    let runs = Cell::<u32>::default();
    let snapshot = || current.borrow().clone();
    let clock = || now.get();
    let wait = |span: Duration| waited.borrow_mut().push(span);
    let stop = || false;
    let run = |_: &_, start, end, _| {
        runs.set(runs.get() + 1);
        Ok(run_of(start, end, None))
    };
    let insert = |_: &_, _: &_| Ok(0);
    let hooks = hooks_run(&snapshot, &clock, &wait, &stop, &run, &insert);
    let (state, outcome) = pass(&hooks, ScheduleState::default());
    assert!(outcome.is_none());
    *current.borrow_mut() = Some(without);
    pass(&hooks, state.clone());
    assert_eq!(waited.borrow().as_slice(), [Duration::from_secs(WAIT_SLICE_SECONDS); PAIR]);
    *current.borrow_mut() = Some(Arc::clone(&with_section));
    let (started, done) = pass(&hooks, state);
    assert!(matches!(done, Some(RoundOutcome::Done { .. })));
    now.set(after(TEN));
    let (same, idle) = pass(&hooks, started.clone());
    assert!(idle.is_none() && same == started);
    assert_eq!(waited.borrow().last(), Some(&Duration::from_secs(WAIT_SLICE_SECONDS)));
    now.set(after(INTERVAL as i64 - 1));
    pass(&hooks, started.clone());
    assert_eq!(waited.borrow().last(), Some(&Duration::from_secs(1)));
    now.set(after(INTERVAL as i64));
    let (later, again) = pass(&hooks, started);
    assert!(again.is_some());
    assert_eq!(later.previous_end, Some(after(INTERVAL as i64)));
    assert_eq!(runs.get(), PAIR_RUNS);
    Ok(())
}


#[test]
fn the_schedule_stops_on_the_stop_test_or_after_its_pass_cap_and_picks_up_a_reload() -> TestResult {
    let current: RefCell<Option<Arc<FeedsFile>>> = RefCell::new(Some(Arc::new(FeedsFile {
        retro: Some(section()),
        ..FeedsFile::default()
    })));
    let now = Cell::new(T0);
    let runs = Cell::<u32>::default();
    let passes = Cell::<u32>::default();
    let seen = RefCell::new(Vec::new());
    let snapshot = || current.borrow().clone();
    let clock = || now.get();
    let wait = |span: Duration| now.set(now.get() + time::Duration::try_from(span).unwrap_or(time::Duration::ZERO));
    let never = || false;
    let run = |_: &_, start, end, _| {
        runs.set(runs.get() + 1);
        if runs.get() == PAIR_RUNS {
            let mut faster = section();
            faster.interval_seconds = MARGIN;
            *current.borrow_mut() = Some(Arc::new(FeedsFile {
                retro: Some(faster),
                ..FeedsFile::default()
            }));
        }
        Ok(run_of(start, end, None))
    };
    let insert = |_: &_, _: &_| Ok(0);
    let hooks = hooks_run(&snapshot, &clock, &wait, &never, &run, &insert);
    let end_state = run_schedule(&hooks, ScheduleState::default(), PASS_CAP, &mut |outcome| {
        seen.borrow_mut().push(matches!(outcome, RoundOutcome::Done { .. }))
    });
    assert!(runs.get() > PAIR_RUNS);
    assert!(seen.borrow().iter().all(|done| *done));
    assert!(end_state.previous_end.is_some());
    let counting_stop = || {
        passes.set(passes.get() + 1);
        passes.get() > 1
    };
    let stopping = hooks_run(&snapshot, &clock, &wait, &counting_stop, &run, &insert);
    let before = runs.get();
    run_schedule(&stopping, ScheduleState::default(), PASS_CAP, &mut |_| ());
    assert_eq!(runs.get(), before + 1);
    assert_eq!(passes.get(), PAIR_RUNS);
    Ok(())
}


#[test]
fn a_good_round_saves_its_end_a_failed_round_saves_nothing_and_a_failed_save_does_not_stop_the_schedule() -> TestResult {
    let current: RefCell<Option<Arc<FeedsFile>>> = RefCell::new(Some(Arc::new(FeedsFile {
        retro: Some(section()),
        ..FeedsFile::default()
    })));
    let saved = RefCell::new(Vec::new());
    let broken = Cell::new(false);
    let failing = Cell::new(false);
    let snapshot = || current.borrow().clone();
    let clock = || T0;
    let wait = |_: Duration| ();
    let never = || false;
    let run = |_: &_, start, end, _| {
        if failing.get() {
            Err(RetroError::Timeout)
        } else {
            Ok(run_of(start, end, None))
        }
    };
    let insert = |_: &_, _: &_| Ok(0);
    let save = |tenant: &str, end| {
        saved.borrow_mut().push((tenant.to_owned(), end));
        if broken.get() {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        }
    };
    let hooks = hooks_saving(&snapshot, &clock, &wait, &never, &run, &insert, &save);
    let (state, done) = pass(&hooks, ScheduleState::default());
    assert!(matches!(done, Some(RoundOutcome::Done { .. })));
    assert_eq!(saved.borrow().as_slice(), [("tenant-a".to_owned(), T0)]);
    failing.set(true);
    pass(&hooks, ScheduleState::default());
    assert_eq!(saved.borrow().len(), 1);
    failing.set(false);
    broken.set(true);
    let (after_broken, again) = pass(&hooks, ScheduleState::default());
    assert!(matches!(again, Some(RoundOutcome::Done { .. })));
    assert_eq!(after_broken.previous_end, state.previous_end);
    assert_eq!(saved.borrow().len(), PAIR);
    Ok(())
}


#[test]
fn the_first_round_after_a_restart_gets_the_saved_end_as_its_previous_end() -> TestResult {
    let current: RefCell<Option<Arc<FeedsFile>>> = RefCell::new(Some(Arc::new(FeedsFile {
        retro: Some(section()),
        ..FeedsFile::default()
    })));
    let seen = RefCell::new(Vec::new());
    let passes = Cell::<u32>::default();
    let snapshot = || current.borrow().clone();
    let clock = || T0;
    let wait = |_: Duration| ();
    let stop = || {
        passes.set(passes.get() + 1);
        passes.get() > 1
    };
    let run = |_: &_, start, end, previous| {
        seen.borrow_mut().push(previous);
        Ok(run_of(start, end, None))
    };
    let insert = |_: &_, _: &_| Ok(0);
    let hooks = hooks_run(&snapshot, &clock, &wait, &stop, &run, &insert);
    let initial = ScheduleState {
        previous_end: Some(after(-HOUR)),
        ..ScheduleState::default()
    };
    run_schedule(&hooks, initial, PASS_CAP, &mut |_| ());
    assert_eq!(seen.borrow().as_slice(), [Some(after(-HOUR))]);
    Ok(())
}


#[test]
fn a_reload_that_changes_the_tenant_drops_the_previous_end_and_saves_under_the_new_tenant() -> TestResult {
    let other = {
        let mut changed = section();
        changed.reader.tenant = "tenant-b".to_owned();
        Arc::new(FeedsFile {
            retro: Some(changed),
            ..FeedsFile::default()
        })
    };
    let current: RefCell<Option<Arc<FeedsFile>>> = RefCell::new(Some(Arc::new(FeedsFile {
        retro: Some(section()),
        ..FeedsFile::default()
    })));
    let seen = RefCell::new(Vec::new());
    let saved = RefCell::new(Vec::new());
    let now = Cell::new(T0);
    let snapshot = || current.borrow().clone();
    let clock = || now.get();
    let wait = |_: Duration| ();
    let never = || false;
    let run = |_: &_, start, end, previous| {
        seen.borrow_mut().push(previous);
        Ok(run_of(start, end, None))
    };
    let insert = |_: &_, _: &_| Ok(0);
    let save = |tenant: &str, end| {
        saved.borrow_mut().push((tenant.to_owned(), end));
        Ok(())
    };
    let hooks = hooks_saving(&snapshot, &clock, &wait, &never, &run, &insert, &save);
    let initial = ScheduleState {
        tenant: Some("tenant-a".to_owned()),
        previous_end: Some(after(-HOUR)),
        ..ScheduleState::default()
    };
    let (first, _) = pass(&hooks, initial);
    *current.borrow_mut() = Some(other);
    now.set(after(INTERVAL as i64));
    let (second, _) = pass(&hooks, first);
    now.set(after(INTERVAL as i64 + INTERVAL as i64));
    pass(&hooks, second);
    assert_eq!(seen.borrow().as_slice(), [Some(after(-HOUR)), None, Some(after(INTERVAL as i64))]);
    let tenants: Vec<String> = saved.borrow().iter().map(|(tenant, _)| tenant.clone()).collect();
    assert_eq!(tenants, ["tenant-a", "tenant-b", "tenant-b"]);
    Ok(())
}

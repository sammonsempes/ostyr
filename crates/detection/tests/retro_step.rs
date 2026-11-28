#![cfg(unix)]

#[path = "retro_step/types.rs"]
mod types;


use alerts::id::alert_id;
use detection::error::{CursorError, RetroError, SinkError, StepError};
use detection::id::payload_hash;
use detection::retro::{RetroEvent, RetroIds, RetroOutcome, MAX_RETRO_DAYS, SECONDS_PER_DAY};
use detection::retro_cursor::{find_entry, CursorEntry, RetroCursors};
use detection::retro_rules::RetroRule;
use detection::retro_step::{
    decide_error, event_record, loss_record, plan_window, query_of, retro_step, StepInput, StepOutcome, StepReport, Window, MIN_STEP_SECONDS,
    RETRO_SETTLE_SECONDS, RETRO_STEP_SECONDS,
};
use siem_ingest::error::InsertClass;
use sigma_sql::error::SigmaError;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, VecDeque};
use std::io::{self, Write};
use std::sync::{Arc, LazyLock, Mutex};
use stream_correlation::level::Level;
use time::macros::datetime;
use time::OffsetDateTime;
use tracing::dispatcher::with_default;
use tracing::Dispatch;
use types::{ReadScript, TestResult};


const NOW: OffsetDateTime = datetime!(2026-11-20 12:00:00 UTC);


const TENANT: &str = "t-one";


const OTHER_TENANT: &str = "t-two";


const HASH_CHARS: usize = 64;


const CAP: usize = 3;


const HALVINGS: usize = 6;


const FIRST_HALF: i64 = 1_800;


const SECOND_HALF: i64 = 900;


const BIG_BATCH: usize = 1_201;


const CHUNK_ONE: usize = 500;


const CHUNK_THREE: usize = 201;


const EVENT_OFFSET_SECONDS: i64 = 100;


const MILLIS: i64 = 1_000;


const ODD_MILLIS: i64 = 250;


const FAR_PAST: i64 = i64::MIN / 4;


const FAR_FUTURE: i64 = i64::MAX;


const TWO: usize = 2;


const TWO_I64: i64 = 2;


const THREE: usize = 3;


const HUGE_STEP: i64 = 1_000_000;


const NEGATIVE_STEP: i64 = -5;


const SHORT_TAIL: i64 = 10;


struct Rig {
    script: RefCell<VecDeque<Result<RetroOutcome, RetroError>>>,
    queries: RefCell<Vec<(i64, i64)>>,
    stored: RefCell<BTreeSet<String>>,
    chunks: RefCell<Vec<usize>>,
    rule_ids: RefCell<Vec<String>>,
    log: RefCell<Vec<&'static str>>,
    saved: RefCell<Vec<RetroCursors>>,
    fail_insert: Cell<bool>,
    fail_save: Cell<bool>,
}


fn rig(script: ReadScript) -> Rig {
    Rig {
        script: RefCell::new(script.into()),
        queries: RefCell::new(Vec::new()),
        stored: RefCell::new(BTreeSet::new()),
        chunks: RefCell::new(Vec::new()),
        rule_ids: RefCell::new(Vec::new()),
        log: RefCell::new(Vec::new()),
        saved: RefCell::new(Vec::new()),
        fail_insert: Cell::new(false),
        fail_save: Cell::new(false),
    }
}


fn rule(name: &str) -> RetroRule {
    RetroRule {
        rule_id: format!("retro:{name}"),
        loss_id: format!("retro.loss:{name}"),
        title: format!("Title {name}"),
        level: Level::High,
        source: format!("title: {name}"),
        fingerprint: payload_hash(name.as_bytes()),
    }
}


fn event(ms: i64, name: &str) -> RetroEvent {
    RetroEvent {
        identity: format!("{name}:{}", "a".repeat(HASH_CHARS)),
        event_ms: ms,
        event_time: "2026-11-20T00:00:00Z".to_owned(),
        id_chars: 1,
        host_name: Some("host-1".to_owned()),
        host_chars: 1,
        user_name: None,
        user_chars: 0,
    }
}


fn found(events: Vec<RetroEvent>) -> RetroIds {
    let rows = events.len();
    RetroIds { events, refused: 0, rows }
}


fn complete(events: Vec<RetroEvent>) -> Result<RetroOutcome, RetroError> {
    Ok(RetroOutcome::Complete(found(events)))
}


fn row_cap(events: Vec<RetroEvent>) -> Result<RetroOutcome, RetroError> {
    Ok(RetroOutcome::RowCap {
        found: found(events),
        cap: CAP,
    })
}


fn run(rig: &Rig, rule: &RetroRule, tenant: &str, now: OffsetDateTime, cursors: &RetroCursors) -> Result<(RetroCursors, StepReport), StepError> {
    let input = StepInput { rule, tenant, now };
    retro_step(
        &input,
        cursors,
        &|query| {
            rig.queries.borrow_mut().push((query.start.unix_timestamp(), query.end.unix_timestamp()));
            rig.script.borrow_mut().pop_front().unwrap_or(Err(RetroError::MalformedReply))
        },
        &|_tenant, records| {
            rig.log.borrow_mut().push("insert");
            rig.chunks.borrow_mut().push(records.len());
            rig.rule_ids.borrow_mut().extend(records.iter().map(|record| record.rule_id.clone()));
            if rig.fail_insert.get() {
                Err(SinkError::Exhausted)
            } else {
                Ok(records.iter().filter(|record| rig.stored.borrow_mut().insert(record.id.clone())).count())
            }
        },
        &|saved| {
            rig.log.borrow_mut().push("save");
            if rig.fail_save.get() {
                Err(CursorError::Corrupt)
            } else {
                rig.saved.borrow_mut().push(saved.clone());
                Ok(())
            }
        },
    )
}


fn first_start() -> i64 {
    NOW.unix_timestamp() - MAX_RETRO_DAYS * SECONDS_PER_DAY
}


fn entry_of(rule: &RetroRule, next: i64, step: i64) -> CursorEntry {
    CursorEntry {
        tenant: TENANT.to_owned(),
        fingerprint: rule.fingerprint.clone(),
        next,
        step,
    }
}


fn cursors_at(rule: &RetroRule, next: i64, step: i64) -> RetroCursors {
    RetroCursors {
        entries: vec![entry_of(rule, next, step)],
    }
}


fn entry_for<'a>(cursors: &'a RetroCursors, rule: &RetroRule) -> Result<&'a CursorEntry, &'static str> {
    find_entry(cursors, TENANT, &rule.fingerprint).ok_or("no entry")
}


#[test]
fn the_first_window_starts_seven_days_back_and_clamps_the_step() -> TestResult {
    let now = NOW.unix_timestamp();
    let first = plan_window(None, now);
    assert_eq!(
        first,
        Window {
            start: first_start(),
            end: first_start() + RETRO_STEP_SECONDS,
            step: RETRO_STEP_SECONDS
        }
    );
    let settled = plan_window(Some(&entry_of(&rule("a"), now - SHORT_TAIL, RETRO_STEP_SECONDS)), now);
    assert_eq!(settled.end, now - RETRO_SETTLE_SECONDS);
    let wide = plan_window(Some(&entry_of(&rule("a"), first_start(), HUGE_STEP)), now);
    assert_eq!(wide.step, RETRO_STEP_SECONDS);
    let narrow = plan_window(Some(&entry_of(&rule("a"), first_start(), NEGATIVE_STEP)), now);
    assert_eq!((narrow.step, narrow.end), (MIN_STEP_SECONDS, first_start() + MIN_STEP_SECONDS));
    let ahead = plan_window(Some(&entry_of(&rule("a"), FAR_FUTURE, RETRO_STEP_SECONDS)), now);
    assert_eq!(ahead, first);
    Ok(())
}


#[test]
fn a_complete_step_stores_the_alerts_once_and_moves_the_cursor_to_the_window_end() -> TestResult {
    let alerting = rule("a");
    let rig = rig(vec![complete(vec![
        event(first_start() * MILLIS + 1, "e1"),
        event(first_start() * MILLIS + TWO_I64, "e2"),
    ])]);
    let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!(report.outcome, StepOutcome::Complete);
    assert_eq!((report.found, report.stored, report.losses, report.refused_ids), (TWO, TWO, 0, 0));
    let entry = entry_for(&cursors, &alerting)?;
    assert_eq!(
        (entry.next, entry.step),
        (first_start() + RETRO_STEP_SECONDS, RETRO_STEP_SECONDS * TWO_I64)
    );
    assert_eq!(rig.queries.borrow().as_slice(), &[(first_start(), first_start() + RETRO_STEP_SECONDS)]);
    assert_eq!(rig.log.borrow().as_slice(), &["insert", "save"]);
    assert_eq!(rig.saved.borrow().len(), 1);
    Ok(())
}


#[test]
fn an_alert_id_comes_from_the_rule_and_the_event_never_from_the_window() -> TestResult {
    let alerting = rule("a");
    let matching = event(first_start() * MILLIS, "e1");
    let record = event_record(&alerting, TENANT, &matching);
    assert_eq!(record.id, alert_id(TENANT, "retro:a", std::slice::from_ref(&matching.identity)));
    assert_eq!(record.event_ids, vec![matching.identity.clone()]);
    assert_eq!(record.group.get("host.name").map(String::as_str), Some("host-1"));
    assert!(!record.group.contains_key("user.name"));
    let later = event_record(
        &alerting,
        TENANT,
        &event(first_start() * MILLIS + MILLIS * RETRO_STEP_SECONDS * TWO_I64, "e1"),
    );
    assert_eq!(later.id, record.id);
    assert_ne!(event_record(&alerting, OTHER_TENANT, &matching).id, record.id);
    assert_ne!(event_record(&rule("b"), TENANT, &matching).id, record.id);
    let loss = loss_record(&alerting, TENANT, 1, TWO_I64);
    assert_eq!(
        (loss.rule_id.as_str(), loss.event_ids.as_slice()),
        ("retro.loss:a", &["window:1-2".to_owned()][..])
    );
    assert_eq!(loss.level, Level::Medium);
    assert!(loss.rule_title.ends_with("Title a"));
    Ok(())
}


#[test]
fn a_crash_between_the_insert_and_the_cursor_save_is_repaired_by_the_rerun() -> TestResult {
    let alerting = rule("a");
    let events = || vec![event(first_start() * MILLIS, "e1")];
    let rig = rig(vec![complete(events()), complete(events())]);
    rig.fail_save.set(true);
    let failed = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default());
    assert!(matches!(failed, Err(StepError::Save(CursorError::Corrupt))));
    assert_eq!(rig.stored.borrow().len(), 1);
    assert!(rig.saved.borrow().is_empty());
    rig.fail_save.set(false);
    let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!((report.found, report.stored), (1, 0));
    assert_eq!(rig.stored.borrow().len(), 1);
    assert_eq!(entry_for(&cursors, &alerting)?.next, first_start() + RETRO_STEP_SECONDS);
    Ok(())
}


#[test]
fn a_failed_insert_keeps_the_old_cursor_and_never_saves() -> TestResult {
    let alerting = rule("a");
    let rig = rig(vec![complete(vec![event(first_start() * MILLIS, "e1")])]);
    rig.fail_insert.set(true);
    let failed = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default());
    assert!(matches!(failed, Err(StepError::Insert(SinkError::Exhausted))));
    assert_eq!(rig.log.borrow().as_slice(), &["insert"]);
    Ok(())
}


#[test]
fn the_cursor_is_saved_only_after_every_chunk_of_five_hundred_answered() -> TestResult {
    let alerting = rule("a");
    let events: Vec<RetroEvent> = (0..BIG_BATCH).map(|index| event(first_start() * MILLIS, &format!("e{index}"))).collect();
    let rig = rig(vec![complete(events)]);
    let (_cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!(report.stored, BIG_BATCH);
    assert_eq!(rig.chunks.borrow().as_slice(), &[CHUNK_ONE, CHUNK_ONE, CHUNK_THREE]);
    assert_eq!(rig.log.borrow().as_slice(), &["insert", "insert", "insert", "save"]);
    Ok(())
}


#[test]
fn a_row_cap_moves_the_cursor_to_the_second_of_the_last_row_and_reads_that_second_again() -> TestResult {
    let alerting = rule("a");
    let second = first_start() + EVENT_OFFSET_SECONDS;
    let rig = rig(vec![
        row_cap(vec![
            event(first_start() * MILLIS + 1, "e1"),
            event(second * MILLIS + ODD_MILLIS, "e2"),
            event(second * MILLIS + ODD_MILLIS + 1, "e3"),
        ]),
        complete(vec![
            event(second * MILLIS + ODD_MILLIS, "e2"),
            event(second * MILLIS + ODD_MILLIS + 1, "e3"),
            event((second + 1) * MILLIS, "e4"),
        ]),
    ]);
    let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!(
        (report.outcome, report.found, report.stored, report.losses),
        (StepOutcome::RowCap, THREE, THREE, 0)
    );
    assert_eq!(entry_for(&cursors, &alerting)?.next, second);
    let (next_cursors, next_report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
    let queries = rig.queries.borrow();
    assert_eq!(queries.get(1).map(|window| window.0), Some(second));
    assert_eq!((next_report.found, next_report.stored), (THREE, 1));
    assert_eq!(rig.stored.borrow().len(), THREE + 1);
    assert_eq!(entry_for(&next_cursors, &alerting)?.next, second + RETRO_STEP_SECONDS);
    Ok(())
}


#[test]
fn a_row_cap_on_one_rule_never_moves_the_cursor_of_the_second_rule() -> TestResult {
    let first = rule("a");
    let second = rule("b");
    let second_at = first_start() + EVENT_OFFSET_SECONDS;
    let rig = rig(vec![
        row_cap(vec![event(first_start() * MILLIS + 1, "e1"), event(second_at * MILLIS, "e2")]),
        complete(vec![event(first_start() * MILLIS, "e9")]),
    ]);
    let (after_first, _report) = run(&rig, &first, TENANT, NOW, &RetroCursors::default())?;
    let (after_second, report) = run(&rig, &second, TENANT, NOW, &after_first)?;
    assert_eq!(report.outcome, StepOutcome::Complete);
    assert_eq!(entry_for(&after_second, &first)?.next, second_at);
    assert_eq!(entry_for(&after_second, &second)?.next, first_start() + RETRO_STEP_SECONDS);
    assert_eq!(after_second.entries.len(), TWO);
    assert_eq!(rig.rule_ids.borrow().as_slice(), &["retro:a", "retro:a", "retro:b"]);
    Ok(())
}


#[test]
fn a_whole_second_at_the_cap_is_a_named_loss_and_the_cursor_moves_one_second() -> TestResult {
    let alerting = rule("a");
    let start_ms = first_start() * MILLIS;
    let rig = rig(vec![row_cap(vec![
        event(start_ms, "e1"),
        event(start_ms + 1, "e2"),
        event(start_ms + TWO_I64, "e3"),
    ])]);
    let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!(
        (report.outcome, report.losses, report.found, report.stored),
        (StepOutcome::RowCap, 1, THREE, THREE + 1)
    );
    assert_eq!(entry_for(&cursors, &alerting)?.next, first_start() + 1);
    assert!(rig.rule_ids.borrow().iter().any(|id| id == "retro.loss:a"));
    let loss = loss_record(&alerting, TENANT, first_start(), first_start() + 1);
    assert!(rig.stored.borrow().contains(&loss.id));
    Ok(())
}


#[test]
fn a_row_cap_with_no_usable_event_is_a_named_loss_too() -> TestResult {
    let alerting = rule("a");
    let rig = rig(vec![Ok(RetroOutcome::RowCap {
        found: RetroIds {
            events: Vec::new(),
            refused: CAP + 1,
            rows: CAP + 1,
        },
        cap: CAP,
    })]);
    let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default())?;
    assert_eq!((report.losses, report.refused_ids, report.stored), (1, CAP + 1, 1));
    assert_eq!(entry_for(&cursors, &alerting)?.next, first_start() + 1);
    Ok(())
}


#[test]
fn a_timeout_halves_the_step_to_the_minimum_then_the_window_is_a_named_loss() -> TestResult {
    let alerting = rule("a");
    let mut script: ReadScript = vec![Err(RetroError::ReadLimit)];
    script.extend((1..HALVINGS).map(|_| Err(RetroError::Timeout)));
    script.push(Err(RetroError::ReadLimit));
    let rig = rig(script);
    let mut cursors = RetroCursors::default();
    let mut steps = Vec::new();
    for _ in 0..HALVINGS {
        let (next, report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
        assert_eq!((report.outcome, report.stored, report.losses), (StepOutcome::Halved, 0, 0));
        cursors = next;
        steps.push(entry_for(&cursors, &alerting)?.step);
    }
    assert_eq!(
        steps.iter().take(THREE).copied().collect::<Vec<i64>>(),
        vec![FIRST_HALF, SECOND_HALF, SECOND_HALF / TWO_I64]
    );
    assert_eq!(steps.last(), Some(&MIN_STEP_SECONDS));
    assert!(cursors.entries.iter().all(|entry| entry.next == first_start()));
    assert_eq!(rig.queries.borrow().get(1), Some(&(first_start(), first_start() + FIRST_HALF)));
    assert!(rig.stored.borrow().is_empty());
    let (after, report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
    assert_eq!((report.outcome, report.losses, report.stored), (StepOutcome::Lost, 1, 1));
    assert_eq!(entry_for(&after, &alerting)?.next, first_start() + MIN_STEP_SECONDS);
    assert!(rig
        .stored
        .borrow()
        .contains(&loss_record(&alerting, TENANT, first_start(), first_start() + MIN_STEP_SECONDS).id));
    assert_eq!(rig.rule_ids.borrow().as_slice(), &["retro.loss:a"]);
    Ok(())
}


#[test]
fn a_rule_edit_is_a_new_fingerprint_that_backfills_with_the_same_alert_ids() -> TestResult {
    let before = rule("a");
    let edited = RetroRule {
        source: "title: edited".to_owned(),
        fingerprint: payload_hash(b"edited"),
        ..before.clone()
    };
    let events = || vec![event(first_start() * MILLIS, "e1")];
    let rig = rig(vec![complete(events()), complete(events())]);
    let (once, _first) = run(&rig, &before, TENANT, NOW, &RetroCursors::default())?;
    let (twice, report) = run(&rig, &edited, TENANT, NOW, &once)?;
    assert_eq!((report.found, report.stored), (1, 0));
    assert_eq!(rig.stored.borrow().len(), 1);
    assert_eq!(
        rig.queries.borrow().as_slice(),
        &[(first_start(), first_start() + RETRO_STEP_SECONDS); TWO]
    );
    assert_eq!(twice.entries.len(), TWO);
    Ok(())
}


#[test]
fn a_step_with_nothing_settled_reads_stores_and_saves_nothing() -> TestResult {
    let alerting = rule("a");
    let now = NOW.unix_timestamp();
    let cursors = cursors_at(&alerting, now - RETRO_SETTLE_SECONDS, RETRO_STEP_SECONDS);
    let rig = rig(Vec::new());
    let (same, report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
    assert_eq!(report.outcome, StepOutcome::Idle);
    assert_eq!(same, cursors);
    assert!(rig.queries.borrow().is_empty() && rig.log.borrow().is_empty());
    Ok(())
}


#[test]
fn a_refused_rule_is_counted_alone_and_changes_nothing() -> TestResult {
    let alerting = rule("a");
    let refusal = || SigmaError::Usage;
    let rig = rig(vec![
        Err(RetroError::Rule(refusal())),
        Err(RetroError::Refused(InsertClass::ParseError)),
        Err(RetroError::Refused(InsertClass::Rejected)),
    ]);
    let start = RetroCursors::default();
    for _ in 0..THREE {
        let (cursors, report) = run(&rig, &alerting, TENANT, NOW, &start)?;
        assert_eq!(report.outcome, StepOutcome::RuleRefused);
        assert_eq!(cursors, start);
    }
    assert!(rig.log.borrow().is_empty());
    Ok(())
}


#[test]
fn any_other_read_error_stops_the_step_with_the_old_cursor() -> TestResult {
    let alerting = rule("a");
    let errors = [
        RetroError::Refused(InsertClass::Unavailable),
        RetroError::Refused(InsertClass::Unauthorized),
        RetroError::MalformedReply,
        RetroError::ReaderProfileChanged(1),
    ];
    errors.into_iter().for_each(|error| {
        let rig = rig(vec![Err(error)]);
        let outcome = run(&rig, &alerting, TENANT, NOW, &RetroCursors::default());
        assert!(matches!(outcome, Err(StepError::Read(_))));
        assert!(rig.log.borrow().is_empty());
    });
    Ok(())
}


#[test]
fn a_window_outside_the_calendar_is_a_window_error() -> TestResult {
    let alerting = rule("a");
    let input = StepInput {
        rule: &alerting,
        tenant: TENANT,
        now: NOW,
    };
    let bad_end = Window {
        start: 0,
        end: i64::MAX,
        step: RETRO_STEP_SECONDS,
    };
    assert!(matches!(query_of(&input, &bad_end), Err(RetroError::Window)));
    let decided = decide_error(&input, &bad_end, RetroError::Window);
    assert!(matches!(decided, Err(RetroError::Window)));
    Ok(())
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn the_step_and_the_loss_are_logged_with_epochs_and_counts_only() -> TestResult {
    LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let dispatch = Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish());
    let alerting = rule("secret-rule");
    let rig = rig(vec![
        Err(RetroError::Timeout),
        complete(vec![event(first_start() * MILLIS, "secret-event")]),
    ]);
    let cursors = cursors_at(&alerting, first_start(), MIN_STEP_SECONDS);
    let lost = with_default(&dispatch, || run(&rig, &alerting, TENANT, NOW, &cursors));
    let (after, _report) = lost?;
    let again = with_default(&dispatch, || run(&rig, &alerting, TENANT, NOW, &after));
    again?;
    let logs = String::from_utf8(captured.lock().map_err(|poisoned| poisoned.to_string())?.clone())?;
    assert!(
        logs.contains("retro window lost") && logs.contains(&format!("{}-{}", first_start(), first_start() + MIN_STEP_SECONDS)),
        "{logs}"
    );
    assert!(
        logs.contains("retro step done") && logs.contains("Lost losses=1") && logs.contains("Complete losses=0"),
        "{logs}"
    );
    assert!(
        !logs.contains(TENANT) && !logs.contains("secret-rule") && !logs.contains("secret-event"),
        "{logs}"
    );
    Ok(())
}


const CRAFTED_NEXT: i64 = 4_000_000_000;


const CLOCK_BACK_SECONDS: i64 = 120;


fn capture_logs<Output>(action: impl FnOnce() -> Output) -> Result<(Output, String), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let dispatch = Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish());
    let output = with_default(&dispatch, action);
    let logs = String::from_utf8(captured.lock().map_err(|poisoned| poisoned.to_string())?.clone())?;
    Ok((output, logs))
}


#[test]
fn a_cursor_ahead_of_now_restarts_from_the_horizon_with_one_counted_warning() -> TestResult {
    let alerting = rule("a");
    let crafted = [
        CRAFTED_NEXT,
        NOW.unix_timestamp() + 1,
        NOW.unix_timestamp() + CLOCK_BACK_SECONDS - RETRO_SETTLE_SECONDS,
    ];
    crafted.into_iter().try_for_each(|next| -> TestResult {
        let rig = rig(vec![complete(vec![event(first_start() * MILLIS + 1, "e1")])]);
        let cursors = cursors_at(&alerting, next, RETRO_STEP_SECONDS);
        let (result, logs) = capture_logs(|| run(&rig, &alerting, TENANT, NOW, &cursors))?;
        let (after, report) = result?;
        assert_eq!(report.outcome, StepOutcome::Complete);
        assert_eq!((report.found, report.stored, report.losses), (1, 1, 0));
        assert_eq!(rig.queries.borrow().as_slice(), &[(first_start(), first_start() + RETRO_STEP_SECONDS)]);
        assert_eq!(entry_for(&after, &alerting)?.next, first_start() + RETRO_STEP_SECONDS);
        assert!(logs.contains("retro cursor ahead of now") && logs.contains("cursor_ahead=1"), "{logs}");
        assert!(!rig.rule_ids.borrow().iter().any(|id| id.starts_with("retro.loss:")));
        Ok(())
    })?;
    Ok(())
}


#[test]
fn a_cursor_at_now_is_idle_and_never_warns() -> TestResult {
    let alerting = rule("a");
    let rig = rig(Vec::new());
    let cursors = cursors_at(&alerting, NOW.unix_timestamp(), RETRO_STEP_SECONDS);
    let (result, logs) = capture_logs(|| run(&rig, &alerting, TENANT, NOW, &cursors))?;
    let (same, report) = result?;
    assert_eq!((report.outcome, same), (StepOutcome::Idle, cursors));
    assert!(!logs.contains("cursor_ahead"), "{logs}");
    Ok(())
}


#[test]
fn a_cursor_older_than_the_horizon_is_clamped_with_a_named_loss_for_the_gap() -> TestResult {
    let alerting = rule("a");
    let old = [0, FAR_PAST, first_start() - 1];
    old.into_iter().try_for_each(|next| -> TestResult {
        let rig = rig(vec![complete(vec![event(first_start() * MILLIS + 1, "e1")])]);
        let cursors = cursors_at(&alerting, next, RETRO_STEP_SECONDS);
        let (result, logs) = capture_logs(|| run(&rig, &alerting, TENANT, NOW, &cursors))?;
        let (after, report) = result?;
        assert_eq!(
            (report.outcome, report.found, report.stored, report.losses),
            (StepOutcome::Complete, 1, TWO, 1)
        );
        assert_eq!(rig.queries.borrow().as_slice(), &[(first_start(), first_start() + RETRO_STEP_SECONDS)]);
        assert_eq!(entry_for(&after, &alerting)?.next, first_start() + RETRO_STEP_SECONDS);
        let gap = loss_record(&alerting, TENANT, next, first_start());
        assert!(rig.stored.borrow().contains(&gap.id));
        assert!(rig.rule_ids.borrow().contains(&alerting.loss_id));
        assert!(
            logs.contains("retro cursor older than the horizon") && logs.contains(&format!("{next}-{}", first_start())),
            "{logs}"
        );
        Ok(())
    })?;
    Ok(())
}


#[test]
fn a_cursor_exactly_at_the_horizon_is_usable_and_loses_nothing() -> TestResult {
    let alerting = rule("a");
    let rig = rig(vec![complete(Vec::new())]);
    let cursors = cursors_at(&alerting, first_start(), RETRO_STEP_SECONDS);
    let (_after, report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
    assert_eq!((report.outcome, report.losses, report.stored), (StepOutcome::Complete, 0, 0));
    assert_eq!(rig.log.borrow().as_slice(), &["save"]);
    Ok(())
}


#[test]
fn a_stale_cursor_with_a_refused_rule_stores_no_loss_and_keeps_the_cursor() -> TestResult {
    let alerting = rule("a");
    let rig = rig(vec![Err(RetroError::Rule(SigmaError::Usage))]);
    let cursors = cursors_at(&alerting, 0, RETRO_STEP_SECONDS);
    let (same, report) = run(&rig, &alerting, TENANT, NOW, &cursors)?;
    assert_eq!((report.outcome, report.losses, same), (StepOutcome::RuleRefused, 0, cursors));
    assert!(rig.log.borrow().is_empty());
    Ok(())
}

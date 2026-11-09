use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use siem_ingest::batcher::{new_batcher, push};
use siem_ingest::error::{InsertClass, InsertError, PipelineError};
use siem_ingest::model::{AckAction, CycleReport, Delivery, FlushReport, LoopReport, Message, Pipeline, Wiring};
use siem_ingest::pipeline::{new_pipeline, pending_bytes, poison_text, run_cycle, run_loop, settle, MAX_LOOP_CYCLES, POISON_REASON};
use siem_ingest::settings::open_settings;
use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


const EVENT: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","ecs":{"version":"8.11"},"event":{"kind":"event"}}"#;


const BAD_MARK: &str = "BAD";


const START: i64 = 1_800_000_000;


const EVENT_BYTES: usize = 87;


const OVERSIZED_TENANT: usize = 65;


const LATER: i64 = 10;


const TOKEN_ONE: u64 = 1;


const TOKEN_TWO: u64 = 2;


const TOKEN_THREE: u64 = 3;


const CYCLES: u64 = 5;


const FAILING_CYCLES: u64 = 3;


const FIRST_DELAY_MS: u64 = 100;


const SECOND_DELAY_MS: u64 = 200;


const THIRD_DELAY_MS: u64 = 400;


const SENT: usize = 3;


const TWO: usize = 2;


const HOLD_BYTES: usize = 150;


const GARBAGE_BYTES: usize = 100;


#[derive(Default)]
pub struct Queue {
    pub items: Mutex<VecDeque<Result<Vec<Delivery>, String>>>,
}


pub struct Rig {
    pub dir: TempDir,
    pub pipeline: Pipeline,
    pub lines: Arc<Mutex<Vec<String>>>,
    pub queue: Arc<Queue>,
    pub sink_error: Arc<Mutex<Option<String>>>,
    pub poison: Arc<AtomicBool>,
    pub split_poison: Arc<AtomicBool>,
    pub ack_fails: Arc<AtomicBool>,
    pub dead_fails: Arc<AtomicBool>,
    pub clock: Arc<AtomicI64>,
    pub delays: Arc<Mutex<Vec<Duration>>>,
}


fn record(lines: &Arc<Mutex<Vec<String>>>, text: String) -> Result<(), String> {
    lines.lock().map_err(|_| "poisoned".to_owned())?.push(text);
    Ok(())
}


fn rig(yaml: &str) -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("ingest.yaml");
    fs::write(&path, yaml)?;
    let log = genesis_log(io::sink());
    let engine = open_settings(path, Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }))?;
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let queue: Arc<Queue> = Arc::default();
    let sink_error: Arc<Mutex<Option<String>>> = Arc::default();
    let poison = Arc::new(AtomicBool::new(false));
    let split_poison = Arc::new(AtomicBool::new(false));
    let ack_fails = Arc::new(AtomicBool::new(false));
    let dead_fails = Arc::new(AtomicBool::new(false));
    let clock = Arc::new(AtomicI64::new(START));
    let delays: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let sink_lines = Arc::clone(&lines);
    let sink_failure = Arc::clone(&sink_error);
    let sink_poison = Arc::clone(&poison);
    let sink_split = Arc::clone(&split_poison);
    let ticking = Arc::clone(&clock);
    let slept = Arc::clone(&delays);
    let batcher = new_batcher(
        Arc::new(engine),
        Box::new(move |tenant, documents| {
            record(&sink_lines, format!("sink:{tenant}:{}", documents.len()))?;
            let failure = sink_failure.lock().map_err(|_| "poisoned")?.clone();
            let malformed = documents.len() > 1
                || documents
                    .iter()
                    .any(|document| String::from_utf8_lossy(&document.payload).contains(BAD_MARK));
            if sink_poison.load(Ordering::SeqCst) || (sink_split.load(Ordering::SeqCst) && malformed) {
                Err(Box::new(InsertError::Class(InsertClass::ParseError)))
            } else {
                failure.map_or(Ok(()), |text| Err(text.into()))
            }
        }),
        Box::new(move || OffsetDateTime::from_unix_timestamp(ticking.load(Ordering::SeqCst)).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
        Box::new(move |delay| {
            if let Ok(mut recorded) = slept.lock() {
                recorded.push(delay);
            }
        }),
    );
    let fetch_queue = Arc::clone(&queue);
    let ack_lines = Arc::clone(&lines);
    let ack_failing = Arc::clone(&ack_fails);
    let dead_lines = Arc::clone(&lines);
    let dead_failing = Arc::clone(&dead_fails);
    let wiring = Wiring {
        fetch: Box::new(move |_max| {
            let next = fetch_queue.items.lock().map_err(|_| "poisoned")?.pop_front();
            next.unwrap_or_else(|| Ok(Vec::new())).map_err(Into::into)
        }),
        ack: Box::new(move |token, action| {
            let word = if action == AckAction::Ack { "ack" } else { "nak" };
            record(&ack_lines, format!("{word}:{token}"))?;
            if ack_failing.load(Ordering::SeqCst) {
                Err("bus refused".into())
            } else {
                Ok(())
            }
        }),
        dead_letter: Box::new(move |tenant, payload, reason| {
            record(&dead_lines, format!("dead:{tenant}:{}:{reason}", payload.len()))?;
            if dead_failing.load(Ordering::SeqCst) {
                Err("publish refused".into())
            } else {
                Ok(())
            }
        }),
    };
    Ok(Rig {
        dir,
        pipeline: new_pipeline(batcher, wiring),
        lines,
        queue,
        sink_error,
        poison,
        split_poison,
        ack_fails,
        dead_fails,
        clock,
        delays,
    })
}


fn stop_after(cycles: u64) -> impl Fn() -> bool {
    let seen = AtomicU64::new(0);
    move || seen.fetch_add(1, Ordering::SeqCst) >= cycles
}


fn delivery(subject: &str, payload: &str, token: u64) -> Delivery {
    Delivery {
        subject: subject.to_owned(),
        payload: payload.as_bytes().to_vec(),
        token,
    }
}


fn enqueue(rig: &Rig, items: Vec<Delivery>) -> Result<(), Box<dyn Error>> {
    rig.queue.items.lock().map_err(|_| "poisoned")?.push_back(Ok(items));
    Ok(())
}


fn lines(rig: &Rig) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(rig.lines.lock().map_err(|_| "poisoned")?.clone())
}


fn delays(rig: &Rig) -> Result<Vec<Duration>, Box<dyn Error>> {
    Ok(rig.delays.lock().map_err(|_| "poisoned")?.clone())
}


#[test]
fn acknowledges_only_after_the_insert_succeeded() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 2\n")?;
    enqueue(
        &rig,
        vec![
            delivery("events.tenant-a", EVENT, TOKEN_ONE),
            delivery("events.tenant-a", EVENT, TOKEN_TWO),
        ],
    )?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:2", "ack:1", "ack:2"]);
    assert_eq!(report.fetched, TWO);
    assert_eq!(report.acknowledged, TWO);
    assert!(rig.pipeline.pending.is_empty());
    assert!(rig.dir.path().exists());
    Ok(())
}


#[test]
fn a_refused_batch_is_redelivered_not_acknowledged() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\nretry_attempts: 1\n")?;
    *rig.sink_error.lock().map_err(|_| "poisoned")? = Some("clickhouse down".to_owned());
    enqueue(&rig, vec![delivery("events.tenant-a", EVENT, TOKEN_ONE)])?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:1", "nak:1"]);
    assert_eq!(report.redelivered, 1);
    assert_eq!(report.acknowledged, 0);
    assert!(rig.pipeline.pending.is_empty());
    Ok(())
}


#[test]
fn an_unparsable_batch_is_dead_lettered_then_acknowledged() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\nretry_attempts: 1\n")?;
    rig.poison.store(true, Ordering::SeqCst);
    enqueue(&rig, vec![delivery("events.tenant-a", EVENT, TOKEN_ONE)])?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(
        lines(&rig)?,
        [
            "sink:tenant-a:1".to_owned(),
            format!("dead:tenant-a:{EVENT_BYTES}:{POISON_REASON}"),
            "ack:1".to_owned()
        ]
    );
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(poison_text(), "ClickHouse insert failed: ParseError");
    Ok(())
}


#[test]
fn a_malformed_event_is_dead_lettered_before_the_sink_then_acknowledged() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\n")?;
    enqueue(&rig, vec![delivery("events.tenant-a", "not json", TOKEN_ONE)])?;
    let report = run_cycle(&mut rig.pipeline)?;
    let seen = lines(&rig)?;
    assert_eq!(seen.len(), TWO);
    assert!(seen.first().is_some_and(|line| line.starts_with("dead:tenant-a:8:not an ECS document")));
    assert_eq!(seen.get(1).map(String::as_str), Some("ack:1"));
    assert_eq!(report.dead_lettered, 1);
    Ok(())
}


#[test]
fn a_failed_dead_letter_publish_leaves_the_message_for_redelivery() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\n")?;
    rig.dead_fails.store(true, Ordering::SeqCst);
    enqueue(&rig, vec![delivery("events.tenant-a", "not json", TOKEN_ONE)])?;
    let report = run_cycle(&mut rig.pipeline)?;
    let seen = lines(&rig)?;
    assert!(!seen.iter().any(|line| line == "ack:1"));
    assert_eq!(seen.last().map(String::as_str), Some("nak:1"));
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(report.redelivered, 1);
    Ok(())
}


#[test]
fn bad_tenants_never_reach_the_batcher() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\n")?;
    let long = format!("events.{}", "a".repeat(OVERSIZED_TENANT));
    enqueue(
        &rig,
        vec![
            delivery("events.", EVENT, TOKEN_ONE),
            delivery(&long, EVENT, TOKEN_TWO),
            delivery("metrics.x", EVENT, TOKEN_THREE),
        ],
    )?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(report.refused, SENT);
    assert_eq!(lines(&rig)?, ["ack:1", "ack:2", "ack:3"]);
    Ok(())
}


#[test]
fn a_bus_that_refuses_acknowledgements_is_counted() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 1\n")?;
    rig.ack_fails.store(true, Ordering::SeqCst);
    enqueue(&rig, vec![delivery("events.tenant-a", EVENT, TOKEN_ONE)])?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(report.ack_failures, 1);
    assert_eq!(report.acknowledged, 0);
    Ok(())
}


#[test]
fn a_second_tenant_waits_for_the_flush_of_the_first() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 2\n")?;
    enqueue(
        &rig,
        vec![
            delivery("events.tenant-a", EVENT, TOKEN_ONE),
            delivery("events.tenant-b", EVENT, TOKEN_TWO),
        ],
    )?;
    run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:1", "ack:1"]);
    assert_eq!(rig.pipeline.carry.len(), 1);
    enqueue(&rig, vec![delivery("events.tenant-b", EVENT, TOKEN_THREE)])?;
    run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:1", "ack:1", "sink:tenant-b:2", "ack:2", "ack:3"]);
    assert!(rig.pipeline.carry.is_empty());
    Ok(())
}


#[test]
fn a_full_buffer_flushes_then_takes_the_message() -> Result<(), Box<dyn Error>> {
    let yaml = format!("max_message_bytes: {EVENT_BYTES}\nmax_batch_bytes: {HOLD_BYTES}\nmax_buffered_bytes: {HOLD_BYTES}\n");
    let mut rig = rig(&yaml)?;
    enqueue(
        &rig,
        vec![
            delivery("events.tenant-a", EVENT, TOKEN_ONE),
            delivery("events.tenant-a", EVENT, TOKEN_TWO),
        ],
    )?;
    run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:1", "ack:1"]);
    run_cycle(&mut rig.pipeline)?;
    assert_eq!(rig.pipeline.carry.len(), 0);
    assert_eq!(rig.pipeline.pending.len(), 1);
    Ok(())
}


#[test]
fn dead_letter_payloads_count_against_the_buffer_cap() -> Result<(), Box<dyn Error>> {
    let yaml = format!("max_message_bytes: {EVENT_BYTES}\nmax_batch_bytes: {HOLD_BYTES}\nmax_buffered_bytes: {HOLD_BYTES}\n");
    let mut rig = rig(&yaml)?;
    let garbage = "x".repeat(GARBAGE_BYTES);
    enqueue(
        &rig,
        vec![
            delivery("events.tenant-a", &garbage, TOKEN_ONE),
            delivery("events.tenant-a", &garbage, TOKEN_TWO),
            delivery("events.tenant-a", &garbage, TOKEN_THREE),
        ],
    )?;
    run_cycle(&mut rig.pipeline)?;
    assert!(pending_bytes(&rig.pipeline) <= HOLD_BYTES);
    assert_eq!(rig.pipeline.carry.len(), 1);
    let dead: Vec<String> = lines(&rig)?.into_iter().filter(|line| line.starts_with("dead:")).collect();
    assert_eq!(dead.len(), 1);
    Ok(())
}


#[test]
fn an_old_batch_flushes_on_the_timer_pass() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_age_seconds: 1\n")?;
    enqueue(&rig, vec![delivery("events.tenant-a", EVENT, TOKEN_ONE)])?;
    run_cycle(&mut rig.pipeline)?;
    assert!(lines(&rig)?.is_empty());
    rig.clock.fetch_add(LATER, Ordering::SeqCst);
    run_cycle(&mut rig.pipeline)?;
    assert_eq!(lines(&rig)?, ["sink:tenant-a:1", "ack:1"]);
    Ok(())
}


#[test]
fn a_fetch_error_is_returned_and_loses_nothing() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("")?;
    rig.queue.items.lock().map_err(|_| "poisoned")?.push_back(Err("bus down".to_owned()));
    let outcome = run_cycle(&mut rig.pipeline);
    assert!(matches!(outcome, Err(PipelineError::Fetch(_))));
    assert_eq!(
        outcome.err().map(|error| error.to_string()).as_deref(),
        Some("fetching from the bus failed")
    );
    Ok(())
}


#[test]
fn the_loop_backs_off_on_a_dead_bus_and_restarts_after_a_success() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("")?;
    {
        let mut queue = rig.queue.items.lock().map_err(|_| "poisoned")?;
        (0..FAILING_CYCLES).for_each(|_| queue.push_back(Err("bus down".to_owned())));
    }
    let summary = run_loop(&mut rig.pipeline, &stop_after(CYCLES));
    assert_eq!(
        summary,
        LoopReport {
            cycles: CYCLES,
            fetch_failures: FAILING_CYCLES
        }
    );
    let expected: Vec<Duration> = [FIRST_DELAY_MS, SECOND_DELAY_MS, THIRD_DELAY_MS]
        .into_iter()
        .map(Duration::from_millis)
        .collect();
    assert_eq!(delays(&rig)?, expected);
    {
        let mut queue = rig.queue.items.lock().map_err(|_| "poisoned")?;
        queue.push_back(Err("again".to_owned()));
        queue.push_back(Ok(Vec::new()));
        queue.push_back(Err("again".to_owned()));
    }
    run_loop(&mut rig.pipeline, &stop_after(FAILING_CYCLES));
    let tail: Vec<Duration> = delays(&rig)?.into_iter().skip(FAILING_CYCLES as usize).collect();
    assert_eq!(tail, vec![Duration::from_millis(FIRST_DELAY_MS); TWO]);
    Ok(())
}


#[test]
fn the_loop_returns_at_its_cycle_cap_for_the_caller_to_restart() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("")?;
    let summary = run_loop(&mut rig.pipeline, &|| false);
    assert_eq!(summary.cycles, MAX_LOOP_CYCLES);
    assert_eq!(summary.fetch_failures, 0);
    Ok(())
}


#[test]
fn the_loop_stops_when_asked() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("")?;
    assert_eq!(run_loop(&mut rig.pipeline, &|| true), LoopReport::default());
    assert_eq!(CycleReport::default().fetched, 0);
    Ok(())
}


#[test]
fn an_unparsable_batch_is_split_so_the_valid_rows_land() -> Result<(), Box<dyn Error>> {
    let mut rig = rig("max_batch_messages: 3\nretry_attempts: 1\n")?;
    rig.split_poison.store(true, Ordering::SeqCst);
    let bad = EVENT.replace("\"event\"}", "\"BAD\"}");
    enqueue(
        &rig,
        vec![
            delivery("events.tenant-a", EVENT, TOKEN_ONE),
            delivery("events.tenant-a", &bad, TOKEN_TWO),
            delivery("events.tenant-a", EVENT, TOKEN_THREE),
        ],
    )?;
    let report = run_cycle(&mut rig.pipeline)?;
    assert_eq!(
        lines(&rig)?,
        [
            "sink:tenant-a:3".to_owned(),
            "sink:tenant-a:1".to_owned(),
            "ack:1".to_owned(),
            "sink:tenant-a:1".to_owned(),
            format!("dead:tenant-a:{}:{POISON_REASON}", bad.len()),
            "ack:2".to_owned(),
            "sink:tenant-a:1".to_owned(),
            "ack:3".to_owned(),
        ]
    );
    assert_eq!(report.acknowledged, TWO + 1);
    assert_eq!(report.dead_lettered, 1);
    assert!(rig.pipeline.pending.is_empty());
    Ok(())
}


#[test]
fn an_isolated_message_the_batcher_refuses_is_naked_not_left_pending() -> Result<(), Box<dyn Error>> {
    let yaml = format!("max_message_bytes: {EVENT_BYTES}\nmax_batch_bytes: {HOLD_BYTES}\nmax_buffered_bytes: {HOLD_BYTES}\n");
    let mut rig = rig(&yaml)?;
    let message = |token: u64| Message {
        tenant: "tenant-a".to_owned(),
        payload: EVENT.as_bytes().to_vec(),
        token,
    };
    push(&mut rig.pipeline.batcher, &message(TOKEN_THREE))?;
    [TOKEN_ONE, TOKEN_TWO].into_iter().for_each(|token| {
        rig.pipeline.pending.insert(token, message(token));
    });
    let flushed = FlushReport {
        tenant: "tenant-a".to_owned(),
        acknowledge: Vec::new(),
        unacknowledged: vec![TOKEN_ONE, TOKEN_TWO],
        dead_letters: Vec::new(),
        delivered: 0,
        sink_error: Some(poison_text()),
    };
    let mut report = CycleReport::default();
    settle(&mut rig.pipeline, flushed, &mut report);
    assert_eq!(lines(&rig)?, ["nak:1", "sink:tenant-a:1", "ack:3", "sink:tenant-a:1", "ack:2"]);
    assert_eq!(report.redelivered, 1);
    assert!(rig.pipeline.pending.is_empty());
    Ok(())
}

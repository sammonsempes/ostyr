mod common;


use common::types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::types::{BoxError, SharedAuditFn};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::consume::{run_loop, Hooks};
use metrics_ingest::consumer_settings::{
    limits_state, metrics_view, open_consumer, validate_consumer, ConsumerSettingsError, Engines, OpenError, MAX_METRICS_BATCH_MESSAGES,
};
use metrics_ingest::insert::{Batch, InsertError};
use metrics_ingest::settings::MetricsSettings;
use siem_ingest::model::{Delivery, Wiring};
use siem_ingest::settings::IngestSettings;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};


const NOW: u64 = 1_790_230_470_084_404_000;


const BACKOFF_MS: u64 = 10;


const FIVE: usize = 5;


const CYCLE_CAP: u64 = 50;


const SMALL_CAP: u64 = 3;


const HUNDRED: usize = 100;


const THOUSAND: usize = 1_000;


const SECOND_FETCH: usize = 2;


const THIRD_FETCH: usize = 3;


const SEVEN: usize = 7;


const CYCLES: usize = 4;


const EVENT: &str = r#"{"event":{"dataset":"ostyr.host_metrics"},"host":{"name":"claimed"},"metrics":{"system.uptime":5}}"#;


const BASE: &str = "ingest:\n  nats_consumer: metrics-ingest\n  clickhouse_table: metric_samples\n  backoff_initial_ms: 10\n  max_batch_messages: 5\nlimits:\n  max_batch_rows: 100\n";


fn held<Item>(mutex: &Mutex<Item>) -> MutexGuard<'_, Item> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


fn audit() -> Arc<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Arc::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) })
}


fn engines_for(dir: &TempDir, text: &str) -> Result<(Engines, std::path::PathBuf), Box<dyn std::error::Error>> {
    let path = dir.path().join("metrics.yaml");
    fs::write(&path, text)?;
    Ok((open_consumer(path.clone(), &audit())?, path))
}


fn open_error<'a>(failure: &'a (dyn std::error::Error + 'static)) -> Option<&'a OpenError> {
    failure.downcast_ref::<OpenError>()
}


fn text_with(extra: &str) -> String {
    BASE.replace("limits:", &format!("{extra}limits:"))
}


#[test]
fn the_file_gives_both_engines_and_the_sender_view() -> TestResult {
    let dir = tempdir()?;
    let (engines, _) = engines_for(&dir, BASE)?;
    let ingest = core_config::reload::current_config(&engines.ingest);
    let limits = core_config::reload::current_config(&engines.limits);
    assert_eq!(
        (ingest.nats_consumer.as_str(), ingest.max_batch_messages, limits.max_batch_rows),
        ("metrics-ingest", FIVE, HUNDRED)
    );
    let view = metrics_view(&ingest, &limits);
    assert_eq!(
        (view.url.as_str(), view.table.as_str(), view.timeout_ms, view.limits.max_batch_rows),
        (ingest.clickhouse_url.as_str(), "metric_samples", ingest.insert_timeout_ms, HUNDRED)
    );
    assert!(limits_state(&limits)
        .get("limits")
        .is_some_and(|text| text.contains("max_batch_rows: 100")));
    Ok(())
}


#[test]
fn the_consumers_own_rules_refuse_what_siem_ingest_accepts() -> TestResult {
    let dir = tempdir()?;
    ["siem-ingest", "detection"].iter().try_for_each(|name| -> TestResult {
        let refused = engines_for(&dir, &BASE.replace("metrics-ingest", name))
            .err()
            .ok_or("another durable was accepted")?;
        assert!(refused.to_string().contains("nats_consumer"), "{refused}");
        Ok(())
    })?;
    let large = engines_for(&dir, &BASE.replace("max_batch_messages: 5", "max_batch_messages: 1001"))
        .err()
        .ok_or("accepted")?;
    assert!(large.to_string().contains("max_batch_messages"), "{large}");
    assert!(engines_for(&dir, &BASE.replace("max_batch_messages: 5", "max_batch_messages: 1000")).is_ok());
    assert_eq!(MAX_METRICS_BATCH_MESSAGES, THOUSAND);
    let siem = engines_for(&dir, &BASE.replace("max_batch_messages: 5", "max_batch_messages: 0"))
        .err()
        .ok_or("accepted")?;
    assert!(matches!(
        open_error(siem.as_ref()),
        Some(OpenError::Ingest(ConsumerSettingsError::Ingest(_)))
    ));
    let table = engines_for(&dir, &BASE.replace("metric_samples", "bad`table")).err().ok_or("accepted")?;
    assert!(matches!(
        open_error(table.as_ref()),
        Some(OpenError::Ingest(ConsumerSettingsError::Ingest(_)))
    ));
    let user = engines_for(&dir, &text_with("  clickhouse_user: \"a b\"\n")).err().ok_or("accepted")?;
    assert!(
        matches!(open_error(user.as_ref()), Some(OpenError::Ingest(ConsumerSettingsError::Metrics(_)))),
        "{user}"
    );
    Ok(())
}


#[test]
fn an_unknown_key_or_an_invalid_limit_or_a_missing_file_is_refused_at_open() -> TestResult {
    let dir = tempdir()?;
    let unknown = engines_for(&dir, &format!("{BASE}extra: 1\n")).err().ok_or("accepted")?;
    assert!(matches!(open_error(unknown.as_ref()), Some(OpenError::Config(_))));
    let limits = engines_for(&dir, &BASE.replace("max_batch_rows: 100", "max_batch_rows: 0"))
        .err()
        .ok_or("accepted")?;
    assert!(matches!(open_error(limits.as_ref()), Some(OpenError::Limits(_))), "{limits}");
    let missing = open_consumer(dir.path().join("absent.yaml"), &audit()).err().ok_or("opened")?;
    assert!(matches!(missing, OpenError::Config(_)));
    assert!(validate_consumer(&IngestSettings::default()).is_err());
    Ok(())
}


fn loop_wiring(path: &Path, calls: &Arc<AtomicUsize>, asked: &Arc<Mutex<Vec<usize>>>, redeliver: bool) -> Wiring {
    let counter = Arc::clone(calls);
    let log = Arc::clone(asked);
    let owned = path.to_path_buf();
    Wiring {
        fetch: Box::new(move |max| {
            held(&log).push(max);
            let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
            match call {
                SECOND_FETCH => fs::write(&owned, text_with("").replace("max_batch_messages: 5", "max_batch_messages: 7")).map_err(BoxError::from)?,
                THIRD_FETCH => fs::write(
                    &owned,
                    text_with("")
                        .replace("metrics-ingest", "siem-ingest")
                        .replace("max_batch_rows: 100", "max_batch_rows: 0"),
                )
                .map_err(BoxError::from)?,
                _ => (),
            }
            let wanted = redeliver && call <= SECOND_FETCH;
            Ok(if wanted {
                vec![Delivery {
                    subject: "events.a".to_owned(),
                    payload: EVENT.as_bytes().to_vec(),
                    token: 1,
                    message_ids: vec!["a:agent:1:0".to_owned()],
                    stored_nanos: Some(NOW),
                }]
            } else {
                Vec::new()
            })
        }),
        ack: Box::new(|_, _| Ok(())),
        dead_letter: Box::new(|_, _, _| Ok(())),
        progress: Arc::new(|| Ok(())),
    }
}


#[test]
fn the_loop_backs_off_after_a_failed_insert_stores_the_redelivery_and_reloads_each_cycle() -> TestResult {
    let dir = tempdir()?;
    let (engines, path) = engines_for(&dir, BASE)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let asked: Arc<Mutex<Vec<usize>>> = Arc::default();
    let mut wiring = loop_wiring(&path, &calls, &asked, true);
    let sent: Arc<Mutex<Vec<String>>> = Arc::default();
    let sleeps: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let sent_log = Arc::clone(&sent);
    let sleep_log = Arc::clone(&sleeps);
    let send = move |_: &MetricsSettings, batches: &[Batch]| -> Result<usize, InsertError> {
        batches
            .iter()
            .for_each(|batch| held(&sent_log).push(String::from_utf8_lossy(&batch.body).into_owned()));
        if held(&sent_log).len() == 1 {
            Err(InsertError { sent: 0 })
        } else {
            Ok(batches.len())
        }
    };
    let sleep = move |delay: Duration| held(&sleep_log).push(delay);
    let now = || NOW;
    let hooks = Hooks {
        now: &now,
        sleep: &sleep,
        send: &send,
        max_cycles: CYCLE_CAP,
    };
    let seen = Arc::clone(&calls);
    let stop = move || seen.load(Ordering::SeqCst) >= CYCLES;
    let summary = run_loop(&mut wiring, &engines, &mut CardinalityState::default(), (&hooks, &stop));
    assert_eq!((summary.cycles, summary.failures), (CYCLES as u64, 1));
    assert_eq!(*held(&sleeps), vec![Duration::from_millis(BACKOFF_MS)]);
    let bodies = held(&sent).clone();
    assert_eq!(bodies.len(), SECOND_FETCH);
    assert_eq!(bodies.first(), bodies.get(1));
    assert_eq!(*held(&asked), vec![FIVE, FIVE, SEVEN, SEVEN]);
    Ok(())
}


#[test]
fn a_loop_that_is_stopped_at_once_runs_no_cycle() -> TestResult {
    let dir = tempdir()?;
    let (engines, path) = engines_for(&dir, BASE)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut wiring = loop_wiring(&path, &calls, &Arc::default(), false);
    let send = |_: &MetricsSettings, _: &[Batch]| -> Result<usize, InsertError> { Ok(0) };
    let sleep = |_: Duration| ();
    let now = || NOW;
    let hooks = Hooks {
        now: &now,
        sleep: &sleep,
        send: &send,
        max_cycles: CYCLE_CAP,
    };
    let summary = run_loop(&mut wiring, &engines, &mut CardinalityState::default(), (&hooks, &|| true));
    assert_eq!(summary.cycles, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}


#[test]
fn a_loop_that_is_never_stopped_ends_at_its_cycle_cap() -> TestResult {
    let dir = tempdir()?;
    let (engines, path) = engines_for(&dir, BASE)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut wiring = loop_wiring(&path, &calls, &Arc::default(), false);
    let send = |_: &MetricsSettings, _: &[Batch]| -> Result<usize, InsertError> { Ok(0) };
    let sleep = |_: Duration| ();
    let now = || NOW;
    let hooks = Hooks {
        now: &now,
        sleep: &sleep,
        send: &send,
        max_cycles: SMALL_CAP,
    };
    let summary = run_loop(&mut wiring, &engines, &mut CardinalityState::default(), (&hooks, &|| false));
    assert_eq!((summary.cycles, summary.failures), (SMALL_CAP, 0));
    Ok(())
}

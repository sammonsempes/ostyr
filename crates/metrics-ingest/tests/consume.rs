mod common;
#[path = "consume_support/types.rs"]
mod consume_types;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use consume_types::{Acks, Bodies, Dead};
use core_config::types::BoxError;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::consume::{clickhouse_store, refusal_name, run_cycle, tally_text, ConsumeError, ConsumeReport};
use metrics_ingest::consumer_settings::{metrics_view, MAX_METRICS_BATCH_MESSAGES};
use metrics_ingest::insert::{Batch, InsertError};
use metrics_ingest::model::{DropReason, Limits, Refusal};
use metrics_ingest::settings::MetricsSettings;
use siem_ingest::model::{AckAction, Delivery, Wiring};
use siem_ingest::settings::IngestSettings;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use stub::serve;
use tempfile::tempdir;


const NOW: u64 = 1_790_230_470_084_404_000;


const EVENT_ROWS: usize = 2;


const IGNORED_IDENTITY: u64 = 3;


const BAD_EVENTS: u64 = 2;


const BAD_SUBJECTS: u64 = 3;


const MOUNTS: usize = 64;


const BUDGET_MESSAGES: usize = 1_000;


const TOKEN_ONE: u64 = 1;


const TOKEN_TWO: u64 = 2;


const TOKEN_THREE: u64 = 3;


const TOKEN_FOUR: u64 = 4;


const TOKEN_FIVE: u64 = 5;


const TOKEN_SIX: u64 = 6;


const TOKEN_SEVEN: u64 = 7;


const FORM_COUNT: usize = 9;


const MISMATCH_INDEX: usize = 5;


const FOREIGN_COUNT: usize = 7;


const PAIR: usize = 2;


const OVER_FACTOR: usize = 5;


const SMALL_FETCH: usize = 3;


const FOUR_REQUESTS: usize = 4;


const BIG_BYTES: usize = 300_000;


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


const PASSWORD: &str = "consume-pw-1f9a";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


pub struct Bus {
    pub acks: Acks,
    pub dead: Dead,
    pub asked: Arc<Mutex<Vec<usize>>>,
}


fn held<Item>(mutex: &Mutex<Item>) -> MutexGuard<'_, Item> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


fn event(extra_metrics: &str) -> String {
    format!(
        r#"{{"@timestamp":"2001-01-01T00:00:00Z","ecs":{{"version":"8.11.0"}},"event":{{"kind":"metric","dataset":"ostyr.host_metrics"}},"host":{{"name":"db-prod-1","id":"evil-host"}},"tenant":"evil","metrics":{{"system.cpu.utilization":0.5,"system.uptime":10{extra_metrics}}}}}"#
    )
}


fn mounts_event() -> String {
    let entries: Vec<String> = (0..MOUNTS).map(|index| format!(r#"{{"mountpoint":"/m{index}","value":1}}"#)).collect();
    let array = entries.join(",");
    event(&format!(r#","system.filesystem.limit":[{array}],"system.filesystem.free":[{array}]"#))
}


fn delivery(subject: &str, payload: &str, token: u64, ids: &[&str]) -> Delivery {
    Delivery {
        subject: subject.to_owned(),
        payload: payload.as_bytes().to_vec(),
        token,
        message_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        stored_nanos: Some(NOW),
    }
}


fn host(token: u64, ids: &[&str]) -> Delivery {
    delivery("events.a", &event(""), token, ids)
}


fn make_bus(deliveries: Vec<Delivery>, failing: (Option<u64>, bool)) -> (Wiring, Bus) {
    let acks: Acks = Arc::default();
    let dead: Dead = Arc::default();
    let asked: Arc<Mutex<Vec<usize>>> = Arc::default();
    let mut queue = Some(deliveries);
    let (failing_token, failing_dead) = failing;
    let ack_log = Arc::clone(&acks);
    let dead_log = Arc::clone(&dead);
    let asked_log = Arc::clone(&asked);
    let wiring = Wiring {
        fetch: Box::new(move |max| {
            held(&asked_log).push(max);
            Ok(queue.take().into_iter().flatten().collect())
        }),
        ack: Box::new(move |token, action| {
            held(&ack_log).push((token, action));
            if failing_token == Some(token) {
                Err(BoxError::from("ack refused"))
            } else {
                Ok(())
            }
        }),
        dead_letter: Box::new(move |tenant, payload, reason| {
            if failing_dead {
                Err(BoxError::from("dead letter refused"))
            } else {
                held(&dead_log).push((tenant.to_owned(), payload.to_vec(), reason.to_owned()));
                Ok(())
            }
        }),
        progress: Arc::new(|| Ok(())),
        pulls: Default::default(),
    };
    (wiring, Bus { acks, dead, asked })
}


fn settings() -> (IngestSettings, MetricsSettings) {
    let ingest = IngestSettings::default();
    let metrics = metrics_view(&ingest, &Limits::default());
    (ingest, metrics)
}


fn recording_sender(fail: bool) -> (Box<metrics_ingest::types::StoreFn>, Bodies) {
    let bodies: Bodies = Arc::default();
    let log = Arc::clone(&bodies);
    let send = move |_: &MetricsSettings, batches: &[Batch]| -> Result<usize, InsertError> {
        batches
            .iter()
            .for_each(|batch| held(&log).push(String::from_utf8_lossy(&batch.body).into_owned()));
        if fail {
            Err(InsertError { sent: 0 })
        } else {
            Ok(batches.len())
        }
    };
    (Box::new(send), bodies)
}


fn cycle(wiring: &mut Wiring, send: &metrics_ingest::types::StoreFn) -> Result<ConsumeReport, ConsumeError> {
    let (ingest, metrics) = settings();
    run_cycle(wiring, (&ingest, &metrics), &mut CardinalityState::default(), (NOW, send))
}


fn tally(report: &ConsumeReport, name: &str) -> u64 {
    report.tally.get(name).copied().unwrap_or(0)
}


#[test]
fn a_host_event_stores_rows_for_the_subject_tenant_and_the_header_agent_at_the_stored_time() -> TestResult {
    let (mut wiring, bus) = make_bus(vec![host(TOKEN_ONE, &["a:agent-7:5:0"])], (None, false));
    let (send, bodies) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!((report.fetched, report.rows), (1, EVENT_ROWS));
    let stored = held(&bodies).concat();
    assert!(stored.contains(r#""tenant":"a""#), "{stored}");
    assert!(stored.contains(r#""host.id":"agent-7""#), "{stored}");
    assert!(!stored.contains("evil") && !stored.contains("db-prod-1"), "{stored}");
    assert!(stored.contains("2026-"), "{stored}");
    assert_eq!(*held(&bus.acks), vec![(TOKEN_ONE, AckAction::Ack)]);
    assert!(held(&bus.dead).is_empty());
    assert_eq!(held(&bus.asked).clone(), vec![MAX_METRICS_BATCH_MESSAGES]);
    assert_eq!(report.dropped.get(&DropReason::PayloadIdentityIgnored), Some(&IGNORED_IDENTITY));
    Ok(())
}


#[test]
fn every_unusable_identity_is_dead_lettered_by_name_then_acknowledged_and_nothing_is_stored() -> TestResult {
    let forms: [&[&str]; FORM_COUNT] = [
        &[],
        &["a:b:1:0", "a:b:1:1"],
        &["a:b:1"],
        &["a:b:1:0:9"],
        &["a::1:0"],
        &["b:agent:1:0"],
        &["a:b:01:0"],
        &["a:b:x:0"],
        &["a:b:1:01"],
    ];
    let deliveries: Vec<Delivery> = forms.iter().zip(TOKEN_ONE..).map(|(ids, token)| host(token, ids)).collect();
    let (mut wiring, bus) = make_bus(deliveries, (None, false));
    let (send, bodies) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!(tally(&report, "identity_unusable"), forms.len() as u64);
    assert!(held(&bodies).is_empty());
    assert_eq!(held(&bus.dead).len(), forms.len());
    assert!(held(&bus.dead)
        .iter()
        .all(|(tenant, payload, reason)| tenant == "a" && !payload.is_empty() && reason.starts_with("identity_unusable: ")));
    let reasons: Vec<String> = held(&bus.dead).iter().map(|(_, _, reason)| reason.clone()).collect();
    assert_eq!(reasons.first().map(String::as_str), Some("identity_unusable: no_message_id"));
    assert_eq!(reasons.get(1).map(String::as_str), Some("identity_unusable: repeated_message_id"));
    assert_eq!(
        reasons.get(MISMATCH_INDEX).map(String::as_str),
        Some("identity_unusable: tenant_mismatch")
    );
    assert_eq!(held(&bus.acks).len(), forms.len());
    assert!(held(&bus.acks).iter().all(|(_, action)| *action == AckAction::Ack));
    Ok(())
}


#[test]
fn a_missing_stored_time_is_dead_lettered() -> TestResult {
    let mut message = host(TOKEN_ONE, &["a:b:1:0"]);
    message.stored_nanos = None;
    let (mut wiring, bus) = make_bus(vec![message], (None, false));
    let (send, _) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!(tally(&report, "identity_unusable"), 1);
    assert_eq!(
        held(&bus.dead).first().map(|(_, _, reason)| reason.clone()),
        Some("identity_unusable: no_stored_time".to_owned())
    );
    Ok(())
}


#[test]
fn a_dead_letter_that_is_not_confirmed_goes_back_to_the_bus() -> TestResult {
    let (mut wiring, bus) = make_bus(vec![host(TOKEN_ONE, &[])], (None, true));
    let (send, _) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!((tally(&report, "dead_letter_failed"), tally(&report, "identity_unusable")), (1, 1));
    assert_eq!(*held(&bus.acks), vec![(TOKEN_ONE, AckAction::Nak)]);
    Ok(())
}


#[test]
fn foreign_events_are_acknowledged_and_counted_never_dead_lettered_whatever_their_header() -> TestResult {
    let other = r#"{"event":{"dataset":"other"},"x":1}"#;
    let big = format!(r#"{{"event":{{"dataset":"other"}},"pad":"{}"}}"#, "x".repeat(BIG_BYTES));
    let deliveries = vec![
        delivery("events.a", other, TOKEN_ONE, &["bad", "worse"]),
        delivery("events.a", "not json", TOKEN_TWO, &[]),
        delivery("events.a", &big, TOKEN_THREE, &["b:x:1:0"]),
        delivery("events.a", r#"{"event":"text"}"#, TOKEN_FOUR, &[]),
        delivery("events.-x", other, TOKEN_FIVE, &[]),
        delivery("events.a.b", other, TOKEN_SIX, &[]),
        delivery("other.a", other, TOKEN_SEVEN, &[]),
    ];
    let (mut wiring, bus) = make_bus(deliveries, (None, false));
    let (send, bodies) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!(tally(&report, "not_host_metrics"), 1);
    assert_eq!(tally(&report, "bad_event"), BAD_EVENTS);
    assert_eq!(tally(&report, "too_large"), 1);
    assert_eq!(tally(&report, "bad_subject"), BAD_SUBJECTS);
    assert!(held(&bus.dead).is_empty());
    assert!(held(&bodies).is_empty());
    assert_eq!(held(&bus.acks).len(), FOREIGN_COUNT);
    assert!(held(&bus.acks).iter().all(|(_, action)| *action == AckAction::Ack));
    let text = tally_text(&report.tally);
    assert!(text.contains("bad_subject=3") && text.contains("too_large=1"), "{text}");
    Ok(())
}


#[test]
fn a_failed_insert_naks_every_waiting_message_and_a_redelivery_stores_the_same_rows() -> TestResult {
    let foreign = delivery("events.a", r#"{"event":{"dataset":"other"}}"#, TOKEN_TWO, &[]);
    let (mut wiring, bus) = make_bus(vec![host(TOKEN_ONE, &["a:agent-7:5:0"]), foreign], (None, false));
    let (failing, bodies) = recording_sender(true);
    let error = cycle(&mut wiring, &*failing).err().ok_or("the insert failure was swallowed")?;
    assert!(matches!(error, ConsumeError::Insert(InsertError { sent: 0 })));
    assert_eq!(error.to_string(), "the insert failed after 0 batches");
    assert_eq!(*held(&bus.acks), vec![(TOKEN_TWO, AckAction::Ack), (TOKEN_ONE, AckAction::Nak)]);
    let (mut again, _) = make_bus(vec![host(TOKEN_ONE, &["a:agent-7:5:0"])], (None, false));
    let (working, second) = recording_sender(false);
    cycle(&mut again, &*working)?;
    assert_eq!(held(&bodies).clone(), held(&second).clone());
    assert!(!held(&second).is_empty());
    Ok(())
}


#[test]
fn an_acknowledgement_the_bus_refuses_is_counted_and_the_rest_still_settle() -> TestResult {
    let (mut wiring, bus) = make_bus(
        vec![host(TOKEN_ONE, &["a:b:1:0"]), host(TOKEN_TWO, &["a:b:2:0"])],
        (Some(TOKEN_ONE), false),
    );
    let (send, _) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!(tally(&report, "ack_failed"), 1);
    assert_eq!(held(&bus.acks).len(), PAIR);
    Ok(())
}


#[test]
fn a_fetch_failure_is_an_error() -> TestResult {
    let mut wiring = make_bus(Vec::new(), (None, false)).0;
    wiring.fetch = Box::new(|_| Err(BoxError::from("down")));
    let (send, _) = recording_sender(false);
    let error = cycle(&mut wiring, &*send).err().ok_or("no error")?;
    assert!(matches!(error, ConsumeError::Fetch(_)));
    assert_eq!(error.to_string(), "the bus fetch failed");
    Ok(())
}


#[test]
fn an_event_without_rows_and_a_row_outside_the_window_are_acknowledged_and_counted() -> TestResult {
    let empty = r#"{"event":{"dataset":"ostyr.host_metrics"},"metrics":{"system.uptime":null}}"#;
    let mut ancient = host(TOKEN_TWO, &["a:b:1:0"]);
    ancient.stored_nanos = Some(0);
    let deliveries = vec![delivery("events.a", empty, TOKEN_ONE, &["a:b:1:0"]), ancient];
    let (mut wiring, bus) = make_bus(deliveries, (None, false));
    let (send, bodies) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    assert_eq!(tally(&report, "no_rows"), 1);
    assert!(tally(&report, "row_refused_timestamp_out_of_range") > 0);
    assert!(held(&bodies).is_empty());
    assert_eq!(held(&bus.acks).len(), PAIR);
    assert_eq!(report.dropped.get(&DropReason::NotANumber), Some(&1));
    Ok(())
}


#[test]
fn a_host_the_row_rules_refuse_is_acknowledged_by_name() -> TestResult {
    let (mut wiring, bus) = make_bus(vec![host(TOKEN_ONE, &["a:b:1:0"])], (None, false));
    let (send, _) = recording_sender(false);
    let ingest = IngestSettings::default();
    let limits = Limits {
        max_labels: 0,
        ..Limits::default()
    };
    let metrics = metrics_view(&ingest, &limits);
    let report = run_cycle(&mut wiring, (&ingest, &metrics), &mut CardinalityState::default(), (NOW, &*send))?;
    assert_eq!(tally(&report, "bad_host"), 1);
    assert_eq!(*held(&bus.acks), vec![(TOKEN_ONE, AckAction::Ack)]);
    Ok(())
}


#[test]
fn the_row_budget_inserts_what_is_built_and_sends_the_rest_back_untouched() -> TestResult {
    let payload = mounts_event();
    let deliveries: Vec<Delivery> = (1..=BUDGET_MESSAGES as u64)
        .map(|token| delivery("events.a", &payload, token, &["a:agent:1:0"]))
        .collect();
    let (mut wiring, bus) = make_bus(deliveries, (None, false));
    let (send, bodies) = recording_sender(false);
    let report = cycle(&mut wiring, &*send)?;
    let deferred = tally(&report, "deferred_by_row_budget") as usize;
    assert_eq!(tally(&report, "batch_row_budget"), 1);
    assert!(deferred > 0 && deferred < BUDGET_MESSAGES, "{deferred}");
    let acks = held(&bus.acks).clone();
    assert_eq!(acks.len(), BUDGET_MESSAGES);
    assert_eq!(acks.iter().filter(|(_, action)| *action == AckAction::Nak).count(), deferred);
    let first_nak = acks
        .iter()
        .find(|(_, action)| *action == AckAction::Nak)
        .map(|(token, _)| *token)
        .ok_or("no nak")?;
    assert!(acks
        .iter()
        .filter(|(token, _)| *token < first_nak)
        .all(|(_, action)| *action == AckAction::Ack));
    assert!(!held(&bodies).is_empty());
    Ok(())
}


#[test]
fn the_fetch_never_asks_for_more_than_the_ceiling() -> TestResult {
    let (mut wiring, bus) = make_bus(Vec::new(), (None, false));
    let (send, _) = recording_sender(false);
    let ingest = IngestSettings {
        max_batch_messages: MAX_METRICS_BATCH_MESSAGES * OVER_FACTOR,
        ..IngestSettings::default()
    };
    let metrics = metrics_view(&ingest, &Limits::default());
    let report = run_cycle(&mut wiring, (&ingest, &metrics), &mut CardinalityState::default(), (NOW, &*send))?;
    assert_eq!(report.fetched, 0);
    assert_eq!(*held(&bus.asked), vec![MAX_METRICS_BATCH_MESSAGES]);
    let small = IngestSettings {
        max_batch_messages: SMALL_FETCH,
        ..IngestSettings::default()
    };
    let (mut small_wiring, small_bus) = make_bus(Vec::new(), (None, false));
    let view = metrics_view(&small, &Limits::default());
    run_cycle(&mut small_wiring, (&small, &view), &mut CardinalityState::default(), (NOW, &*send))?;
    assert_eq!(*held(&small_bus.asked), vec![SMALL_FETCH]);
    Ok(())
}


#[test]
fn a_zero_batch_limit_is_an_encode_error_and_naks_the_waiting_messages() -> TestResult {
    let (mut wiring, bus) = make_bus(vec![host(TOKEN_ONE, &["a:b:1:0"])], (None, false));
    let (send, _) = recording_sender(false);
    let ingest = IngestSettings::default();
    let limits = Limits {
        max_batch_rows: 0,
        ..Limits::default()
    };
    let metrics = metrics_view(&ingest, &limits);
    let error = run_cycle(&mut wiring, (&ingest, &metrics), &mut CardinalityState::default(), (NOW, &*send))
        .err()
        .ok_or("no error")?;
    assert!(matches!(error, ConsumeError::Encode(_)));
    assert_eq!(error.to_string(), "the rows could not be encoded");
    assert_eq!(*held(&bus.acks), vec![(TOKEN_ONE, AckAction::Nak)]);
    Ok(())
}


#[test]
fn refusals_have_fixed_names() -> TestResult {
    assert_eq!(refusal_name(&Refusal::TooLarge { bytes: 1 }), "too_large");
    assert_eq!(refusal_name(&Refusal::BadEvent), "bad_event");
    assert_eq!(refusal_name(&Refusal::NotHostMetrics), "not_host_metrics");
    assert_eq!(refusal_name(&Refusal::BadHost), "bad_host");
    assert_eq!(refusal_name(&Refusal::TooManyResources { count: 1 }), "refused");
    Ok(())
}


fn store_settings(port: u16, password: &Path) -> MetricsSettings {
    let ingest = IngestSettings {
        clickhouse_url: format!("http://127.0.0.1:{port}"),
        clickhouse_table: "metric_samples".to_owned(),
        clickhouse_password_file: password.to_path_buf(),
        ..IngestSettings::default()
    };
    metrics_view(&ingest, &Limits::default())
}


fn batches() -> Vec<Batch> {
    vec![
        Batch {
            body: b"{}\n".to_vec(),
            rows: 1,
        },
        Batch {
            body: b"{}\n".to_vec(),
            rows: 1,
        },
    ]
}


#[test]
fn the_store_sends_each_batch_and_reports_the_count_sent_or_the_failure() -> TestResult {
    let dir = tempdir()?;
    let password = dir.path().join("password");
    write_secret(&password, PASSWORD)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let settings = store_settings(listener.local_addr()?.port(), &password);
    let server = serve(listener.try_clone()?, vec![OK, OK, OK, SERVER_ERROR]);
    assert_eq!(clickhouse_store(&settings, &batches())?, PAIR);
    assert_eq!(clickhouse_store(&settings, &batches()).err().map(|failed| failed.sent), Some(1));
    let seen = server.join().map_err(|_| "server panicked")??;
    assert_eq!(seen.len(), FOUR_REQUESTS);
    assert!(seen.iter().all(|request| !request.lines().next().unwrap_or("").contains(PASSWORD)));
    let missing = store_settings(1, &dir.path().join("absent"));
    assert_eq!(clickhouse_store(&missing, &batches()).err().map(|failed| failed.sent), Some(0));
    Ok(())
}


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)
}


#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


static ANCHOR: std::sync::LazyLock<tracing::Dispatch> =
    std::sync::LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[test]
fn confirmed_identity_dead_letters_are_one_grouped_line_per_cycle() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let forms: [&[&str]; THREE_FORMS] = [&[], &[], &["a::1:0"]];
    let deliveries: Vec<Delivery> = forms.iter().zip(TOKEN_ONE..).map(|(ids, token)| host(token, ids)).collect();
    let (mut wiring, _bus) = make_bus(deliveries, (None, false));
    let (send, _) = recording_sender(false);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&bytes));
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let report = tracing::subscriber::with_default(subscriber, || cycle(&mut wiring, &*send))?;
    let logs = String::from_utf8(held(&bytes).clone())?;
    assert_eq!(tally(&report, "identity_unusable"), THREE_FORMS as u64);
    assert_eq!(logs.matches("dead letters of this cycle").count(), 1, "{logs}");
    assert!(logs.contains("a/identity_unusable:no_message_id=2"), "{logs}");
    assert!(logs.contains("a/identity_unusable:bad_agent_id=1"), "{logs}");
    Ok(())
}


#[test]
fn an_unconfirmed_identity_dead_letter_is_not_recorded() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let (mut wiring, _bus) = make_bus(vec![host(TOKEN_ONE, &[])], (None, true));
    let (send, _) = recording_sender(false);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&bytes));
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    tracing::subscriber::with_default(subscriber, || cycle(&mut wiring, &*send))?;
    assert!(!String::from_utf8(held(&bytes).clone())?.contains("dead letters of this cycle"));
    Ok(())
}


const THREE_FORMS: usize = 3;

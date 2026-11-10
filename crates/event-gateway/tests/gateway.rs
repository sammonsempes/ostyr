mod common;
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;


use agent_channel::model::Identity;
use agent_channel::proto::EventBatch;
use common::types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{reload, ReloadContext, ReloadEngine, ReloadOutcome};
use event_gateway::error::GatewayError;
use event_gateway::model::{Gateway, GatewaySettings};
use event_gateway::model::{RefusalCounts, Refusals};
use event_gateway::publish::{
    admit, check_identity, count_refusal, events_of, forced_payload, gateway_sink, log_summary, message_id, outgoing_events, publish_batch,
    refusal_counts, spawn_summary,
};
use event_gateway::session::{backoff_delay, new_gateway, settings_of};
use event_gateway::settings::{open_settings, path_text, settings_state, validate_settings};
use nats_stub::{kill_connections, lock, start_stub, wait_until, Stub};
use nkeys::KeyPair;
use serde_json::Value;
use siem_ingest::error::NatsError;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::time::sleep;
use tracing::level_filters::{LevelFilter, STATIC_MAX_LEVEL};


const TWO: usize = 2;


const SUMMARY_PERIOD_MS: u64 = 1000;


const FOUR: usize = 4;


const TWO_FAILURES: u32 = 2;


const THREE_FAILURES: u32 = 3;


const SECOND_SEQUENCE: u64 = 2;


const DEFAULT_EVENTS: usize = 1000;


const MS_OVER_LIMIT: u64 = 600_001;


const COUNT_OVER_LIMIT: usize = 100_001;


const INITIAL_ABOVE_MAX: u64 = 10;


const MAX_BELOW_INITIAL: u64 = 5;


const BASE_MS: u64 = 100;


const DOUBLE_MS: u64 = 200;


const QUADRUPLE_MS: u64 = 400;


const CEILING_MS: u64 = 1000;


const SETTINGS_FILE: &str = "gateway.yaml";


const POLLS: usize = 2000;


const POLL_MS: u64 = 5;


const OUTAGE_POLLS: usize = 200;


const SHORT_MS: u64 = 300;


const GENEROUS_MS: u64 = 20_000;


const LONG_BACKOFF_MS: u64 = 600_000;


const SEQUENCE: u64 = 7;


const SMALL_PAYLOAD_LIMIT: usize = 1024;


const BIG_EVENT_BYTES: usize = 2000;


const CROWD: usize = 24;


const CROWD_IN_FLIGHT: usize = 4;


const FAILURES_FAR: u32 = 4000;


const TRACE_PASSWORD: &str = "TRACEPW-9f3a7c1d";


const TRACE_JWT: &str = "TRACEJWT.9f3a7c1d.payload";


const TRACE_PAYLOAD: &str = "TRACEPAYLOAD-5e2b8d40";


fn identity(tenant: &str, agent: &str) -> Identity {
    Identity {
        tenant: tenant.to_owned(),
        agent_id: agent.to_owned(),
    }
}


fn batch(sequence: u64, lines: &[&str]) -> EventBatch {
    EventBatch {
        sequence,
        ecs_json: lines.join("\n").into_bytes(),
        tenant: String::new(),
        agent_id: String::new(),
    }
}


pub struct Rig {
    pub dir: TempDir,
    pub path: PathBuf,
    pub engine: Arc<ReloadEngine<GatewaySettings>>,
    pub gateway: Arc<Gateway>,
    pub audit: Arc<Mutex<Vec<NewEntry>>>,
}


fn yaml_with(port: u16, (connect_ms, publish_ms): (u64, u64), extra: &str) -> String {
    format!("nats_url: \"nats://127.0.0.1:{port}\"\nconnect_timeout_ms: {connect_ms}\npublish_timeout_ms: {publish_ms}\n{extra}")
}


fn yaml(port: u16, extra: &str) -> String {
    yaml_with(port, (GENEROUS_MS, GENEROUS_MS), extra)
}


fn rig(text: &str) -> Result<Rig, Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let path = dir.path().join(SETTINGS_FILE);
    fs::write(&path, text)?;
    let audit = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&audit);
    let log = genesis_log(io::sink());
    let engine = Arc::new(open_settings(
        path.clone(),
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> {
            kept.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
            append(&log, entry)
        }),
        ReloadContext {
            actor_id: "test".to_owned(),
            tenant: "platform".to_owned(),
            module: "event-gateway".to_owned(),
            target: path.display().to_string(),
            request_id: "test".to_owned(),
        },
    )?);
    let gateway = Arc::new(new_gateway(Arc::clone(&engine)));
    Ok(Rig {
        dir,
        path,
        engine,
        gateway,
        audit,
    })
}


fn dead_port() -> Result<u16, Box<dyn Error + Send + Sync>> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}


fn published(stub: &Stub) -> Vec<(String, String, Vec<u8>)> {
    lock(&stub.hub)
        .published
        .iter()
        .map(|message| (message.subject.clone(), message.headers.clone(), message.payload.clone()))
        .collect()
}


async fn eventually_in_flight(rig: &Rig, wanted: usize) -> TestResult {
    let mut reached = false;
    for _ in 0..POLLS {
        reached = reached || rig.gateway.in_flight.load(Ordering::SeqCst) == wanted;
        if !reached {
            sleep(Duration::from_millis(POLL_MS)).await;
        }
    }
    if reached {
        Ok(())
    } else {
        Err("the in-flight count was not reached".into())
    }
}


#[tokio::test]
async fn a_batch_is_published_per_event_with_subjects_and_message_ids() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    let agent = identity("tenant-a", "agent-1");
    publish_batch(&rig.gateway, &agent, &batch(SEQUENCE, &["{\"event\":1}", "{\"event\":2}"])).await?;
    let sent = published(&stub);
    assert_eq!(sent.len(), TWO);
    assert!(sent.iter().all(|(subject, _, _)| subject == "events.tenant-a"));
    let mut identifiers: Vec<String> = sent
        .iter()
        .filter_map(|(_, headers, _)| headers.lines().find_map(|line| line.strip_prefix("Nats-Msg-Id: ")).map(str::to_owned))
        .collect();
    identifiers.sort();
    assert_eq!(identifiers, vec!["tenant-a:agent-1:7:0".to_owned(), "tenant-a:agent-1:7:1".to_owned()]);
    assert_eq!(settings_of(&rig.gateway).max_events_per_batch, DEFAULT_EVENTS);
    Ok(())
}


#[tokio::test]
async fn a_replayed_batch_carries_the_same_message_ids() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    let agent = identity("tenant-a", "agent-1");
    let events = batch(SEQUENCE, &["{\"event\":1}", "{\"event\":2}"]);
    publish_batch(&rig.gateway, &agent, &events).await?;
    publish_batch(&rig.gateway, &agent, &events).await?;
    let sent = published(&stub);
    assert_eq!(sent.len(), FOUR);
    let ids_of =
        |range: std::ops::Range<usize>| -> Vec<String> { sent.get(range).into_iter().flatten().map(|(_, headers, _)| headers.clone()).collect() };
    let mut first = ids_of(0..TWO);
    let mut second = ids_of(TWO..FOUR);
    first.sort();
    second.sort();
    assert_eq!(first, second);
    assert_eq!(message_id(&agent, SEQUENCE, 1), "tenant-a:agent-1:7:1");
    Ok(())
}


#[tokio::test]
async fn the_sink_acknowledges_only_after_every_event_was_confirmed() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    let sink = gateway_sink(Arc::clone(&rig.gateway));
    sink(identity("tenant-a", "agent-1"), batch(1, &["{\"event\":1}"])).await?;
    assert_eq!(published(&stub).len(), 1);
    lock(&stub.hub).fail_publish = true;
    let refused = sink(identity("tenant-a", "agent-1"), batch(SECOND_SEQUENCE, &["{\"event\":2}"])).await;
    assert!(refused.is_err());
    assert_eq!(rig.gateway.in_flight.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_stub_that_never_confirms_leaves_the_batch_unacknowledged_at_the_deadline() -> TestResult {
    let stub = start_stub(None, |state| state.silent_publish = true)?;
    let rig = rig(&yaml_with(stub.port, (GENEROUS_MS, SHORT_MS), ""))?;
    let outcome = publish_batch(&rig.gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{\"event\":1}"])).await;
    assert!(matches!(outcome, Err(GatewayError::Publish(_))));
    assert_eq!(rig.gateway.in_flight.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_stub_that_refuses_the_publish_leaves_the_batch_unacknowledged() -> TestResult {
    let stub = start_stub(None, |state| state.fail_publish = true)?;
    let rig = rig(&yaml(stub.port, ""))?;
    let outcome = publish_batch(&rig.gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{\"event\":1}"])).await;
    assert!(matches!(outcome, Err(GatewayError::Publish(_))));
    Ok(())
}


#[tokio::test]
async fn a_payload_above_the_server_limit_refuses_the_whole_batch_before_publishing() -> TestResult {
    let stub = start_stub(None, |state| state.max_payload = SMALL_PAYLOAD_LIMIT)?;
    let rig = rig(&yaml(stub.port, ""))?;
    let big = format!("{{\"data\":\"{}\"}}", "x".repeat(BIG_EVENT_BYTES));
    let outcome = publish_batch(&rig.gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{\"event\":1}", &big])).await;
    assert!(matches!(
        outcome,
        Err(GatewayError::PayloadTooLarge {
            max: SMALL_PAYLOAD_LIMIT,
            ..
        })
    ));
    assert!(published(&stub).is_empty());
    Ok(())
}


#[tokio::test]
async fn too_many_events_refuse_the_batch() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, "max_events_per_batch: 1\n"))?;
    let outcome = publish_batch(&rig.gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{\"a\":1}", "{\"b\":2}"])).await;
    assert!(matches!(outcome, Err(GatewayError::TooManyEvents { count: TWO, max: 1 })));
    assert!(published(&stub).is_empty());
    Ok(())
}


#[tokio::test]
async fn an_identity_that_is_not_a_subject_token_is_refused() -> TestResult {
    assert!(check_identity(&identity("tenant-a", "agent-1")).is_ok());
    for (tenant, agent) in [
        ("a.b", "agent"),
        ("a b", "agent"),
        ("a>", "agent"),
        ("", "agent"),
        ("tenant", ""),
        ("tenant", "ag:ent"),
    ] {
        assert!(matches!(check_identity(&identity(tenant, agent)), Err(GatewayError::Identity)));
    }
    let settings = GatewaySettings::default();
    assert!(matches!(
        outgoing_events(&identity("a.b", "agent"), &batch(1, &["{}"]), &settings, SMALL_PAYLOAD_LIMIT),
        Err(GatewayError::Identity)
    ));
    Ok(())
}


#[tokio::test]
async fn the_tenant_comes_from_the_identity_never_from_the_event() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    let lines = [
        "{\"tenant\":\"b\",\"event\":1}",
        "{\"event\":2}",
        "{\"tenant\":\"a\",\"event\":3}",
        "{\"tenant\":\"b\",\"tenant\":\"a\",\"event\":4}",
    ];
    publish_batch(&rig.gateway, &identity("a", "agent-1"), &batch(1, &lines)).await?;
    let sent = published(&stub);
    assert_eq!(sent.len(), lines.len());
    assert!(sent.iter().all(|(subject, _, _)| subject == "events.a"));
    let payloads: Vec<String> = sent.iter().map(|(_, _, payload)| String::from_utf8_lossy(payload).into_owned()).collect();
    assert!(payloads
        .iter()
        .all(|text| text.matches("\"tenant\"").count() == 1 && text.contains("\"tenant\":\"a\"")));
    assert!(!payloads.iter().any(|text| text.contains("\"b\"")));
    assert_eq!(forced_payload(b"{\"tenant\":\"a\"}", "a")?.as_ref(), b"{\"tenant\":\"a\"}");
    assert_eq!(events_of(b"a\n\nb\n").len(), TWO);
    Ok(())
}


#[tokio::test]
async fn an_event_that_is_not_exactly_one_object_refuses_the_whole_batch() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    for bad in ["{\"tenant\":\"b\",\"event\":1} x", "not json", "[1,2]", "{\"a\":1}{\"b\":2}"] {
        let outcome = publish_batch(&rig.gateway, &identity("a", "agent-1"), &batch(1, &["{\"event\":0}", bad])).await;
        assert!(matches!(outcome, Err(GatewayError::NotAnObject(_))));
    }
    assert!(published(&stub).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_dead_server_fails_the_batch_then_backs_off() -> TestResult {
    let rig = rig(&yaml(
        dead_port()?,
        &format!("backoff_initial_ms: {LONG_BACKOFF_MS}\nbackoff_max_ms: {LONG_BACKOFF_MS}\n"),
    ))?;
    let agent = identity("tenant-a", "agent-1");
    let first = publish_batch(&rig.gateway, &agent, &batch(1, &["{}"])).await;
    assert!(matches!(first, Err(GatewayError::Nats(_))));
    let second = publish_batch(&rig.gateway, &agent, &batch(1, &["{}"])).await;
    assert!(matches!(second, Err(GatewayError::BackingOff)));
    assert_eq!(rig.gateway.in_flight.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn the_gateway_reconnects_when_the_server_comes_back_through_a_reload() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(dead_port()?, "backoff_initial_ms: 1\nbackoff_max_ms: 1\n"))?;
    let agent = identity("tenant-a", "agent-1");
    assert!(publish_batch(&rig.gateway, &agent, &batch(1, &["{}"])).await.is_err());
    fs::write(&rig.path, yaml(stub.port, "backoff_initial_ms: 1\nbackoff_max_ms: 1\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    let mut recovered = false;
    for _ in 0..OUTAGE_POLLS {
        recovered = recovered || publish_batch(&rig.gateway, &agent, &batch(SECOND_SEQUENCE, &["{}"])).await.is_ok();
        sleep(Duration::from_millis(POLL_MS)).await;
    }
    assert!(recovered);
    assert!(!published(&stub).is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_connection_is_replaced_on_the_next_publish() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, "backoff_initial_ms: 1\nbackoff_max_ms: 1\n"))?;
    let agent = identity("tenant-a", "agent-1");
    publish_batch(&rig.gateway, &agent, &batch(1, &["{}"])).await?;
    kill_connections(&stub);
    wait_until(&stub, |state| state.connections >= TWO)?;
    let mut recovered = false;
    for sequence in SECOND_SEQUENCE..(OUTAGE_POLLS as u64) {
        recovered = recovered || publish_batch(&rig.gateway, &agent, &batch(sequence, &["{}"])).await.is_ok();
        sleep(Duration::from_millis(POLL_MS)).await;
    }
    assert!(recovered);
    assert!(lock(&stub.hub).connects.len() >= TWO);
    Ok(())
}


#[tokio::test]
async fn a_server_that_accepts_and_never_speaks_hits_the_deadline_and_frees_the_slot() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let rig = rig(&yaml_with(
        port,
        (SHORT_MS, SHORT_MS),
        &format!("max_in_flight_batches: {CROWD_IN_FLIGHT}\nbackoff_initial_ms: 1\nbackoff_max_ms: 1\n"),
    ))?;
    let mut tasks = Vec::new();
    for sequence in 0..CROWD {
        let gateway = Arc::clone(&rig.gateway);
        tasks.push(tokio::spawn(async move {
            publish_batch(&gateway, &identity("tenant-a", "agent-1"), &batch(sequence as u64, &["{}"])).await
        }));
    }
    for task in tasks {
        assert!(task.await?.is_err());
    }
    assert_eq!(rig.gateway.in_flight.load(Ordering::SeqCst), 0);
    drop(listener);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_in_flight_cap_refuses_at_once_and_a_waiting_batch_ends_at_the_deadline() -> TestResult {
    let rig = rig(&yaml_with(dead_port()?, (GENEROUS_MS, GENEROUS_MS), "max_in_flight_batches: 1\n"))?;
    let held = rig.gateway.link.lock().await;
    let waiting_gateway = Arc::clone(&rig.gateway);
    let waiting = tokio::spawn(async move { publish_batch(&waiting_gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{}"])).await });
    eventually_in_flight(&rig, 1).await?;
    let refused = publish_batch(&rig.gateway, &identity("tenant-a", "agent-2"), &batch(1, &["{}"])).await;
    assert!(matches!(refused, Err(GatewayError::Busy { max: 1 })));
    assert!(matches!(waiting.await?, Err(GatewayError::Timeout(_))));
    drop(held);
    eventually_in_flight(&rig, 0).await
}


#[tokio::test]
async fn admit_gives_the_place_back_when_the_slot_drops() -> TestResult {
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first = admit(&counter, 1)?;
    assert!(matches!(admit(&counter, 1), Err(GatewayError::Busy { max: 1 })));
    drop(first);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert!(admit(&counter, 1).is_ok());
    Ok(())
}


#[tokio::test]
async fn a_reload_applies_to_the_next_publish_and_an_invalid_one_is_refused_and_audited() -> TestResult {
    let stub = start_stub(None, |_| ())?;
    let rig = rig(&yaml(stub.port, ""))?;
    let agent = identity("tenant-a", "agent-1");
    publish_batch(&rig.gateway, &agent, &batch(1, &["{\"a\":1}", "{\"b\":2}"])).await?;
    fs::write(&rig.path, yaml(stub.port, "max_events_per_batch: 1\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    let tightened = publish_batch(&rig.gateway, &agent, &batch(SECOND_SEQUENCE, &["{\"a\":1}", "{\"b\":2}"])).await;
    assert!(matches!(tightened, Err(GatewayError::TooManyEvents { count: TWO, max: 1 })));
    fs::write(&rig.path, yaml(stub.port, "max_events_per_batch: 0\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(settings_of(&rig.gateway).max_events_per_batch, 1);
    fs::write(&rig.path, yaml(stub.port, "max_events_per_batch: 1\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Unchanged));
    let entries = rig.audit.lock().map_err(|error| error.to_string())?;
    assert_eq!(entries.len(), TWO);
    assert!(entries.iter().all(|entry| entry.action == "config.reload"));
    drop(entries);
    assert!(rig.dir.path().exists());
    Ok(())
}


#[test]
fn settings_are_validated() -> TestResult {
    assert!(validate_settings(&GatewaySettings::default()).is_ok());
    let base = GatewaySettings::default;
    let broken = [
        GatewaySettings {
            nats_url: "http://x".to_owned(),
            ..base()
        },
        GatewaySettings {
            connect_timeout_ms: 0,
            ..base()
        },
        GatewaySettings {
            publish_timeout_ms: MS_OVER_LIMIT,
            ..base()
        },
        GatewaySettings {
            ping_interval_ms: 0,
            ..base()
        },
        GatewaySettings {
            max_in_flight_batches: 0,
            ..base()
        },
        GatewaySettings {
            max_events_per_batch: COUNT_OVER_LIMIT,
            ..base()
        },
        GatewaySettings {
            backoff_initial_ms: 0,
            ..base()
        },
        GatewaySettings { backoff_max_ms: 0, ..base() },
        GatewaySettings {
            backoff_initial_ms: INITIAL_ABOVE_MAX,
            backoff_max_ms: MAX_BELOW_INITIAL,
            ..base()
        },
        GatewaySettings {
            nats_ca_file: Some(PathBuf::new()),
            ..base()
        },
        GatewaySettings {
            nats_password_file: Some(PathBuf::new()),
            nats_user: Some("u".to_owned()),
            ..base()
        },
        GatewaySettings {
            nats_credentials_file: Some(PathBuf::new()),
            ..base()
        },
        GatewaySettings {
            nats_user: Some("u".to_owned()),
            ..base()
        },
        GatewaySettings {
            nats_password_file: Some(PathBuf::from("/p")),
            ..base()
        },
        GatewaySettings {
            nats_user: Some(String::new()),
            nats_password_file: Some(PathBuf::from("/p")),
            ..base()
        },
        GatewaySettings {
            nats_user: Some("u".to_owned()),
            nats_password_file: Some(PathBuf::from("/p")),
            nats_credentials_file: Some(PathBuf::from("/c")),
            ..base()
        },
    ];
    for settings in &broken {
        assert!(validate_settings(settings).is_err(), "{settings:?}");
    }
    let good = GatewaySettings {
        nats_user: Some("u".to_owned()),
        nats_password_file: Some(PathBuf::from("/p")),
        nats_ca_file: Some(PathBuf::from("/ca")),
        ..base()
    };
    assert!(validate_settings(&good).is_ok());
    let state = settings_state(&good);
    assert_eq!(state.get("nats_user").map(String::as_str), Some("u"));
    assert_eq!(state.get("nats_credentials_file").map(String::as_str), Some(""));
    assert_eq!(path_text(good.nats_ca_file.as_ref()), "/ca");
    assert!(!format!("{state:?}").contains("secret"));
    Ok(())
}


#[test]
fn the_backoff_doubles_and_stops_at_its_ceiling() -> TestResult {
    let settings = GatewaySettings {
        backoff_initial_ms: BASE_MS,
        backoff_max_ms: CEILING_MS,
        ..GatewaySettings::default()
    };
    assert_eq!(backoff_delay(&settings, 0), Duration::from_millis(BASE_MS));
    assert_eq!(backoff_delay(&settings, 1), Duration::from_millis(BASE_MS));
    assert_eq!(backoff_delay(&settings, TWO_FAILURES), Duration::from_millis(DOUBLE_MS));
    assert_eq!(backoff_delay(&settings, THREE_FAILURES), Duration::from_millis(QUADRUPLE_MS));
    assert_eq!(backoff_delay(&settings, FAILURES_FAR), Duration::from_millis(CEILING_MS));
    Ok(())
}


#[test]
fn a_bad_ca_or_credentials_file_is_a_typed_error_without_its_content() -> TestResult {
    let rig_dir = tempdir()?;
    let garbage = rig_dir.path().join("garbage");
    fs::write(&garbage, "SECRET-CONTENT")?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    for settings in [
        GatewaySettings {
            nats_ca_file: Some(garbage.clone()),
            ..GatewaySettings::default()
        },
        GatewaySettings {
            nats_credentials_file: Some(garbage.clone()),
            ..GatewaySettings::default()
        },
        GatewaySettings {
            nats_ca_file: Some(rig_dir.path().join("missing")),
            ..GatewaySettings::default()
        },
    ] {
        let outcome = runtime.block_on(event_gateway::session::open_session(&Arc::new(settings)));
        let error = outcome.err().ok_or("expected an error")?;
        assert!(matches!(
            error,
            GatewayError::Nats(NatsError::CaEmpty | NatsError::Credentials(_) | NatsError::File { .. })
        ));
        assert!(!error.to_string().contains("SECRET-CONTENT"));
    }
    Ok(())
}


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


#[tokio::test]
async fn credentials_and_payloads_never_reach_a_trace_subscriber() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    let stub = start_stub(None, |state| state.nonce = true)?;
    let dir = tempdir()?;
    let password_path = dir.path().join("nats.password");
    fs::write(&password_path, format!("{TRACE_PASSWORD}\n"))?;
    let extra = format!("nats_user: ops\nnats_password_file: \"{}\"\n", password_path.display());
    let first = rig(&yaml(stub.port, &extra))?;
    let event = format!("{{\"marker\":\"{TRACE_PAYLOAD}\"}}");
    publish_batch(&first.gateway, &identity("tenant-a", "agent-1"), &batch(1, &[&event])).await?;
    let credentials_stub = start_stub(None, |state| state.nonce = true)?;
    let pair = KeyPair::new_user();
    let seed = pair.seed()?;
    let credentials_path = dir.path().join("nats.creds");
    fs::write(
        &credentials_path,
        format!("-----BEGIN NATS USER JWT-----\n{TRACE_JWT}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"),
    )?;
    let second = rig(&yaml(
        credentials_stub.port,
        &format!("nats_credentials_file: \"{}\"\n", credentials_path.display()),
    ))?;
    publish_batch(&second.gateway, &identity("tenant-a", "agent-1"), &batch(1, &[&event])).await?;
    let connects = lock(&credentials_stub.hub).connects.clone();
    assert_eq!(
        connects.first().and_then(|connect| connect.get("jwt")).and_then(Value::as_str),
        Some(TRACE_JWT)
    );
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(!logs.is_empty());
    for secret in [TRACE_PASSWORD, TRACE_JWT, seed.as_str(), TRACE_PAYLOAD] {
        assert!(!logs.contains(secret));
    }
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(STATIC_MAX_LEVEL <= LevelFilter::DEBUG);
    Ok(())
}


#[test]
fn missing_credential_files_and_a_valid_ca_are_handled_at_connect() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("missing");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    for settings in [
        GatewaySettings {
            nats_credentials_file: Some(missing.clone()),
            ..GatewaySettings::default()
        },
        GatewaySettings {
            nats_user: Some("ops".to_owned()),
            nats_password_file: Some(missing.clone()),
            ..GatewaySettings::default()
        },
    ] {
        let outcome = runtime.block_on(event_gateway::session::open_session(&Arc::new(settings)));
        assert!(matches!(outcome.err(), Some(GatewayError::Nats(NatsError::File { .. }))));
    }
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let ca = dir.path().join("ca.pem");
    fs::write(&ca, certified.cert.pem())?;
    for tls_first in [false, true] {
        let settings = GatewaySettings {
            nats_ca_file: Some(ca.clone()),
            nats_tls_first: tls_first,
            ..GatewaySettings::default()
        };
        assert!(event_gateway::session::connect_options(&settings, Arc::new(std::sync::atomic::AtomicBool::new(false))).is_ok());
    }
    Ok(())
}


#[test]
fn a_first_settings_file_that_does_not_parse_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join(SETTINGS_FILE);
    fs::write(&path, "unknown_key: 1\n")?;
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "platform".to_owned(),
        module: "event-gateway".to_owned(),
        target: path.display().to_string(),
        request_id: "test".to_owned(),
    };
    let log = genesis_log(io::sink());
    let outcome = open_settings(
        path,
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
        context,
    );
    assert!(matches!(outcome.err(), Some(GatewayError::Config(_))));
    Ok(())
}


#[tokio::test]
async fn every_refusal_kind_increments_its_own_counter() -> TestResult {
    let stub = start_stub(None, |state| state.max_payload = SMALL_PAYLOAD_LIMIT)?;
    let rig = rig(&yaml(stub.port, "max_events_per_batch: 1\n"))?;
    let agent = identity("tenant-a", "agent-1");
    let big = format!("{{\"data\":\"{}\"}}", "x".repeat(BIG_EVENT_BYTES));
    publish_batch(&rig.gateway, &agent, &batch(1, &["not json"]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    publish_batch(&rig.gateway, &agent, &batch(1, &[&big]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    publish_batch(&rig.gateway, &agent, &batch(1, &["{}", "{}"]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    publish_batch(&rig.gateway, &identity("a.b", "agent-1"), &batch(1, &["{}"]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    publish_batch(&rig.gateway, &agent, &batch(1, &["{}"])).await?;
    assert_eq!(
        refusal_counts(&rig.gateway.refusals),
        RefusalCounts {
            not_an_object: 1,
            payload_too_large: 1,
            too_many_events: 1,
            invalid_identity: 1,
            busy: 0,
            backing_off: 0,
        }
    );
    Ok(())
}


#[tokio::test]
async fn a_backing_off_gateway_counts_the_refusal_and_a_nats_failure_does_not() -> TestResult {
    let rig = rig(&yaml(
        dead_port()?,
        &format!("backoff_initial_ms: {LONG_BACKOFF_MS}\nbackoff_max_ms: {LONG_BACKOFF_MS}\n"),
    ))?;
    let agent = identity("tenant-a", "agent-1");
    publish_batch(&rig.gateway, &agent, &batch(1, &["{}"]))
        .await
        .err()
        .ok_or("expected a failure")?;
    assert_eq!(refusal_counts(&rig.gateway.refusals), RefusalCounts::default());
    publish_batch(&rig.gateway, &agent, &batch(1, &["{}"]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    assert_eq!(refusal_counts(&rig.gateway.refusals).backing_off, 1);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_batch_refused_as_busy_is_counted() -> TestResult {
    let rig = rig(&yaml_with(dead_port()?, (GENEROUS_MS, GENEROUS_MS), "max_in_flight_batches: 1\n"))?;
    let held = rig.gateway.link.lock().await;
    let waiting_gateway = Arc::clone(&rig.gateway);
    let waiting = tokio::spawn(async move { publish_batch(&waiting_gateway, &identity("tenant-a", "agent-1"), &batch(1, &["{}"])).await });
    eventually_in_flight(&rig, 1).await?;
    publish_batch(&rig.gateway, &identity("tenant-a", "agent-2"), &batch(1, &["{}"]))
        .await
        .err()
        .ok_or("expected a refusal")?;
    assert_eq!(refusal_counts(&rig.gateway.refusals).busy, 1);
    waiting.await?.err().ok_or("expected a timeout")?;
    drop(held);
    Ok(())
}


#[tokio::test]
async fn the_counters_are_logged_by_the_summary() -> TestResult {
    let refusals = Refusals::default();
    count_refusal(&refusals, &GatewayError::Identity);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let counts = log_summary(&refusals);
    drop(guard);
    assert_eq!(counts.invalid_identity, 1);
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(logs.contains("invalid_identity: 1"));
    assert!(logs.contains("refused batches since the start"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_summary_task_logs_every_period_until_dropped() -> TestResult {
    let refusals = Arc::new(Refusals::default());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let task = spawn_summary(Arc::clone(&refusals), Duration::from_millis(SUMMARY_PERIOD_MS));
    sleep(Duration::from_millis(SUMMARY_PERIOD_MS * TWO as u64 + 1)).await;
    drop(task);
    sleep(Duration::from_millis(SUMMARY_PERIOD_MS * TWO as u64)).await;
    drop(guard);
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert_eq!(logs.matches("refused batches since the start").count(), TWO);
    Ok(())
}

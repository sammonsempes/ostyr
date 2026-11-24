mod nats_stub;
#[path = "common/private.rs"]
mod private;


use async_nats::jetstream;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued, Stub, StubState};
use nkeys::KeyPair;
use private::write_private;
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use siem_ingest::error::{class_of, handshake_class, rustls_in, without_peer_text, NatsError, PeerFailure, TlsClass};
use siem_ingest::model::{AckAction, Link, Wiring};
use siem_ingest::nats::release_held;
use siem_ingest::nats::{
    acknowledge, check_payload_limit, connect_options, fetch_batch, nats_wiring, progress_in, publish_dead_letter, read_bounded, report_progress,
    settle_token, terminate, tls_config, MAX_NATS_FILE_BYTES,
};
use siem_ingest::settings::{open_settings, IngestSettings};
use socket2::{Domain, Socket, Type};
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::runtime::Builder;


const PAIR: usize = 2;


const POLLS: usize = 2000;


const POLL_MS: u64 = 10;


const NORMAL_MS: u64 = 50_000;


const SHORT_MS: u64 = 200;


const PATIENT_FETCH_MS: u64 = 5_000;


const PING_MS: u64 = 1000;


const FETCH_MAX: usize = 10;


const TOKEN_ONE: u64 = 1;


const TOKEN_TWO: u64 = 2;


const UNKNOWN_TOKEN: u64 = 99;


const MANY_HEADERS: usize = 20;


const BATCH_BYTES: u64 = 4_194_304;


const WRONG_ACK_WAIT_NANOS: u64 = 1_000_000_000;


const HUGE_PAYLOAD: usize = 8_388_608;


const SETTINGS_FILE: &str = "ingest.yaml";


const HOST: &str = "localhost";


const GARBAGE_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";


const NO_CERTIFICATE_PEM: &[u8] = b"not a certificate at all";


pub struct Rig {
    pub dir: TempDir,
    pub stub: Stub,
    pub engine: Arc<ReloadEngine<IngestSettings>>,
    pub path: PathBuf,
    pub link: Arc<Link>,
}


fn yaml(port: u16, request_ms: u64, extra: &str) -> String {
    format!("nats_url: \"nats://127.0.0.1:{port}\"\nnats_fetch_deadline_ms: {SHORT_MS}\nnats_request_timeout_ms: {request_ms}\nnats_ping_interval_ms: {PING_MS}\n{extra}")
}


fn engine_for(dir: &TempDir, text: &str) -> Result<Arc<ReloadEngine<IngestSettings>>, Box<dyn Error + Send + Sync>> {
    let path = dir.path().join(SETTINGS_FILE);
    fs::write(&path, text)?;
    let log = genesis_log(io::sink());
    let engine = open_settings(
        path.clone(),
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
    )?;
    Ok(Arc::new(engine))
}


fn link_for(engine: &Arc<ReloadEngine<IngestSettings>>) -> Result<Arc<Link>, Box<dyn Error + Send + Sync>> {
    Ok(Arc::new(Link {
        runtime: Builder::new_multi_thread().worker_threads(1).enable_all().build()?,
        settings: Arc::clone(engine),
        session: Mutex::new(None),
        next_token: AtomicU64::new(1),
        refused_field: Mutex::new(None),
    }))
}


fn rig(request_ms: u64, extra: &str, configure: impl FnOnce(&mut StubState)) -> Result<Rig, Box<dyn Error + Send + Sync>> {
    let stub = start_stub(None, configure)?;
    let dir = tempdir()?;
    let engine = engine_for(&dir, &yaml(stub.port, request_ms, extra))?;
    let path = dir.path().join(SETTINGS_FILE);
    let link = link_for(&engine)?;
    Ok(Rig {
        dir,
        stub,
        engine,
        path,
        link,
    })
}


fn queued(subject: &str, payload: &str) -> Queued {
    Queued {
        subject: subject.to_owned(),
        payload: payload.as_bytes().to_vec(),
        extra_headers: 0,
        repeated_values: 0,
        message_ids: Vec::new(),
    }
}


fn dropped(link: &Link) -> bool {
    link.session
        .lock()
        .map(|slot| {
            slot.as_ref()
                .is_some_and(|session| session.dropped.load(std::sync::atomic::Ordering::SeqCst))
        })
        .unwrap_or(true)
}


fn is_empty_slot(link: &Link) -> bool {
    link.session.lock().map(|slot| slot.is_none()).unwrap_or(false)
}


fn eventually(check: impl Fn() -> bool) -> Result<(), Box<dyn Error + Send + Sync>> {
    if (0..POLLS).any(|_| {
        check() || {
            sleep(Duration::from_millis(POLL_MS));
            false
        }
    }) {
        Ok(())
    } else {
        Err("the condition was not reached".into())
    }
}


#[test]
fn a_batch_is_fetched_acknowledged_and_dead_lettered() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| {
        state.queue.push_back(queued("events.tenant-a", "one"));
        state.queue.push_back(queued("events.tenant-b", "two"));
    })?;
    let Wiring {
        mut fetch, ack, dead_letter, ..
    } = nats_wiring(Arc::clone(&rig.engine))?;
    let deliveries = fetch(FETCH_MAX)?;
    assert_eq!(deliveries.len(), PAIR);
    let first = deliveries.first().ok_or("no first delivery")?;
    let second = deliveries.get(1).ok_or("no second delivery")?;
    assert_eq!(
        (first.subject.as_str(), first.payload.as_slice(), first.token),
        ("events.tenant-a", b"one".as_slice(), TOKEN_ONE)
    );
    assert_eq!(
        (second.subject.as_str(), second.payload.as_slice(), second.token),
        ("events.tenant-b", b"two".as_slice(), TOKEN_TWO)
    );
    ack(TOKEN_ONE, AckAction::Ack)?;
    ack(TOKEN_TWO, AckAction::Nak)?;
    wait_until(&rig.stub, |state| state.acks.len() == PAIR)?;
    dead_letter("tenant-a", b"bad", "unparsable at line 1")?;
    assert!(fetch(FETCH_MAX)?.is_empty());
    let state = lock(&rig.stub.hub);
    assert_eq!(state.acks, ["+ACK", "-NAK"]);
    assert_eq!(state.connections, 1);
    let published = state.published.first().ok_or("no dead letter")?;
    assert_eq!(published.payload, b"bad");
    assert!(published.headers.contains("Ostyr-Tenant: tenant-a"));
    assert!(published.headers.contains("Ostyr-Reason: unparsable at line 1"));
    assert_eq!(state.infos, ["JS.EVENTS.API.CONSUMER.INFO.events.siem-ingest"]);
    let pull = state.pulls.first().ok_or("no pull")?;
    assert_eq!(pull.get("batch").and_then(|value| value.as_u64()), Some(FETCH_MAX as u64));
    assert_eq!(pull.get("max_bytes").and_then(|value| value.as_u64()), Some(BATCH_BYTES));
    assert!(rig.dir.path().exists());
    Ok(())
}


#[test]
fn acknowledgements_need_a_session_and_a_known_token() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    let Wiring {
        mut fetch, ack, dead_letter, ..
    } = nats_wiring(Arc::clone(&rig.engine))?;
    assert!(ack(TOKEN_ONE, AckAction::Ack).is_err());
    assert!(dead_letter("tenant-a", b"bad", "reason").is_err());
    assert_eq!(fetch(FETCH_MAX)?.len(), 1);
    let refusal = ack(UNKNOWN_TOKEN, AckAction::Ack).err().ok_or("an unknown token was accepted")?;
    assert_eq!(refusal.to_string(), "the acknowledgement token is unknown to the NATS session");
    assert!(lock(&rig.stub.hub).acks.is_empty());
    Ok(())
}


#[test]
fn a_refused_or_unconfirmed_dead_letter_is_an_error() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    lock(&rig.stub.hub).fail_publish = true;
    assert!(publish_dead_letter(&rig.link, "tenant-a", b"bad", "reason").is_err());
    {
        let mut state = lock(&rig.stub.hub);
        state.fail_publish = false;
        state.silent_publish = true;
    }
    fs::write(&rig.path, yaml(rig.stub.port, SHORT_MS, ""))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    let timeout = publish_dead_letter(&rig.link, "tenant-a", b"bad", "reason")
        .err()
        .ok_or("an unconfirmed publish passed")?;
    assert_eq!(timeout.to_string(), "the NATS server did not answer before the deadline");
    Ok(())
}


#[test]
fn a_silent_server_fails_the_fetch_and_the_next_one_reconnects() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(SHORT_MS, "", |_| {})?;
    eventually(|| fetch_batch(&rig.link, FETCH_MAX).is_ok())?;
    lock(&rig.stub.hub).silent_pull = true;
    let failure = fetch_batch(&rig.link, FETCH_MAX).err().ok_or("a silent server was not reported")?;
    assert_eq!(failure.to_string(), "the NATS server did not answer before the deadline");
    assert!(is_empty_slot(&rig.link));
    {
        let mut state = lock(&rig.stub.hub);
        state.silent_pull = false;
        state.queue.push_back(queued("events.tenant-a", "one"));
    }
    eventually(|| fetch_batch(&rig.link, FETCH_MAX).is_ok_and(|batch| batch.len() == 1))?;
    assert!(lock(&rig.stub.hub).infos.len() >= PAIR);
    Ok(())
}


#[test]
fn a_lost_connection_rebuilds_the_session_from_the_current_settings() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    kill_connections(&rig.stub);
    eventually(|| dropped(&rig.link))?;
    fs::write(&rig.path, yaml(rig.stub.port, NORMAL_MS, "nats_stream: other\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    lock(&rig.stub.hub).queue.push_back(queued("events.tenant-a", "two"));
    let deliveries = fetch_batch(&rig.link, FETCH_MAX)?;
    assert_eq!(deliveries.len(), 1);
    let state = lock(&rig.stub.hub);
    assert_eq!(
        state.infos.last().map(String::as_str),
        Some("JS.EVENTS.API.CONSUMER.INFO.other.siem-ingest")
    );
    assert_eq!(state.infos.len(), PAIR);
    Ok(())
}


#[test]
fn a_pull_error_status_is_reported() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.pull_status = Some("409 Exceeded MaxRequestBatch".to_owned()))?;
    assert!(fetch_batch(&rig.link, FETCH_MAX).is_err());
    assert!(is_empty_slot(&rig.link));
    Ok(())
}


#[test]
fn a_refused_consumer_is_reported() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.fail_info = true)?;
    assert!(fetch_batch(&rig.link, FETCH_MAX).is_err());
    Ok(())
}


#[test]
fn a_durable_that_is_not_the_pre_created_one_is_refused_by_field() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wrong = [
        ("ack_policy", json!({"ack_policy": "none"})),
        ("filter_subject", json!({"filter_subject": "events.a"})),
        ("filter_subject", json!({"filter_subject": "events.>", "filter_subjects": ["events.b"]})),
        ("ack_wait", json!({"ack_wait": WRONG_ACK_WAIT_NANOS})),
    ];
    wrong
        .into_iter()
        .try_for_each(|(field, patch)| -> Result<(), Box<dyn Error + Send + Sync>> {
            let rig = rig(NORMAL_MS, "", |state| state.config_patch = Some(patch))?;
            let failure = fetch_batch(&rig.link, FETCH_MAX).err().ok_or("a wrong durable was accepted")?;
            assert!(failure.to_string().contains(&format!("`{field}` differs")), "{failure}");
            Ok(())
        })
}


#[test]
fn a_server_payload_limit_above_the_batch_cap_is_refused() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.max_payload = HUGE_PAYLOAD)?;
    let failure = fetch_batch(&rig.link, FETCH_MAX)
        .err()
        .ok_or("a payload limit above the batch cap was accepted")?;
    assert!(failure.to_string().contains("accepts payloads of 8388608 bytes"));
    assert!(check_payload_limit(1, 1).is_ok());
    assert!(lock(&rig.stub.hub).infos.is_empty());
    Ok(())
}


#[test]
fn a_message_with_too_many_headers_is_terminated_not_delivered() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| {
        state.queue.push_back(Queued {
            subject: "events.tenant-a".to_owned(),
            payload: b"crowded".to_vec(),
            extra_headers: MANY_HEADERS,
            repeated_values: 0,
            message_ids: Vec::new(),
        });
        state.queue.push_back(queued("events.tenant-a", "fine"));
    })?;
    let deliveries = fetch_batch(&rig.link, FETCH_MAX)?;
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries.first().map(|delivery| delivery.payload.clone()), Some(b"fine".to_vec()));
    wait_until(&rig.stub, |state| !state.acks.is_empty())?;
    assert_eq!(lock(&rig.stub.hub).acks, ["+TERM"]);
    Ok(())
}


/// A bound, never listening socket: connections to it are refused and its port stays taken while it lives.
fn closed_socket() -> Result<(Socket, u16), Box<dyn Error + Send + Sync>> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = socket.local_addr()?.as_socket().ok_or("not an inet address")?.port();
    Ok((socket, port))
}


#[test]
fn a_down_server_fails_the_fetch() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (closed, port) = closed_socket()?;
    let dir = tempdir()?;
    let engine = engine_for(&dir, &yaml(port, SHORT_MS, ""))?;
    let link = link_for(&engine)?;
    assert!(fetch_batch(&link, FETCH_MAX).is_err());
    assert!(acknowledge(&link, TOKEN_ONE, AckAction::Ack).is_err());
    drop(closed);
    Ok(())
}


#[test]
fn a_failing_acknowledgement_or_termination_is_an_error_and_a_log() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    let crafted = {
        let slot = rig.link.session.lock().map_err(|_| "poisoned")?;
        let session = slot.as_ref().ok_or("no session")?;
        jetstream::Message {
            message: async_nats::Message {
                subject: "events.tenant-a".into(),
                reply: Some("bad reply subject".into()),
                payload: "x".into(),
                headers: None,
                status: None,
                description: None,
                length: 1,
            },
            context: session.jetstream.clone(),
        }
    };
    let settings = siem_ingest::settings::IngestSettings::default();
    rig.link.runtime.block_on(terminate(&crafted, &settings));
    {
        let mut slot = rig.link.session.lock().map_err(|_| "poisoned")?;
        slot.as_mut().ok_or("no session")?.held.insert(UNKNOWN_TOKEN, crafted);
    }
    let failure = acknowledge(&rig.link, UNKNOWN_TOKEN, AckAction::Ack)
        .err()
        .ok_or("a bad reply subject was accepted")?;
    assert_eq!(failure.to_string(), "the NATS server request failed");
    let mut empty_slot = None;
    let missing = rig
        .link
        .runtime
        .block_on(settle_token(&mut empty_slot, &settings, TOKEN_ONE, AckAction::Nak));
    assert!(matches!(missing, Err(NatsError::NotConnected)));
    Ok(())
}


fn credentials_text() -> Result<String, Box<dyn Error + Send + Sync>> {
    let pair = KeyPair::new_user();
    Ok(format!(
        "-----BEGIN NATS USER JWT-----\nstub.jwt.token\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------\n",
        pair.seed()?
    ))
}


fn tls_material() -> Result<(Arc<ServerConfig>, String), Box<dyn Error + Send + Sync>> {
    let generated = generate_simple_self_signed(vec![HOST.to_owned()])?;
    let certificate_pem = generated.cert.pem();
    let certificates = CertificateDer::pem_slice_iter(certificate_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(generated.signing_key.serialize_pem().as_bytes())?;
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    Ok((Arc::new(config), certificate_pem))
}


#[test]
fn a_tls_first_connection_with_a_ca_file_and_credentials_works() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (server_config, ca_pem) = tls_material()?;
    let stub = start_stub(Some(server_config), |state| {
        state.nonce = true;
        state.queue.push_back(queued("events.tenant-a", "one"));
    })?;
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    let credentials_path = dir.path().join("nats.creds");
    fs::write(&ca_path, ca_pem)?;
    write_private(&credentials_path, credentials_text()?)?;
    let extra = format!(
        "nats_tls_first: true\nnats_ca_file: \"{}\"\nnats_credentials_file: \"{}\"\n",
        ca_path.display(),
        credentials_path.display()
    );
    let text = yaml(stub.port, NORMAL_MS, &extra).replace("127.0.0.1", HOST);
    let engine = engine_for(&dir, &text)?;
    let link = link_for(&engine)?;
    assert_eq!(fetch_batch(&link, FETCH_MAX)?.len(), 1);
    let state = lock(&stub.hub);
    let connect = state.connects.first().ok_or("no CONNECT")?;
    assert_eq!(connect.get("jwt").and_then(|value| value.as_str()), Some("stub.jwt.token"));
    assert!(connect
        .get("sig")
        .and_then(|value| value.as_str())
        .is_some_and(|signature| !signature.is_empty()));
    Ok(())
}


#[test]
fn files_are_read_bounded_and_refused_when_unusable() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let big = dir.path().join("big");
    fs::write(&big, vec![b'a'; MAX_NATS_FILE_BYTES as usize + 1])?;
    assert!(matches!(
        read_bounded(&big, "CA", MAX_NATS_FILE_BYTES),
        Err(NatsError::FileTooLarge { what: "CA" })
    ));
    assert!(matches!(
        read_bounded(&dir.path().join("missing"), "CA", MAX_NATS_FILE_BYTES),
        Err(NatsError::File { what: "CA", .. })
    ));
    assert!(matches!(
        read_bounded(dir.path(), "CA", MAX_NATS_FILE_BYTES),
        Err(NatsError::File { what: "CA", .. })
    ));
    assert_eq!(read_bounded(&big, "CA", MAX_NATS_FILE_BYTES + 1)?.len(), MAX_NATS_FILE_BYTES as usize + 1);
    assert!(matches!(tls_config(NO_CERTIFICATE_PEM), Err(NatsError::CaEmpty)));
    assert!(matches!(tls_config(GARBAGE_PEM), Err(NatsError::CaInvalid(_))));
    Ok(())
}


#[test]
fn connect_options_refuse_bad_ca_and_credentials_files() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let junk = dir.path().join("junk");
    write_private(&junk, "junk")?;
    let dropped_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let with_ca = IngestSettings {
        nats_ca_file: Some(junk.clone()),
        ..IngestSettings::default()
    };
    assert!(matches!(connect_options(&with_ca, Arc::clone(&dropped_flag)), Err(NatsError::CaEmpty)));
    let with_credentials = IngestSettings {
        nats_credentials_file: Some(junk),
        ..IngestSettings::default()
    };
    let failure = connect_options(&with_credentials, Arc::clone(&dropped_flag))
        .err()
        .ok_or("junk credentials were accepted")?;
    assert!(matches!(failure, NatsError::Credentials(_)));
    assert_eq!(failure.to_string(), "the NATS credentials file is not valid");
    let no_password = IngestSettings {
        nats_user: Some("ops".to_owned()),
        nats_password_file: Some(dir.path().join("missing")),
        ..IngestSettings::default()
    };
    assert!(matches!(
        connect_options(&no_password, Arc::clone(&dropped_flag)),
        Err(NatsError::File { what: "password", .. })
    ));
    let missing = IngestSettings {
        nats_credentials_file: Some(dir.path().join("missing")),
        ..IngestSettings::default()
    };
    assert!(matches!(
        connect_options(&missing, dropped_flag),
        Err(NatsError::File { what: "credentials", .. })
    ));
    Ok(())
}


#[test]
fn a_user_and_a_password_file_authenticate_the_connection() -> Result<(), Box<dyn Error + Send + Sync>> {
    let stub = start_stub(None, |state| {
        state.nonce = true;
        state.queue.push_back(queued("events.tenant-a", "one"));
    })?;
    let dir = tempdir()?;
    let password_path = dir.path().join("nats.password");
    write_private(&password_path, "s3cret\n")?;
    let extra = format!("nats_user: ops\nnats_password_file: \"{}\"\n", password_path.display());
    let engine = engine_for(&dir, &yaml(stub.port, NORMAL_MS, &extra))?;
    let link = link_for(&engine)?;
    assert_eq!(fetch_batch(&link, FETCH_MAX)?.len(), 1);
    let state = lock(&stub.hub);
    let connect = state.connects.first().ok_or("no CONNECT")?;
    assert_eq!(connect.get("user").and_then(|value| value.as_str()), Some("ops"));
    assert_eq!(connect.get("pass").and_then(|value| value.as_str()), Some("s3cret"));
    assert!(!state.subscribed.is_empty());
    assert!(state.subscribed.iter().all(|subject| subject.starts_with("_INBOX_ops.")));
    Ok(())
}


#[test]
fn a_connection_without_a_user_keeps_the_default_inbox() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    let state = lock(&rig.stub.hub);
    assert!(!state.subscribed.is_empty());
    assert!(state.subscribed.iter().all(|subject| subject.starts_with("_INBOX.")));
    Ok(())
}


#[test]
fn repeated_values_of_one_header_name_count_against_the_cap() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| {
        state.queue.push_back(Queued {
            subject: "events.tenant-a".to_owned(),
            payload: b"crowded".to_vec(),
            extra_headers: 0,
            repeated_values: MANY_HEADERS,
            message_ids: Vec::new(),
        });
    })?;
    assert!(fetch_batch(&rig.link, FETCH_MAX)?.is_empty());
    wait_until(&rig.stub, |state| !state.acks.is_empty())?;
    assert_eq!(lock(&rig.stub.hub).acks, ["+TERM"]);
    Ok(())
}


#[test]
fn a_token_of_a_dropped_session_never_settles_a_later_message() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "old")))?;
    let first = fetch_batch(&rig.link, FETCH_MAX)?;
    let old_token = first.first().ok_or("no first delivery")?.token;
    kill_connections(&rig.stub);
    eventually(|| dropped(&rig.link))?;
    lock(&rig.stub.hub).queue.push_back(queued("events.tenant-b", "new"));
    let second = fetch_batch(&rig.link, FETCH_MAX)?;
    let new_token = second.first().ok_or("no second delivery")?.token;
    assert_ne!(old_token, new_token);
    assert!(acknowledge(&rig.link, old_token, AckAction::Ack).is_err());
    assert!(acknowledge(&rig.link, new_token, AckAction::Ack).is_ok());
    Ok(())
}


#[test]
fn a_reload_of_the_connection_settings_replaces_the_session_and_releases_what_it_held() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "old")))?;
    let first = fetch_batch(&rig.link, FETCH_MAX)?;
    let old_token = first.first().ok_or("no first delivery")?.token;
    fs::write(&rig.path, yaml(rig.stub.port, NORMAL_MS, "nats_consumer: other\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    lock(&rig.stub.hub).queue.push_back(queued("events.tenant-b", "new"));
    let second = fetch_batch(&rig.link, FETCH_MAX)?;
    let new_token = second.first().ok_or("no second delivery")?.token;
    assert_ne!(old_token, new_token);
    wait_until(&rig.stub, |state| state.acks.iter().any(|ack| ack.starts_with("-NAK")))?;
    let state = lock(&rig.stub.hub);
    assert_eq!(state.connections, PAIR);
    assert_eq!(state.infos.len(), PAIR);
    assert_eq!(state.infos.last().map(String::as_str), Some("JS.EVENTS.API.CONSUMER.INFO.events.other"));
    drop(state);
    assert!(acknowledge(&rig.link, old_token, AckAction::Ack).is_err());
    assert!(acknowledge(&rig.link, new_token, AckAction::Ack).is_ok());
    Ok(())
}


#[test]
fn a_reload_that_leaves_the_connection_settings_keeps_the_session() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    fs::write(&rig.path, yaml(rig.stub.port, NORMAL_MS, "nats_max_headers: 3\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    assert!(fetch_batch(&rig.link, FETCH_MAX)?.is_empty());
    let state = lock(&rig.stub.hub);
    assert_eq!(state.connections, 1);
    assert_eq!(state.infos.len(), 1);
    Ok(())
}


#[test]
fn releasing_a_session_logs_a_failing_nak_and_skips_a_dropped_one() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    let patient = yaml(rig.stub.port, NORMAL_MS, "").replace(
        &format!("nats_fetch_deadline_ms: {SHORT_MS}"),
        &format!("nats_fetch_deadline_ms: {PATIENT_FETCH_MS}"),
    );
    fs::write(&rig.path, patient)?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(fetch_batch(&rig.link, 1)?.len(), 1);
    let mut session = rig.link.session.lock().map_err(|_| "poisoned")?.take().ok_or("no session")?;
    let real = session.held.remove(&TOKEN_ONE).ok_or("no held message")?;
    session.held.insert(
        TOKEN_TWO,
        jetstream::Message {
            message: async_nats::Message {
                subject: "events.tenant-a".into(),
                reply: Some("bad reply subject".into()),
                payload: "x".into(),
                headers: None,
                status: None,
                description: None,
                length: 1,
            },
            context: session.jetstream.clone(),
        },
    );
    rig.link.runtime.block_on(release_held(session));
    assert!(lock(&rig.stub.hub).acks.is_empty());
    drop(real);
    Ok(())
}


#[derive(Clone)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn trace_capture() -> Result<Arc<Mutex<Vec<u8>>>, Box<dyn Error + Send + Sync>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    Ok(captured)
}


const TRACE_PASSWORD: &str = "TRACEPW-9f3a7c1d";


const TRACE_JWT: &str = "TRACEJWT.9f3a7c1d.payload";


const TRACE_PAYLOAD: &str = "TRACEPAYLOAD-5e2b8d40";


#[test]
fn a_trace_subscriber_never_sees_the_nats_password() -> Result<(), Box<dyn Error + Send + Sync>> {
    let captured = trace_capture()?;
    let stub = start_stub(None, |state| {
        state.nonce = true;
        state.queue.push_back(queued("events.tenant-a", TRACE_PAYLOAD));
    })?;
    let dir = tempdir()?;
    let password_path = dir.path().join("nats.password");
    write_private(&password_path, format!("{TRACE_PASSWORD}\n"))?;
    let extra = format!("nats_user: ops\nnats_password_file: \"{}\"\n", password_path.display());
    let engine = engine_for(&dir, &yaml(stub.port, NORMAL_MS, &extra))?;
    let link = link_for(&engine)?;
    assert_eq!(fetch_batch(&link, FETCH_MAX)?.len(), 1);
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(!logs.is_empty());
    assert!(!logs.contains(TRACE_PASSWORD));
    let credentials_stub = start_stub(None, |state| {
        state.nonce = true;
        state.queue.push_back(queued("events.tenant-a", TRACE_PAYLOAD));
    })?;
    let pair = KeyPair::new_user();
    let seed = pair.seed()?;
    let credentials_path = dir.path().join("nats.creds");
    write_private(
        &credentials_path,
        format!(
            "-----BEGIN NATS USER JWT-----\n{TRACE_JWT}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"
        ),
    )?;
    let credentials_extra = format!("nats_credentials_file: \"{}\"\n", credentials_path.display());
    let credentials_engine = engine_for(&dir, &yaml(credentials_stub.port, NORMAL_MS, &credentials_extra))?;
    let credentials_link = link_for(&credentials_engine)?;
    assert_eq!(fetch_batch(&credentials_link, FETCH_MAX)?.len(), 1);
    let signed = lock(&credentials_stub.hub);
    let connect = signed.connects.first().ok_or("no CONNECT")?;
    assert_eq!(connect.get("jwt").and_then(|value| value.as_str()), Some(TRACE_JWT));
    let all_logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(!all_logs.contains(TRACE_JWT));
    assert!(!all_logs.contains(&seed));
    assert!(!all_logs.contains(TRACE_PASSWORD));
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(!all_logs.contains(TRACE_PAYLOAD));
    assert!(tracing::level_filters::STATIC_MAX_LEVEL <= tracing::level_filters::LevelFilter::DEBUG);
    Ok(())
}


#[test]
fn an_in_progress_acknowledgement_covers_every_held_message_and_keeps_them_held() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| {
        state.queue.push_back(queued("events.tenant-a", "one"));
        state.queue.push_back(queued("events.tenant-a", "two"));
    })?;
    assert!(report_progress(&rig.link).is_err());
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), PAIR);
    report_progress(&rig.link)?;
    wait_until(&rig.stub, |state| state.acks.len() == PAIR)?;
    assert_eq!(lock(&rig.stub.hub).acks, ["+WPI", "+WPI"]);
    acknowledge(&rig.link, TOKEN_ONE, AckAction::Ack)?;
    wait_until(&rig.stub, |state| state.acks.len() == PAIR + 1)?;
    let settings = current_config(&rig.engine);
    let slot = rig.link.session.lock().map_err(|_| "poisoned")?;
    assert_eq!(rig.link.runtime.block_on(progress_in(&slot, &settings))?, 1);
    Ok(())
}


#[cfg(unix)]
const LAX_MODE: u32 = 0o644;


#[cfg(unix)]
#[test]
fn lax_symlinked_or_fifo_nats_secret_files_are_refused_before_any_connect() -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempdir()?;
    let lax = dir.path().join("lax");
    fs::write(&lax, "nats-lax-644")?;
    fs::set_permissions(&lax, fs::Permissions::from_mode(LAX_MODE))?;
    let private_file = dir.path().join("private");
    write_private(&private_file, "other-service-secret")?;
    let link = dir.path().join("link");
    symlink(&private_file, &link)?;
    let fifo = dir.path().join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
    let dropped_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for path in [&lax, &link, &fifo] {
        let password = IngestSettings {
            nats_user: Some("ops".to_owned()),
            nats_password_file: Some(path.clone()),
            ..IngestSettings::default()
        };
        let refused = connect_options(&password, Arc::clone(&dropped_flag)).err().ok_or("password accepted")?;
        assert!(matches!(refused, NatsError::SecretFile { what: "password", .. }));
        let shown = format!("{refused} {:?}", Error::source(&refused));
        assert!(shown.contains(&path.display().to_string()));
        assert!(!shown.contains("nats-lax-644") && !shown.contains("other-service-secret"));
        let credentials = IngestSettings {
            nats_credentials_file: Some(path.clone()),
            ..IngestSettings::default()
        };
        let refused_credentials = connect_options(&credentials, Arc::clone(&dropped_flag))
            .err()
            .ok_or("credentials accepted")?;
        assert!(matches!(refused_credentials, NatsError::SecretFile { what: "credentials", .. }));
    }
    Ok(())
}


const MARKER: &str = "peer-san-marker";


const ESCAPE: char = '\u{1b}';


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn hostile_material() -> Result<(Arc<ServerConfig>, String), Box<dyn Error + Send + Sync>> {
    let generated = generate_simple_self_signed(vec![format!("{MARKER}{ESCAPE}.example")])?;
    let certificate_pem = generated.cert.pem();
    let certificates = CertificateDer::pem_slice_iter(certificate_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(generated.signing_key.serialize_pem().as_bytes())?;
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    Ok((Arc::new(config), certificate_pem))
}


#[test]
fn a_hostile_certificate_name_never_reaches_the_connect_error() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (server_config, ca_pem) = hostile_material()?;
    let stub = start_stub(Some(server_config), |_state| {})?;
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    fs::write(&ca_path, &ca_pem)?;
    let extra = format!("nats_tls_first: true\nnats_ca_file: \"{}\"\n", ca_path.display());
    let text = yaml(stub.port, NORMAL_MS, &extra).replace("127.0.0.1", HOST);
    let control = Builder::new_current_thread().enable_all().build()?.block_on(
        async_nats::ConnectOptions::new()
            .tls_first()
            .tls_client_config(tls_config(ca_pem.as_bytes())?)
            .connect(format!("nats://{HOST}:{}", stub.port)),
    );
    let raw = control.err().ok_or("connected")?;
    assert!(
        chain(&raw).contains(MARKER),
        "the control: async-nats itself carries the peer text: {}",
        chain(&raw)
    );
    let engine = engine_for(&dir, &text)?;
    let link = link_for(&engine)?;
    let error = fetch_batch(&link, FETCH_MAX).err().ok_or("fetched")?;
    let shown = chain(error.as_ref());
    assert!(!shown.contains(MARKER) && !shown.contains(ESCAPE) && !shown.contains("u{1b}"), "{shown}");
    assert!(matches!(error.downcast_ref::<NatsError>(), Some(NatsError::Request(_))), "{shown}");
    Ok(())
}


#[test]
fn rustls_errors_are_classed_without_their_text() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_eq!(
        class_of(&rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        TlsClass::Certificate
    );
    assert_eq!(class_of(&rustls::Error::NoCertificatesPresented), TlsClass::Certificate);
    assert_eq!(
        class_of(&rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)),
        TlsClass::Alert
    );
    assert_eq!(class_of(&rustls::Error::HandshakeNotComplete), TlsClass::Protocol);
    assert!(rustls_in(&rustls::Error::HandshakeNotComplete).is_some());
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::NoCertificatesPresented);
    assert_eq!(handshake_class(&wrapped), Some(TlsClass::Certificate));
    assert_eq!(handshake_class(&io::Error::from(io::ErrorKind::BrokenPipe)), None);
    assert_eq!(handshake_class(&io::Error::new(io::ErrorKind::BrokenPipe, "text")), None);
    let fixed = without_peer_text(Box::new(wrapped));
    assert_eq!(fixed.to_string(), format!("the TLS exchange failed: {}", TlsClass::Certificate));
    assert!(fixed.source().is_none());
    let kept = without_peer_text(Box::new(io::Error::new(io::ErrorKind::BrokenPipe, "peer text")));
    assert_eq!(kept.downcast_ref::<PeerFailure>(), Some(&PeerFailure::Io(io::ErrorKind::BrokenPipe)));
    assert!(!format!("{kept} {kept:?}").contains("peer text") && kept.source().is_none());
    let other = without_peer_text(Box::new(std::fmt::Error));
    assert_eq!(other.downcast_ref::<PeerFailure>(), Some(&PeerFailure::Other));
    assert!(!TlsClass::Alert.to_string().is_empty() && !TlsClass::Protocol.to_string().is_empty());
    Ok(())
}


const WIDE_DIRECTIVES: &str = "trace,async_nats=trace,async_nats::connector=trace";


static ANCHOR: std::sync::LazyLock<tracing::Dispatch> =
    std::sync::LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


fn connect_logs(dispatch: &tracing::Dispatch, captured: &Arc<Mutex<Vec<u8>>>) -> Result<String, Box<dyn Error + Send + Sync>> {
    let (server_config, ca_pem) = hostile_material()?;
    let stub = start_stub(Some(server_config), |_state| {})?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let client_config = tls_config(ca_pem.as_bytes())?;
    let outcome = tracing::dispatcher::with_default(dispatch, || {
        runtime
            .block_on(
                async_nats::ConnectOptions::new()
                    .tls_first()
                    .tls_client_config(client_config)
                    .connect(format!("nats://localhost:{}", stub.port)),
            )
            .err()
            .ok_or("connected")
            .map(|_| ())
            .map_err(Box::<dyn Error + Send + Sync>::from)
    });
    outcome?;
    let bytes = captured.lock().map_err(|error| error.to_string())?.clone();
    Ok(String::from_utf8(bytes)?)
}


#[test]
fn the_production_filter_keeps_peer_certificate_names_out_of_the_async_nats_log() -> Result<(), Box<dyn Error + Send + Sync>> {
    std::sync::LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = siem_ingest::logging::build_subscriber(move || writer.clone(), Some(WIDE_DIRECTIVES))?;
    let logs = connect_logs(&tracing::Dispatch::new(subscriber), &captured)?;
    assert!(!logs.contains(MARKER) && !logs.contains(ESCAPE), "{logs}");
    Ok(())
}


#[test]
fn a_filter_without_the_cap_shows_the_marker() -> Result<(), Box<dyn Error + Send + Sync>> {
    std::sync::LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let uncapped = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let logs = connect_logs(&tracing::Dispatch::new(uncapped), &captured)?;
    assert!(logs.contains(MARKER), "the probe must see the library line: {logs}");
    Ok(())
}


#[test]
fn the_cap_holds_over_every_directive_and_other_targets_are_untouched() -> Result<(), Box<dyn Error + Send + Sync>> {
    let wide = tracing_subscriber::filter::Targets::from_str(WIDE_DIRECTIVES)?;
    assert!(!siem_ingest::logging::log_allowed(&wide, "async_nats::connector", &tracing::Level::DEBUG));
    assert!(!siem_ingest::logging::log_allowed(&wide, "async_nats", &tracing::Level::TRACE));
    assert!(!siem_ingest::logging::log_allowed(&wide, "async_nats::connector", &tracing::Level::ERROR));
    assert!(siem_ingest::logging::log_allowed(&wide, "siem_ingest::nats", &tracing::Level::TRACE));
    assert!(!siem_ingest::logging::log_allowed(
        &tracing_subscriber::filter::Targets::from_str("warn")?,
        "siem_ingest::nats",
        &tracing::Level::INFO
    ));
    assert!(
        siem_ingest::logging::is_capped_target("async_nats")
            && siem_ingest::logging::is_capped_target("async_nats::x")
            && !siem_ingest::logging::is_capped_target("async_natsx")
    );
    assert!(siem_ingest::logging::build_subscriber(io::sink, Some("=[")).is_err());
    std::sync::LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = siem_ingest::logging::build_subscriber(move || writer.clone(), None)?;
    tracing::subscriber::with_default(subscriber, || {
        tracing::debug!(target: "async_nats::connector", "hidden-line");
        tracing::info!(target: "async_nats::connector", "capped-info-line");
        tracing::debug!(target: "other::module", "shown-line");
    });
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(
        logs.contains("shown-line") && !logs.contains("capped-info-line") && !logs.contains("hidden-line"),
        "{logs}"
    );
    assert!(!logs.contains(ESCAPE), "{logs}");
    Ok(())
}


const PROBE_BYTES: usize = 2_000_000;


const LOG_BYTES_BOUND: usize = 4096;


fn probe(form: &str) -> Vec<u8> {
    let filler = if form == "-ERR" { "A" } else { "B" };
    format!(
        "{form} {}{MARKER}{ESCAPE}[31m{}\r\n",
        if form == "-ERR" { "'" } else { "" },
        filler.repeat(PROBE_BYTES)
    )
    .into_bytes()
}


fn speak_first(bytes: Vec<u8>, tls: Option<Arc<ServerConfig>>) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        match tls {
            Some(config) => {
                let connection = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
                let mut secured = rustls::StreamOwned::new(connection, stream);
                secured.write_all(&bytes)?;
                secured.flush()?;
                io::copy(&mut secured, &mut io::sink()).map(|_| ())
            }
            None => {
                let mut plain = stream;
                plain.write_all(&bytes)?;
                io::copy(&mut plain, &mut io::sink()).map(|_| ())
            }
        }
    });
    Ok(port)
}


fn hostile_attempt(port: u16, host: &str, extra: &str) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    std::sync::LazyLock::force(&ANCHOR);
    let dir = tempdir()?;
    let text = yaml(port, NORMAL_MS, extra).replace("127.0.0.1", host);
    let engine = engine_for(&dir, &text)?;
    let link = link_for(&engine)?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let dispatch = tracing::Dispatch::new(siem_ingest::logging::build_subscriber(move || writer.clone(), Some("trace"))?);
    let outcome = tracing::dispatcher::with_default(&dispatch, || fetch_batch(&link, FETCH_MAX));
    let error = outcome.err().ok_or("fetched")?;
    let logs = String::from_utf8(captured.lock().map_err(|poisoned| poisoned.to_string())?.clone())?;
    Ok((chain(error.as_ref()), logs))
}


fn assert_clean(shown: &str, logs: &str) {
    for text in [shown, logs] {
        assert!(
            !text.contains(MARKER) && !text.contains(ESCAPE) && !text.contains("u{1b}") && !text.contains("x1b"),
            "{text}"
        );
    }
    assert!(logs.len() < LOG_BYTES_BOUND, "{} log bytes", logs.len());
}


#[test]
fn a_server_that_speaks_before_tls_leaves_no_text_in_the_error_or_the_log() -> Result<(), Box<dyn Error + Send + Sync>> {
    for form in ["-ERR", "BOGUS"] {
        let control_port = speak_first(probe(form), None)?;
        let control = Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async_nats::ConnectOptions::new().connect(format!("nats://127.0.0.1:{control_port}")));
        let raw = control.err().ok_or("connected")?;
        assert!(chain(&raw).contains(MARKER), "the control: the raw library error carries the peer text");
        let port = speak_first(probe(form), None)?;
        let (shown, logs) = hostile_attempt(port, "127.0.0.1", "")?;
        assert_clean(&shown, &logs);
        assert!(shown.contains("the NATS server request failed"), "{shown}");
    }
    Ok(())
}


#[test]
fn a_server_error_after_a_good_handshake_leaves_no_text_in_the_error_or_the_log() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (server_config, ca_pem) = tls_material()?;
    let dir = tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    fs::write(&ca_path, &ca_pem)?;
    let extra = format!("nats_tls_first: true\nnats_ca_file: \"{}\"\n", ca_path.display());
    let port = speak_first(probe("-ERR"), Some(server_config))?;
    let (shown, logs) = hostile_attempt(port, HOST, &extra)?;
    assert_clean(&shown, &logs);
    Ok(())
}


#[test]
fn a_delivery_carries_every_message_id_and_the_stored_time() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| {
        state.queue.push_back(Queued {
            message_ids: vec!["a:b:1:0".to_owned(), "a:b:1:1".to_owned()],
            ..queued("events.tenant-a", "one")
        });
        state.queue.push_back(queued("events.tenant-a", "two"));
    })?;
    let deliveries = fetch_batch(&rig.link, FETCH_MAX)?;
    let first = deliveries.first().ok_or("no first delivery")?;
    let second = deliveries.get(1).ok_or("no second delivery")?;
    assert_eq!(first.message_ids, vec!["a:b:1:0".to_owned(), "a:b:1:1".to_owned()]);
    assert!(second.message_ids.is_empty());
    assert_eq!(first.stored_nanos, Some(nats_stub::STORED_NANOS));
    assert_eq!(second.stored_nanos, Some(nats_stub::STORED_NANOS));
    Ok(())
}


#[test]
fn a_reply_without_a_stored_time_gives_none() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rig = rig(NORMAL_MS, "", |state| state.queue.push_back(queued("events.tenant-a", "one")))?;
    assert_eq!(fetch_batch(&rig.link, FETCH_MAX)?.len(), 1);
    let slot = rig.link.session.lock().map_err(|_| "poisoned")?;
    let session = slot.as_ref().ok_or("no session")?;
    let crafted = |reply: &str| jetstream::Message {
        message: async_nats::Message {
            subject: "events.tenant-a".into(),
            reply: Some(reply.into()),
            payload: "x".into(),
            headers: None,
            status: None,
            description: None,
            length: 1,
        },
        context: session.jetstream.clone(),
    };
    assert_eq!(siem_ingest::nats::stored_nanos(&crafted("bad reply subject")), None);
    assert_eq!(siem_ingest::nats::stored_nanos(&crafted("$JS.ACK.events.d.1.1.1.0.0")), Some(0));
    assert!(siem_ingest::nats::message_ids(&crafted("x")).is_empty());
    Ok(())
}


#[test]
fn a_refused_durable_is_logged_by_field_once_until_a_fetch_works() -> Result<(), Box<dyn Error + Send + Sync>> {
    std::sync::LazyLock::force(&ANCHOR);
    let rig = rig(NORMAL_MS, "", |state| {
        state.config_patch = Some(json!({"ack_wait": WRONG_ACK_WAIT_NANOS}))
    })?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let dispatch = tracing::Dispatch::new(siem_ingest::logging::build_subscriber(move || writer.clone(), None)?);
    tracing::dispatcher::with_default(&dispatch, || {
        assert!(fetch_batch(&rig.link, FETCH_MAX).is_err());
        assert!(fetch_batch(&rig.link, FETCH_MAX).is_err());
    });
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    assert_eq!(logs.matches("pre-created durable is refused").count(), 1, "{logs}");
    assert!(logs.contains("ack_wait"), "{logs}");
    assert_eq!(*rig.link.refused_field.lock().map_err(|_| "poisoned")?, Some("ack_wait"));
    let worked: Result<Vec<_>, NatsError> = Ok(Vec::new());
    siem_ingest::nats::log_refusal(&rig.link, &worked);
    assert_eq!(*rig.link.refused_field.lock().map_err(|_| "poisoned")?, None);
    Ok(())
}


#[test]
fn a_fetch_window_that_reaches_the_response_threshold_is_refused_by_name() -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = tempdir()?;
    let last_accepted = siem_ingest::nats_settings::RESPONSE_THRESHOLD_MS - SHORT_MS - 1;
    assert!(engine_for(&dir, &yaml(1, last_accepted, "")).is_ok());
    let refused = engine_for(&dir, &yaml(1, last_accepted + 1, "")).err().ok_or("accepted")?;
    assert!(refused.to_string().contains("nats_fetch_deadline_ms"), "{refused}");
    Ok(())
}

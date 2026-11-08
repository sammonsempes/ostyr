use crate::harness::{bounded, make_platform, scoped_logging};
use crate::harness::{client_paths, server_paths};
use crate::pki::{agent_spec, write_file, AGENT_URI, PRIVATE_MODE, SERVER_NAME, WORLD_READABLE_MODE};
use crate::services::agent_verifier;
use crate::types::TestResult;
use agent_channel::agent_app::{
    batches_of, execute_fn, load_agent_file, read_spool, record_commands, run_agent, run_attempts, session_attempt, AgentFile, MAX_AGENT_ATTEMPTS,
};
use agent_channel::app::{alerting_audit, reload_context, shared_log_audit};
use agent_channel::commands::{agent_directory, command_source, paths_of, read_envelope, read_envelopes, MAX_COMMAND_FILES, MAX_ENVELOPE_FILE_BYTES};
use agent_channel::error::{AppError, ChannelError, SinkError};
use agent_channel::model::Identity;
use agent_channel::proto::EventBatch;
use agent_channel::server_app::{bind_server, load_server_file, run_server, ServerFile};
use agent_channel::sink::{file_sink, load_seen, open_event_store, parse_line, store_batch, EventStore};
use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
use agent_command::sign::{memory_signer, sign_command};
use core_audit::error::AuditError;
use core_audit::log::{genesis_log, no_sync, open_file_log};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};


const KEY_SEED: u8 = 9;


const SEED_LENGTH: usize = 32;


const KEY_ID: &str = "routine-1";


const LIFETIME: u64 = 600;


const KEY_LIFETIME: u64 = 86_400;


const TWICE: usize = 2;


const FIRST: u64 = 1;


const SECOND: u64 = 2;


const TWICE_COUNT: u64 = 2;


const SEVEN: u64 = 7;


const THIRD: usize = 3;


const FOURTH: usize = 4;


const FILLER: u8 = 0;


const AGENT_YAML: &str = "server: 127.0.0.1:1\nserver_name: x\ncertificate: c\nkey: k\nplatform_ca: p\ntenant: t\nagent_id: a\n\
keys_file: k\nstate_file: s\naudit_file: a\nspool_file: s\nexecuted_file: e\n";


const INVALID_UTF8: &[u8] = &[u8::MAX, u8::MAX - 1, b'\n'];


const OVERSIZE_EXTRA: usize = 1;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[derive(Default)]
struct FlakyWriter {
    failed: bool,
    written: Vec<u8>,
}


impl Write for FlakyWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.failed {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        } else {
            self.failed = true;
            Err(io::Error::other("injected"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Fixture {
    server: ServerFile,
    agent: AgentFile,
}


fn epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}


fn signed(sequence: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let command = Command {
        key_id: KEY_ID.to_owned(),
        key_class: KeyClass::Routine,
        agent_id: "agent-1".to_owned(),
        tenant: "acme".to_owned(),
        issued_at: epoch_seconds(),
        expires_at: epoch_seconds() + LIFETIME,
        sequence,
        nonce: [1; NONCE_LENGTH],
        action: Action::Ping,
    };
    let signer = memory_signer(SigningKey::from_bytes(&[KEY_SEED; SEED_LENGTH]));
    Ok(sign_command(&command, KEY_ID, signer.as_ref())?)
}


fn fixture(dir: &Path) -> Result<Fixture, Box<dyn std::error::Error>> {
    let platform = make_platform()?;
    let server_tls = server_paths(dir, &platform)?;
    let agent_tls = client_paths(dir, "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let public = HEXLOWER.encode(&SigningKey::from_bytes(&[KEY_SEED; SEED_LENGTH]).verifying_key().to_bytes());
    let keys = write_file(
        dir,
        "keys.yaml",
        &format!(
            "keys:\n  - id: {KEY_ID}\n    class: routine\n    public_key: {public}\n    not_before: {}\n    not_after: {}\n",
            epoch_seconds() - LIFETIME,
            epoch_seconds() + KEY_LIFETIME
        ),
        WORLD_READABLE_MODE,
    )?;
    let commands_dir = dir.join("commands");
    let agent_commands = commands_dir.join("acme:agent-1");
    fs::create_dir_all(&agent_commands)?;
    fs::write(agent_commands.join("1-valid"), signed(1)?)?;
    fs::write(agent_commands.join("2-junk"), b"junk")?;
    let spool = write_file(dir, "spool.txt", "{\"event\":1}\n{\"event\":2}\n", PRIVATE_MODE)?;
    Ok(Fixture {
        server: ServerFile {
            listen: "127.0.0.1:0".to_owned(),
            certificate: server_tls.certificate,
            key: server_tls.key,
            agent_ca: server_tls.agent_ca,
            revocation_file: write_file(dir, "revoked.yaml", "revoked_serials: []\n", WORLD_READABLE_MODE)?,
            settings_file: write_file(dir, "settings.yaml", "{}\n", WORLD_READABLE_MODE)?,
            audit_file: dir.join("server-audit.log"),
            events_file: dir.join("events.log"),
            commands_dir,
        },
        agent: AgentFile {
            server: "127.0.0.1:1".to_owned(),
            server_name: SERVER_NAME.to_owned(),
            certificate: agent_tls.certificate,
            key: agent_tls.key,
            platform_ca: agent_tls.platform_ca,
            tenant: "acme".to_owned(),
            agent_id: "agent-1".to_owned(),
            keys_file: keys,
            state_file: dir.join("agent-state.json"),
            audit_file: dir.join("agent-audit.log"),
            spool_file: spool,
            executed_file: dir.join("executed.log"),
        },
    })
}


async fn no_pause(_delay: Duration) {}


fn identity() -> Identity {
    Identity {
        tenant: "acme".to_owned(),
        agent_id: "agent-1".to_owned(),
    }
}


fn batch(sequence: u64) -> EventBatch {
    EventBatch {
        sequence,
        ecs_json: b"{}".to_vec(),
        ..EventBatch::default()
    }
}


fn entry() -> NewEntry {
    NewEntry {
        timestamp: time::OffsetDateTime::UNIX_EPOCH,
        actor: Actor {
            kind: ActorKind::System,
            id: "test".to_owned(),
        },
        tenant: "acme".to_owned(),
        module: "test".to_owned(),
        action: "config.reload".to_owned(),
        target: "x".to_owned(),
        outcome: Outcome::Success,
        request_id: "r".to_owned(),
        justification: None,
        parameters: Default::default(),
    }
}


fn command(sequence: u64) -> Command {
    Command {
        key_id: KEY_ID.to_owned(),
        key_class: KeyClass::Routine,
        agent_id: "agent-1".to_owned(),
        tenant: "acme".to_owned(),
        issued_at: 0,
        expires_at: 1,
        sequence,
        nonce: [0; NONCE_LENGTH],
        action: Action::Ping,
    }
}


async fn run_once(agent: &AgentFile) -> Result<agent_channel::agent_app::AgentOutcome, Box<dyn std::error::Error>> {
    Ok(bounded(run_agent(agent, &|delay| Box::pin(no_pause(delay)))).await??)
}


#[tokio::test]
async fn a_batch_lands_once_a_resent_batch_is_deduplicated_and_a_command_reaches_the_worker() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let Fixture { server, mut agent } = fixture(dir.path())?;
    let listener = bind_server(&server).await?;
    agent.server = listener.local_addr()?.to_string();
    let (stop, stopped) = oneshot::channel::<()>();
    let handle = tokio::spawn(run_server(
        server.clone(),
        listener,
        Box::pin(async move {
            if let Err(error) = stopped.await {
                tracing::warn!(%error, "stop sender dropped");
            }
        }),
    ));
    let first = run_once(&agent).await?;
    assert_eq!(first.acknowledged, vec![FIRST, SECOND]);
    assert_eq!((first.run.accepted, first.run.refused, first.executed), (1, 1, 1));
    let second = run_once(&agent).await?;
    assert_eq!(second.acknowledged, vec![FIRST, SECOND]);
    assert_eq!((second.run.accepted, second.run.refused, second.executed), (0, TWICE_COUNT, 0));
    assert_eq!(fs::read_to_string(&server.events_file)?.lines().count(), TWICE);
    assert!(fs::read_to_string(&agent.executed_file)?.contains("acme agent-1 1 Ping"));
    stop.send(()).map_err(|()| "server already stopped")?;
    bounded(handle).await???;
    let reopened = open_event_store(&server.events_file)?;
    assert_eq!(reopened.seen.len(), TWICE);
    Ok(())
}


#[tokio::test]
async fn a_restarted_server_still_deduplicates() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let Fixture { server, mut agent } = fixture(dir.path())?;
    let mut lines = 0;
    for _round in 0..TWICE {
        let listener = bind_server(&server).await?;
        agent.server = listener.local_addr()?.to_string();
        let (stop, stopped) = oneshot::channel::<()>();
        let handle = tokio::spawn(run_server(
            server.clone(),
            listener,
            Box::pin(async move {
                if let Err(error) = stopped.await {
                    tracing::warn!(%error, "stop sender dropped");
                }
            }),
        ));
        run_once(&agent).await?;
        stop.send(()).map_err(|()| "server already stopped")?;
        bounded(handle).await???;
        lines = fs::read_to_string(&server.events_file)?.lines().count();
    }
    assert_eq!(lines, TWICE);
    Ok(())
}


#[tokio::test]
async fn the_server_refuses_bad_files() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let Fixture { server, .. } = fixture(dir.path())?;
    assert!(load_server_file(&dir.path().join("missing.yaml")).is_err());
    let unknown = ServerFile {
        listen: "not-an-address".to_owned(),
        ..server.clone()
    };
    assert!(bind_server(&unknown).await.is_err());
    let listener = bind_server(&server).await?;
    let corrupt = ServerFile {
        events_file: write_file(dir.path(), "corrupt.log", "garbage\n", PRIVATE_MODE)?,
        ..server.clone()
    };
    let outcome = run_server(corrupt, listener, Box::pin(async {})).await;
    assert!(matches!(outcome, Err(AppError::Sink(SinkError::Corrupt { line: 1 }))));
    let text = format!(
        "listen: 127.0.0.1:0\ncertificate: {0}\nkey: {0}\nagent_ca: {0}\nrevocation_file: {0}\nsettings_file: {0}\naudit_file: {0}\nevents_file: {0}\ncommands_dir: {0}\n",
        dir.path().display()
    );
    let file = write_file(dir.path(), "server.yaml", &text, PRIVATE_MODE)?;
    assert_eq!(load_server_file(&file)?.listen, "127.0.0.1:0");
    Ok(())
}


#[tokio::test]
async fn the_agent_refuses_bad_files_and_addresses() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let Fixture { agent, .. } = fixture(dir.path())?;
    let bad_address = AgentFile {
        server: "nowhere".to_owned(),
        ..agent.clone()
    };
    assert!(matches!(run_once(&bad_address).await, Err(error) if error.to_string().contains("invalid server address")));
    let gone = dir.path().join("gone").join("file");
    fs::write(&agent.spool_file, "")?;
    let broken = [
        AgentFile {
            certificate: gone.clone(),
            ..agent.clone()
        },
        AgentFile {
            spool_file: gone.clone(),
            ..agent.clone()
        },
        AgentFile {
            audit_file: gone.clone(),
            ..agent.clone()
        },
        AgentFile {
            keys_file: gone.clone(),
            ..agent.clone()
        },
        AgentFile {
            executed_file: gone.clone(),
            ..agent.clone()
        },
        AgentFile {
            state_file: gone.clone(),
            ..agent.clone()
        },
    ];
    let corrupt = write_file(dir.path(), "corrupt-state.json", "not json", PRIVATE_MODE)?;
    let every_broken = [
        broken.to_vec(),
        vec![AgentFile {
            state_file: corrupt,
            ..agent.clone()
        }],
    ]
    .concat();
    for file in &every_broken {
        assert!(run_once(file).await.is_err());
    }
    assert!(read_spool(&dir.path().join("missing.txt"), &agent).is_err());
    assert!(batches_of(std::iter::once(Err(io::Error::other("injected"))), &agent).is_err());
    fs::write(&agent.spool_file, "{\"event\":1}\n{\"event\":2}\n")?;
    assert_eq!(read_spool(&agent.spool_file, &agent)?.len(), TWICE);
    assert!(load_agent_file(&dir.path().join("missing.yaml")).is_err());
    let file = write_file(dir.path(), "agent.yaml", AGENT_YAML, PRIVATE_MODE)?;
    assert_eq!(load_agent_file(&file)?.agent_id, "a");
    Ok(())
}


#[tokio::test]
async fn an_unreachable_server_exhausts_the_attempts() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let Fixture { mut agent, .. } = fixture(dir.path())?;
    fs::write(&agent.spool_file, "")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    agent.server = listener.local_addr()?.to_string();
    drop(listener);
    let outcome = run_once(&agent).await;
    assert!(matches!(outcome, Err(error) if error.to_string().contains("abandoned")));
    fs::write(&agent.spool_file, "{\"event\":1}\n")?;
    assert!(run_once(&agent).await.is_err());
    Ok(())
}


#[tokio::test]
async fn a_timed_out_call_is_a_failed_attempt() -> TestResult {
    let _logging = scoped_logging();
    let calls = AtomicU32::new(0);
    let pauses = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&pauses);
    let pause = move |_delay: Duration| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {}) as agent_channel::types::PauseFuture
    };
    let output = run_attempts(
        || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Err(ChannelError::CallTimedOut { seconds: 1 })
                } else {
                    Ok(call)
                }
            }
        },
        &pause,
    )
    .await?;
    assert_eq!((output, pauses.load(Ordering::SeqCst)), (1, 1));
    let exhausted = run_attempts(|| async { Err::<(), _>(ChannelError::CallTimedOut { seconds: 1 }) }, &pause).await;
    assert!(matches!(
        exhausted,
        Err(AppError::AttemptsExhausted {
            attempts: MAX_AGENT_ATTEMPTS,
            last: Some(_)
        })
    ));
    Ok(())
}


#[tokio::test]
async fn the_worker_records_and_the_executor_returns_at_once() -> TestResult {
    let _logging = scoped_logging();
    let (sender, receiver) = mpsc::channel(1);
    let execute = execute_fn(sender);
    execute(command(FIRST));
    execute(command(SECOND));
    drop(execute);
    let mut recorded = FlakyWriter::default();
    assert_eq!(record_commands(receiver, &mut recorded).await, 0);
    let (flaky_sender, flaky_receiver) = mpsc::channel(TWICE);
    flaky_sender.send(command(FIRST)).await?;
    flaky_sender.send(command(SECOND)).await?;
    drop(flaky_sender);
    let mut flaky = FlakyWriter::default();
    assert_eq!(record_commands(flaky_receiver, &mut flaky).await, 1);
    assert_eq!(String::from_utf8(flaky.written)?, "acme agent-1 2 Ping\n");
    Ok(())
}


#[tokio::test]
async fn the_sink_deduplicates_and_survives_failures() -> TestResult {
    let _logging = scoped_logging();
    let store = Mutex::new(EventStore {
        writer: Vec::new(),
        sync: no_sync,
        seen: HashSet::new(),
    });
    assert!(store_batch(&store, identity(), &batch(1))?);
    assert!(!store_batch(&store, identity(), &batch(1))?);
    assert!(store_batch(&store, identity(), &batch(SECOND))?);
    let failing = Arc::new(Mutex::new(EventStore {
        writer: FailingWriter,
        sync: no_sync,
        seen: HashSet::new(),
    }));
    let sink = file_sink(Arc::clone(&failing));
    assert!(sink(identity(), batch(1)).await.is_err());
    let working = Arc::new(Mutex::new(EventStore {
        writer: Vec::new(),
        sync: no_sync,
        seen: HashSet::new(),
    }));
    let good = file_sink(working);
    good(identity(), batch(1)).await.map_err(|error| error.to_string())?;
    Ok(())
}


#[test]
fn event_lines_are_parsed_strictly() -> TestResult {
    assert_eq!(parse_line("acme agent-1 7 7b7d", 1)?, (identity(), SEVEN));
    assert!(matches!(parse_line("acme", THIRD), Err(SinkError::Corrupt { line: THIRD })));
    assert!(matches!(
        parse_line("acme agent-1 x 00", FOURTH),
        Err(SinkError::Corrupt { line: FOURTH })
    ));
    assert_eq!(load_seen(Cursor::new("acme agent-1 1 00\nacme agent-1 1 00\n"))?.len(), 1);
    Ok(())
}


#[test]
fn the_events_file_must_open() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(
        open_event_store(&dir.path().join("missing").join("events.log")),
        Err(SinkError::Open { .. })
    ));
    let invalid = dir.path().join("invalid.log");
    fs::write(&invalid, INVALID_UTF8)?;
    assert!(matches!(open_event_store(&invalid), Err(SinkError::Io(_))));
    Ok(())
}


#[tokio::test]
async fn the_command_source_reads_a_bounded_directory() -> TestResult {
    let dir = tempdir()?;
    let agent_dir = agent_directory(dir.path(), &identity());
    fs::create_dir_all(&agent_dir)?;
    (0..=MAX_COMMAND_FILES).try_for_each(|index| fs::write(agent_dir.join(format!("{index:03}")), b"x"))?;
    let source = command_source(dir.path().to_path_buf());
    assert_eq!(source(identity()).collect::<Vec<_>>().await.len(), MAX_COMMAND_FILES);
    let other = Identity {
        tenant: "acme".to_owned(),
        agent_id: "agent-2".to_owned(),
    };
    assert!(source(other).collect::<Vec<_>>().await.is_empty());
    let big = dir.path().join("big");
    fs::write(&big, vec![FILLER; usize::try_from(MAX_ENVELOPE_FILE_BYTES)? + OVERSIZE_EXTRA])?;
    assert!(read_envelope(&big).is_err());
    assert!(paths_of(std::iter::once(Err(io::Error::other("injected")))).is_err());
    let oversized_dir = dir.path().join("oversized");
    fs::create_dir_all(&oversized_dir)?;
    fs::write(
        oversized_dir.join("a"),
        vec![FILLER; usize::try_from(MAX_ENVELOPE_FILE_BYTES)? + OVERSIZE_EXTRA],
    )?;
    assert!(read_envelopes(&oversized_dir).is_err());
    Ok(())
}


#[test]
fn a_failed_audit_append_is_passed_on_as_an_alert() -> TestResult {
    let _logging = scoped_logging();
    let failing = alerting_audit(Box::new(|_entry| Err(AuditError::LogPoisoned)));
    assert!(failing(entry()).is_err());
    let log = Arc::new(genesis_log(io::sink()));
    let working = alerting_audit(Box::new(move |new_entry| core_audit::log::append(&log, new_entry)));
    assert!(working(entry()).is_ok());
    let dir = tempdir()?;
    let file_log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    assert!(shared_log_audit(&file_log)(entry()).is_ok());
    let context = reload_context(Path::new("x.yaml"), "module", "tenant", "request");
    assert_eq!((context.target.as_str(), context.module.as_str()), ("x.yaml", "module"));
    Ok(())
}


#[tokio::test]
async fn a_failed_heartbeat_fails_the_session_attempt() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    let channel = tonic::transport::Endpoint::from_static(agent_channel::model::PLACEHOLDER_ENDPOINT).connect_with_connector_lazy(tower::service_fn(
        move |_uri: http::Uri| async move { tokio::net::TcpStream::connect(address).await.map(hyper_util::rt::TokioIo::new) },
    ));
    let dial: Box<agent_channel::types::DialFn> = Box::new(move || {
        let ready = channel.clone();
        Box::pin(async move { Ok(ready) })
    });
    let verifier = agent_verifier(dir.path())?;
    let execute = execute_fn(mpsc::channel(1).0);
    let outcome = bounded(session_attempt(dial.as_ref(), &verifier, execute.as_ref())).await?;
    assert!(outcome.is_err());
    Ok(())
}

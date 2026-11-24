use crate::app::{fixture, Fixture};
use crate::harness::{
    bounded, client_paths, empty_revocation, make_platform, scoped_logging, server_paths, start_server, start_server_state, stop_server,
};
use crate::harness::{init_logging, long_tempdir};
use crate::harness::{Platform, RunningServer};
use crate::pki::{agent_spec, issue, make_authority, write_file, write_leaf, LeafSpec, AGENT_URI, PRIVATE_MODE, SERVER_NAME, WORLD_READABLE_MODE};
use crate::services::{agent_verifier, settings, signed_envelope};
use crate::spool_refused::captured_log;
use crate::state::{envelope_source, make_state, new_stored, recording_sink};
use crate::types::TestResult;
use agent_channel::agent_app::{dialer, ended_on_rate, execute_fn, load_agent_file, note_run, run_agent, run_attempts, run_streams, AgentFile};
use agent_channel::client::{run_commands_until, subscribe};
use agent_channel::error::{AppError, ChannelError, EndpointFault};
use agent_channel::model::{
    CommandRun, Identity, ServerTlsPaths, CONNECT_TIMEOUT_SECONDS, MAX_RELAYS, PREFERRED_RETRY_SECONDS, UNARY_TIMEOUT_SECONDS,
};
use agent_channel::relay::{
    check_scope, endpoint_addresses, error_text, hold_internal, is_held, is_rate_refusal, kind_of, pinned_dialer, select_endpoint, selection_order,
    stop_at, tripped, EndpointKind, HoldDown, Selected,
};
use agent_channel::server_app::{bind_server, file_events, run_server, ServerFile};
use agent_channel::spool::{suffixed, SENDING_SUFFIX};
use agent_channel::spool_dirs::open_spool_dirs_with;
use agent_channel::tls::client_config;
use agent_channel::types::{CommandSource, SharedClientConfig};
use futures_util::{stream, FutureExt, StreamExt};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;


const BACKLOG: u32 = 16;


const RELAY_PORT: u16 = 443;


const RATE_WINDOW_FOR_TEST: u64 = 3600;


const MAX_FORWARDED: usize = 64;


const MAX_STALLED: usize = 16;


const SLACK_SECONDS: u64 = 5;


const BEFORE_EXPIRY_SECONDS: u64 = 1;


const FAR_FUTURE_SECONDS: u64 = 100_000;


const FIRST_SEQUENCES: [u64; 2] = [1, 2];


const SECOND_SEQUENCES: [u64; 2] = [3, 4];


const THIRD_SEQUENCES: [u64; 2] = [5, 6];


const TWO_RELAYS: usize = 2;


const THIRD_INDEX: usize = 2;


const LAST_RELAY_INDEX: usize = 2;


const WORKER_QUEUE_FOR_TEST: usize = 8;


fn closed_port() -> Result<(TcpSocket, SocketAddr), Box<dyn std::error::Error>> {
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.1:0".parse()?)?;
    let address = socket.local_addr()?;
    Ok((socket, address))
}


fn forward(listener: TcpListener, target: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut accepted = 0;
        while accepted < MAX_FORWARDED {
            match listener.accept().await {
                Ok((mut inbound, _peer)) => {
                    connections.spawn(async move {
                        match TcpStream::connect(target).await {
                            Ok(mut outbound) => {
                                if let Err(error) = copy_bidirectional(&mut inbound, &mut outbound).await {
                                    tracing::info!(%error, "forwarder connection ended");
                                }
                            }
                            Err(error) => tracing::warn!(%error, "forwarder target refused"),
                        }
                    });
                }
                Err(error) => tracing::warn!(%error, "forwarder accept failed"),
            }
            accepted += 1;
        }
    })
}


async fn stalled_endpoint() -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut held = Vec::new();
        while held.len() < MAX_STALLED {
            match listener.accept().await {
                Ok((socket, _peer)) => held.push(socket),
                Err(error) => tracing::warn!(%error, "stalled endpoint accept failed"),
            }
        }
    });
    Ok((address, handle))
}


fn sub_directory(dir: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::create_dir(&path)?;
    Ok(path)
}


struct Rig {
    dir: tempfile::TempDir,
    platform: Platform,
    config: SharedClientConfig,
}


fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = long_tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = client_config(&paths)?;
    Ok(Rig { dir, platform, config })
}


async fn good_server(rig: &Rig, name: &str) -> Result<RunningServer, Box<dyn std::error::Error>> {
    let directory = sub_directory(rig.dir.path(), name)?;
    start_server(&server_paths(&directory, &rig.platform)?).await
}


async fn wrong_ca_server(rig: &Rig, name: &str) -> Result<RunningServer, Box<dyn std::error::Error>> {
    let directory = sub_directory(rig.dir.path(), name)?;
    start_server(&server_paths(&directory, &make_platform()?)?).await
}


async fn other_name_server(rig: &Rig, name: &str) -> Result<RunningServer, Box<dyn std::error::Error>> {
    let directory = sub_directory(rig.dir.path(), name)?;
    let leaf = issue(
        &rig.platform.platform_ca,
        &LeafSpec {
            uris: Vec::new(),
            dns: vec!["other.test".to_owned()],
            expired: false,
        },
    )?;
    let files = write_leaf(&directory, "server", &leaf)?;
    let paths = ServerTlsPaths {
        certificate: files.certificate,
        key: files.key,
        agent_ca: write_file(&directory, "agent-ca.pem", &rig.platform.agent_ca.pem, WORLD_READABLE_MODE)?,
    };
    start_server(&paths).await
}


async fn agent_refusing_server(rig: &Rig, name: &str) -> Result<RunningServer, Box<dyn std::error::Error>> {
    let directory = sub_directory(rig.dir.path(), name)?;
    let paths = server_paths(&directory, &rig.platform)?;
    let refusing = ServerTlsPaths {
        agent_ca: write_file(&directory, "other-agent-ca.pem", &make_authority()?.pem, WORLD_READABLE_MODE)?,
        ..paths
    };
    start_server(&refusing).await
}


fn agent_with(base: &AgentFile, server: &str, relays: &[&str]) -> AgentFile {
    AgentFile {
        server: server.to_owned(),
        relays: relays.iter().map(ToString::to_string).collect(),
        ..base.clone()
    }
}


#[tokio::test]
async fn the_file_refuses_a_bad_endpoint_list_by_entry_index() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let Fixture { agent, .. } = fixture(dir.path())?;
    let good = agent_with(&agent, "10.0.0.1:443", &["10.0.0.2:443", "[2001:db8::1]:443"]);
    assert_eq!(endpoint_addresses(&good)?.len(), TWO_RELAYS + 1);
    assert_eq!(agent_with(&agent, "10.0.0.1:443", &[]).relays.len(), 0);
    let cases: Vec<(&str, Vec<&str>, usize, EndpointFault)> = vec![
        ("10.0.0.1:443", vec!["10.0.0.1:0443"], 1, EndpointFault::Duplicate),
        ("10.0.0.1:443", vec!["[::ffff:10.0.0.1]:443"], 1, EndpointFault::Duplicate),
        ("[::1]:443", vec!["[0:0::1]:443"], 1, EndpointFault::Duplicate),
        (
            "10.0.0.1:443",
            vec!["10.0.0.2:443", "10.0.0.2:443"],
            THIRD_INDEX,
            EndpointFault::Duplicate,
        ),
        ("10.0.0.1:443", vec!["0.0.0.0:443"], 1, EndpointFault::Unusable),
        ("[::]:443", vec![], 0, EndpointFault::Unusable),
        ("10.0.0.1:443", vec!["224.0.0.1:443"], 1, EndpointFault::Unusable),
        ("255.255.255.255:443", vec![], 0, EndpointFault::Unusable),
        ("10.0.0.1:0", vec![], 0, EndpointFault::ZeroPort),
        ("10.0.0.1:443", vec!["10.0.0.2:0"], 1, EndpointFault::ZeroPort),
        ("10.0.0.1:443", vec!["10.0.0.2:443", "nowhere"], THIRD_INDEX, EndpointFault::Unparsable),
        ("[fe80::1]:443", vec![], 0, EndpointFault::LinkLocal),
        ("10.0.0.1:443", vec!["[febf::1]:443"], 1, EndpointFault::LinkLocal),
        ("10.0.0.1:443", vec!["[::1%1]:443"], 1, EndpointFault::Scoped),
        (
            "10.0.0.1:443",
            vec!["10.0.0.2:443", "[fe80::1%2]:443"],
            THIRD_INDEX,
            EndpointFault::Scoped,
        ),
        ("10.0.0.1:443", vec!["[::ffff:10.0.0.2%1]:443"], 1, EndpointFault::Scoped),
    ];
    for (server, relays, index, fault) in cases {
        let outcome = endpoint_addresses(&agent_with(&agent, server, &relays));
        assert!(
            matches!(outcome, Err(AppError::Endpoint { index: found, reason }) if found == index && reason == fault),
            "{server} {relays:?}"
        );
    }
    let texts: Vec<String> = [
        EndpointFault::Unparsable,
        EndpointFault::ZeroPort,
        EndpointFault::Unusable,
        EndpointFault::Duplicate,
        EndpointFault::ServerName,
        EndpointFault::LinkLocal,
        EndpointFault::Scoped,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(texts.iter().collect::<std::collections::HashSet<_>>().len(), texts.len());
    assert!(endpoint_addresses(&agent_with(&agent, "10.0.0.1:443", &["[fec0::1]:443", "[2001:db8::1]:443"])).is_ok());
    let flow = SocketAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, RELAY_PORT, 1, 0));
    assert!(matches!(
        check_scope(1, flow),
        Err(AppError::Endpoint {
            index: 1,
            reason: EndpointFault::Scoped
        })
    ));
    let labelled = SocketAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, RELAY_PORT, 0, 1));
    assert!(matches!(
        check_scope(1, labelled),
        Err(AppError::Endpoint {
            reason: EndpointFault::Scoped,
            ..
        })
    ));
    let five: Vec<String> = (1..=MAX_RELAYS + 1).map(|i| format!("10.0.1.{i}:443")).collect();
    let too_many = AgentFile {
        relays: five,
        ..agent.clone()
    };
    assert!(matches!(endpoint_addresses(&too_many), Err(AppError::TooManyRelays { count, max }) if count == MAX_RELAYS + 1 && max == MAX_RELAYS));
    let four: Vec<String> = (1..=MAX_RELAYS).map(|i| format!("10.0.1.{i}:443")).collect();
    assert_eq!(
        endpoint_addresses(&AgentFile {
            relays: four,
            ..agent.clone()
        })?
        .len(),
        MAX_RELAYS + 1
    );
    for name in ["", "bad name", "-x"] {
        let named = AgentFile {
            server_name: name.to_owned(),
            ..agent.clone()
        };
        assert!(matches!(
            endpoint_addresses(&named),
            Err(AppError::Endpoint {
                index: 0,
                reason: EndpointFault::ServerName
            })
        ));
    }
    Ok(())
}


#[tokio::test]
async fn the_file_is_checked_at_load_not_at_the_first_run() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let text = |relays: &str| {
        format!(
            "server: 127.0.0.1:1\nserver_name: x\n{relays}certificate: c\nkey: k\nplatform_ca: p\ntenant: t\nagent_id: a\n\
keys_file: k\nstate_file: s\naudit_file: a\nspool_file: s\nsequence_file: q\nexecuted_file: e\n"
        )
    };
    let plain = write_file(dir.path(), "plain.yaml", &text(""), PRIVATE_MODE)?;
    assert!(load_agent_file(&plain)?.relays.is_empty());
    let listed = write_file(dir.path(), "listed.yaml", &text("relays: [\"10.0.0.2:443\"]\n"), PRIVATE_MODE)?;
    assert_eq!(load_agent_file(&listed)?.relays, vec!["10.0.0.2:443".to_owned()]);
    let duplicate = write_file(dir.path(), "duplicate.yaml", &text("relays: [\"127.0.0.1:0001\"]\n"), PRIVATE_MODE)?;
    assert!(matches!(
        load_agent_file(&duplicate),
        Err(AppError::Endpoint {
            index: 1,
            reason: EndpointFault::Duplicate
        })
    ));
    let many = write_file(
        dir.path(),
        "many.yaml",
        &text("relays: [\"10.0.0.1:1\", \"10.0.0.2:1\", \"10.0.0.3:1\", \"10.0.0.4:1\", \"10.0.0.5:1\"]\n"),
        PRIVATE_MODE,
    )?;
    assert!(matches!(load_agent_file(&many), Err(AppError::TooManyRelays { .. })));
    let unknown = write_file(dir.path(), "unknown.yaml", &text("relay: x\n"), PRIVATE_MODE)?;
    assert!(load_agent_file(&unknown).is_err());
    Ok(())
}


#[tokio::test]
async fn the_internal_endpoint_is_tried_first_and_a_relay_never_before_it() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let internal = good_server(&rig, "internal").await?;
    let relay = good_server(&rig, "relay").await?;
    let hold = HoldDown::default();
    let selected = bounded(select_endpoint(&[internal.address, relay.address], &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!(
        (selected.index, selected.kind, selected.address, selected.cut),
        (0, EndpointKind::Internal, internal.address, None)
    );
    assert!(!is_held(&hold));
    hold_internal(&hold);
    let held = bounded(select_endpoint(&[internal.address, relay.address], &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!((held.index, held.kind, held.address), (1, EndpointKind::Relay, relay.address));
    assert!(held.cut.is_some());
    let only_internal = bounded(select_endpoint(&[internal.address], &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!(only_internal.kind, EndpointKind::Internal);
    stop_server(internal).await?;
    stop_server(relay).await
}


#[tokio::test]
async fn a_refused_internal_endpoint_falls_to_the_relay_and_is_held_down() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let relay = good_server(&rig, "relay").await?;
    let (_reserved, closed) = closed_port()?;
    let hold = HoldDown::default();
    let selected = bounded(select_endpoint(&[closed, relay.address], &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!((selected.index, selected.kind), (1, EndpointKind::Relay));
    assert!(is_held(&hold));
    assert!(selected.cut.is_some_and(|cut| cut > Instant::now()));
    stop_server(relay).await
}


#[tokio::test]
async fn an_internal_server_that_refuses_the_first_call_is_skipped() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let internal = agent_refusing_server(&rig, "internal").await?;
    let relay = good_server(&rig, "relay").await?;
    let hold = HoldDown::default();
    let selected = bounded(select_endpoint(&[internal.address, relay.address], &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!((selected.index, selected.kind), (1, EndpointKind::Relay));
    assert!(is_held(&hold));
    stop_server(internal).await?;
    stop_server(relay).await
}


#[tokio::test]
async fn a_relay_with_another_ca_or_another_name_is_refused_and_the_next_is_tried() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let (_reserved, closed) = closed_port()?;
    let wrong_ca = wrong_ca_server(&rig, "wrong-ca").await?;
    let other_name = other_name_server(&rig, "other-name").await?;
    let good = good_server(&rig, "good").await?;
    let hold = HoldDown::default();
    let addresses = [closed, wrong_ca.address, other_name.address, good.address];
    let selected = bounded(select_endpoint(&addresses, &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!((selected.index, selected.address), (addresses.len() - 1, good.address));
    let only_hostile = bounded(select_endpoint(
        addresses.get(..addresses.len() - 1).ok_or("empty")?,
        &rig.config,
        SERVER_NAME,
        &hold,
    ))
    .await?;
    assert!(only_hostile.is_err());
    stop_server(wrong_ca).await?;
    stop_server(other_name).await?;
    stop_server(good).await
}


#[tokio::test]
async fn a_black_holed_endpoint_costs_the_connect_deadline_and_never_hangs() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let mut stalled = Vec::new();
    let mut handles = Vec::new();
    for _endpoint in 0..=MAX_RELAYS {
        let (address, handle) = stalled_endpoint().await?;
        stalled.push(address);
        handles.push(handle);
    }
    let hold = HoldDown::default();
    tokio::time::pause();
    let started = Instant::now();
    let outcome = select_endpoint(&stalled, &rig.config, SERVER_NAME, &hold).await;
    let elapsed = started.elapsed();
    assert!(outcome.is_err());
    let floor = Duration::from_secs(CONNECT_TIMEOUT_SECONDS * u64::try_from(stalled.len())?);
    assert!(elapsed >= floor && elapsed < floor + Duration::from_secs(SLACK_SECONDS), "{elapsed:?}");
    assert!(is_held(&hold));
    handles.iter().for_each(JoinHandle::abort);
    Ok(())
}


#[tokio::test]
async fn the_hold_down_lasts_exactly_the_retry_bound_on_the_tokio_clock() -> TestResult {
    let hold = HoldDown::default();
    tokio::time::pause();
    assert!(!is_held(&hold));
    hold_internal(&hold);
    assert!(is_held(&hold));
    tokio::time::advance(Duration::from_secs(PREFERRED_RETRY_SECONDS - BEFORE_EXPIRY_SECONDS)).await;
    assert!(is_held(&hold));
    tokio::time::advance(Duration::from_secs(BEFORE_EXPIRY_SECONDS + BEFORE_EXPIRY_SECONDS)).await;
    assert!(!is_held(&hold));
    Ok(())
}


#[test]
fn the_order_puts_a_held_internal_endpoint_last_and_names_the_kinds() -> TestResult {
    let addresses: Vec<SocketAddr> = ["10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"]
        .iter()
        .map(|text| text.parse())
        .collect::<Result<_, _>>()?;
    let indexes = |held: bool, list: &[SocketAddr]| selection_order(list, held).iter().map(|(index, _address)| *index).collect::<Vec<_>>();
    assert_eq!(indexes(false, &addresses), vec![0, 1, THIRD_INDEX]);
    assert_eq!(indexes(true, &addresses), vec![1, THIRD_INDEX, 0]);
    assert_eq!(indexes(true, addresses.get(..1).ok_or("empty")?), vec![0]);
    assert_eq!(
        (kind_of(0), kind_of(1), kind_of(LAST_RELAY_INDEX)),
        (EndpointKind::Internal, EndpointKind::Relay, EndpointKind::Relay)
    );
    assert_eq!(
        (EndpointKind::Internal.to_string(), EndpointKind::Relay.to_string()),
        ("internal".to_owned(), "relay".to_owned())
    );
    Ok(())
}


#[tokio::test]
async fn a_failed_pinned_dial_trips_the_cancel_and_a_good_one_does_not() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let server = good_server(&rig, "good").await?;
    let (_reserved, closed) = closed_port()?;
    let (sender, receiver) = watch::channel(false);
    let trip = Arc::new(sender);
    let good = pinned_dialer(server.address, Arc::clone(&rig.config), SERVER_NAME.to_owned(), Arc::clone(&trip));
    bounded(good()).await??;
    assert!(!*receiver.borrow());
    let broken = pinned_dialer(closed, Arc::clone(&rig.config), SERVER_NAME.to_owned(), Arc::clone(&trip));
    assert!(bounded(broken()).await?.is_err());
    assert!(*receiver.borrow());
    bounded(tripped(receiver)).await?;
    let (dropped, orphan) = watch::channel(false);
    drop(dropped);
    bounded(tripped(orphan)).await?;
    stop_server(server).await
}


#[tokio::test]
async fn a_relay_run_stops_at_its_bound_and_an_internal_run_never() -> TestResult {
    bounded(stop_at(Some(Instant::now()))).await?;
    assert!(stop_at(None).now_or_never().is_none());
    tokio::time::pause();
    let far = Instant::now() + Duration::from_secs(FAR_FUTURE_SECONDS);
    let mut waiting = Box::pin(stop_at(Some(far)));
    assert!((&mut waiting).now_or_never().is_none());
    tokio::time::advance(Duration::from_secs(FAR_FUTURE_SECONDS)).await;
    bounded(waiting).await?;
    Ok(())
}


#[test]
fn only_a_failed_internal_run_holds_the_internal_endpoint_down() -> TestResult {
    let address: SocketAddr = "10.0.0.1:1".parse()?;
    let internal = Selected {
        index: 0,
        kind: EndpointKind::Internal,
        address,
        cut: None,
    };
    let relay = Selected {
        index: 1,
        kind: EndpointKind::Relay,
        address,
        cut: None,
    };
    let failed = || Err(AppError::Channel(ChannelError::EndpointLost));
    let healthy = || Ok(CommandRun::default());
    let hold = HoldDown::default();
    note_run(&hold, &relay, &failed());
    note_run(&hold, &internal, &healthy());
    assert!(!is_held(&hold));
    note_run(&hold, &internal, &failed());
    assert!(is_held(&hold));
    Ok(())
}


fn held_open(envelopes: Vec<Vec<u8>>, subscribed: Arc<Notify>, subscriptions: Arc<AtomicU64>) -> CommandSource {
    Box::new(move |_identity: Identity| {
        subscriptions.fetch_add(1, Ordering::SeqCst);
        subscribed.notify_one();
        Box::pin(stream::iter(envelopes.clone()).chain(stream::pending()))
    })
}


fn held_state(envelopes: Vec<Vec<u8>>, subscribed: Arc<Notify>) -> agent_channel::types::SharedState {
    make_state(
        agent_channel::model::ChannelSettings::default(),
        recording_sink(new_stored()),
        held_open(envelopes, subscribed, Arc::new(AtomicU64::new(0))),
    )
}


const NOW: u64 = 1_700_000_000;


#[tokio::test]
async fn a_stop_between_envelopes_still_judges_and_reports_the_one_in_flight() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let verifier = agent_verifier(dir.path())?;
    let state = held_state(vec![signed_envelope(1)?], Arc::new(Notify::new()));
    let platform = make_platform()?;
    let server = start_server_state(
        &server_paths(dir.path(), &platform)?,
        empty_revocation(&server_paths(dir.path(), &platform)?)?,
        Arc::clone(&state),
    )
    .await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let channel = bounded(agent_channel::client::connect_channel(
        server.address,
        client_config(&paths)?,
        SERVER_NAME,
    ))
    .await??;
    let (executing, executed) = oneshot::channel::<()>();
    let signal = Mutex::new(Some(executing));
    let stop = Box::pin(async move {
        if let Err(error) = executed.await {
            tracing::warn!(%error, "executor dropped");
        }
    });
    let run = bounded(run_commands_until(
        channel,
        &verifier,
        &|| NOW,
        &move |_command| {
            if let Some(sender) = signal.lock().unwrap_or_else(PoisonError::into_inner).take() {
                sender.send(()).map_err(|()| agent_channel::model::ExecuteRefusal::Busy)?;
            }
            Ok(())
        },
        stop,
    ))
    .await??;
    assert_eq!((run.accepted, run.refused), (1, 0));
    assert_eq!(state.counters.commands_accepted.load(Ordering::SeqCst), 1);
    stop_server(server).await
}


#[tokio::test]
async fn a_silent_subscribe_hits_the_unary_deadline() -> TestResult {
    let _logging = scoped_logging();
    let (address, server) = crate::unary::silent_server().await?;
    let channel = bounded(crate::unary::dial(address)).await??;
    tokio::time::pause();
    let outcome = bounded(subscribe(channel)).await?;
    assert!(matches!(outcome, Err(ChannelError::CallTimedOut { seconds }) if seconds == UNARY_TIMEOUT_SECONDS));
    server.abort();
    Ok(())
}


#[tokio::test]
async fn a_relay_run_cut_at_its_bound_ends_well_and_is_not_a_failed_attempt() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let Fixture { agent, .. } = fixture(dir.path())?;
    let platform = make_platform()?;
    let server = start_server_state(
        &server_paths(dir.path(), &platform)?,
        empty_revocation(&server_paths(dir.path(), &platform)?)?,
        held_state(Vec::new(), Arc::new(Notify::new())),
    )
    .await?;
    let paths = client_paths(dir.path(), "agent-2", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let dial = dialer(server.address, client_config(&paths)?, SERVER_NAME.to_owned());
    let verifier = agent_verifier(dir.path())?;
    let (sender, _receiver) = mpsc::channel(WORKER_QUEUE_FOR_TEST);
    let execute = execute_fn(sender);
    let pauses = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&pauses);
    let pause = move |_delay: Duration| -> agent_channel::types::PauseFuture {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(()))
    };
    let (delivery, run) = bounded(run_streams(
        dial.as_ref(),
        dial.as_ref(),
        &pause,
        Vec::new(),
        &verifier,
        execute.as_ref(),
        Some(Instant::now()),
    ))
    .await?;
    assert!(delivery.is_ok());
    assert_eq!(run?.accepted, 0);
    assert_eq!(pauses.load(Ordering::SeqCst), 0);
    assert!(agent.relays.is_empty());
    stop_server(server).await
}


#[tokio::test]
async fn an_internal_endpoint_dying_mid_run_ends_both_streams_at_once() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let verifier = agent_verifier(dir.path())?;
    let subscribed = Arc::new(Notify::new());
    let platform = make_platform()?;
    let server = start_server_state(
        &server_paths(dir.path(), &platform)?,
        empty_revocation(&server_paths(dir.path(), &platform)?)?,
        held_state(Vec::new(), Arc::clone(&subscribed)),
    )
    .await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = client_config(&paths)?;
    let front = TcpListener::bind("127.0.0.1:0").await?;
    let front_address = front.local_addr()?;
    let forwarder = forward(front, server.address);
    let (sender, receiver) = watch::channel(false);
    let dial = pinned_dialer(front_address, config, SERVER_NAME.to_owned(), Arc::new(sender));
    let (queue, _receiver) = mpsc::channel(WORKER_QUEUE_FOR_TEST);
    let execute = execute_fn(queue);
    let race = async {
        tokio::select! {
            outcome = run_streams(dial.as_ref(), dial.as_ref(), &|_delay| Box::pin(std::future::ready(())), Vec::new(), &verifier, execute.as_ref(), None) => Some(outcome),
            () = tripped(receiver) => None,
        }
    };
    let killer = async {
        subscribed.notified().await;
        forwarder.abort();
    };
    let (outcome, ()) = bounded(async { tokio::join!(race, killer) }).await?;
    assert!(outcome.is_none());
    stop_server(server).await
}


struct Farm {
    server: ServerFile,
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    handle: JoinHandle<Result<(), AppError>>,
}


async fn start_farm(server: &ServerFile) -> Result<Farm, Box<dyn std::error::Error>> {
    let listener = bind_server(server).await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let handle = tokio::spawn(run_server(
        server.clone(),
        listener,
        None,
        Box::pin(async move {
            if let Err(error) = stopped.await {
                tracing::warn!(%error, "stop sender dropped");
            }
        }),
        file_events(server)?,
    ));
    Ok(Farm {
        server: server.clone(),
        address,
        stop,
        handle,
    })
}


async fn stop_farm(farm: Farm) -> TestResult {
    farm.stop.send(()).map_err(|()| "server already stopped")?;
    bounded(farm.handle).await???;
    Ok(())
}


fn accept_any_acl(_directory: &std::fs::File, _shown: &Path) -> Result<(), sys_windows::types::DirAclError> {
    Ok(())
}


async fn run_held(agent: &AgentFile, hold: &HoldDown) -> Result<agent_channel::agent_app::AgentOutcome, Box<dyn std::error::Error>> {
    let dirs = open_spool_dirs_with(agent, accept_any_acl)?;
    Ok(bounded(run_agent(agent, &dirs, &|_delay| Box::pin(std::future::ready(())), None, hold)).await??)
}


fn expire(hold: &HoldDown) {
    *hold.until.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
}


#[tokio::test]
async fn an_agent_reaches_the_server_through_a_relay_and_returns_to_the_internal_path() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let Fixture { server, mut agent } = fixture(dir.path())?;
    let farm = start_farm(&server).await?;
    let (reserved, internal) = closed_port()?;
    let relay_front = TcpListener::bind("127.0.0.1:0").await?;
    let relay = relay_front.local_addr()?;
    let relay_forwarder = forward(relay_front, farm.address);
    agent.server = internal.to_string();
    agent.relays = vec![relay.to_string()];
    let hold = HoldDown::default();
    let first = run_held(&agent, &hold).await?;
    assert_eq!(first.acknowledged, FIRST_SEQUENCES.to_vec());
    assert_eq!((first.internal_runs, first.relay_runs), (0, 1));
    assert!(is_held(&hold));
    let internal_forwarder = forward(reserved.listen(BACKLOG)?, farm.address);
    fs::write(&agent.spool_file, "NEW-A\nNEW-B\n")?;
    let second = run_held(&agent, &hold).await?;
    assert_eq!(second.acknowledged, SECOND_SEQUENCES.to_vec());
    assert_eq!((second.internal_runs, second.relay_runs), (0, 1));
    expire(&hold);
    fs::write(&agent.spool_file, "NEW-C\nNEW-D\n")?;
    let third = run_held(&agent, &hold).await?;
    assert_eq!(third.acknowledged, THIRD_SEQUENCES.to_vec());
    assert_eq!((third.internal_runs, third.relay_runs), (1, 0));
    assert!(!is_held(&hold));
    assert_eq!(
        fs::read_to_string(&farm.server.events_file)?.lines().count(),
        FIRST_SEQUENCES.len() * THIRD_INDEX + FIRST_SEQUENCES.len()
    );
    relay_forwarder.abort();
    internal_forwarder.abort();
    stop_farm(farm).await
}


#[tokio::test]
async fn a_pinned_endpoint_that_dies_after_selection_ends_the_run_and_keeps_the_claimed_spool() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let Fixture { server, mut agent } = fixture(dir.path())?;
    let paths = ServerTlsPaths {
        certificate: server.certificate.clone(),
        key: server.key.clone(),
        agent_ca: server.agent_ca.clone(),
    };
    let single = crate::harness::start_single(&paths).await?;
    agent.server = single.address.to_string();
    let hold = HoldDown::default();
    let outcome = run_held(&agent, &hold).await;
    assert!(matches!(outcome, Err(error) if error.to_string().contains("selected endpoint failed")));
    assert!(is_held(&hold));
    assert!(suffixed(&agent.spool_file, SENDING_SUFFIX).exists());
    assert!(bounded(single.handle).await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn every_endpoint_unreachable_exhausts_the_attempts_and_claims_nothing() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    let Fixture { mut agent, .. } = fixture(dir.path())?;
    let (_first, closed) = closed_port()?;
    let (_second, other) = closed_port()?;
    agent.server = closed.to_string();
    agent.relays = vec![other.to_string()];
    let outcome = run_held(&agent, &HoldDown::default()).await;
    assert!(matches!(outcome, Err(error) if error.to_string().contains("abandoned")));
    assert!(agent.spool_file.exists());
    assert!(!suffixed(&agent.spool_file, SENDING_SUFFIX).exists());
    Ok(())
}


#[tokio::test]
async fn a_rate_refused_redial_does_not_trip_the_endpoint_or_hold_the_internal_one_down() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let directory = sub_directory(rig.dir.path(), "limited")?;
    let state = make_state(
        settings(|bounds| {
            bounds.max_requests_per_window = 1;
            bounds.rate_window_seconds = RATE_WINDOW_FOR_TEST;
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
    );
    let paths = server_paths(&directory, &rig.platform)?;
    let server = start_server_state(&paths, empty_revocation(&paths)?, state).await?;
    let (sender, receiver) = watch::channel(false);
    let trip = Arc::new(sender);
    let dial = pinned_dialer(server.address, Arc::clone(&rig.config), SERVER_NAME.to_owned(), Arc::clone(&trip));
    bounded(dial()).await??;
    let refused = bounded(dial()).await?.err().ok_or("the second heartbeat was not refused")?;
    assert!(is_rate_refusal(&refused));
    assert!(!is_rate_refusal(&ChannelError::Status(Box::new(tonic::Status::permission_denied("no")))));
    assert!(!*receiver.borrow());
    let exhausted = Err(AppError::AttemptsExhausted {
        attempts: 1,
        last: Some(Box::new(refused)),
    });
    assert!(ended_on_rate(&exhausted));
    assert!(!ended_on_rate(&Err(AppError::AttemptsExhausted {
        attempts: 1,
        last: Some(Box::new(ChannelError::EndpointLost))
    })));
    assert!(!ended_on_rate(&Err(AppError::Channel(ChannelError::EndpointLost))));
    assert!(!ended_on_rate(&Ok(CommandRun::default())));
    let internal = Selected {
        index: 0,
        kind: EndpointKind::Internal,
        address: server.address,
        cut: None,
    };
    let hold = HoldDown::default();
    note_run(&hold, &internal, &exhausted);
    assert!(!is_held(&hold));
    note_run(&hold, &internal, &Err(AppError::AttemptsExhausted { attempts: 1, last: None }));
    assert!(is_held(&hold));
    stop_server(server).await
}


const HUGE_STATUS_BYTES: usize = 1 << 20;


const STATUS_MARKER: &str = "STATUS-TAIL-MARKER";


const LOG_LINE_BOUND_BYTES: usize = 1024;


fn hostile_status(message: String) -> ChannelError {
    ChannelError::Status(Box::new(tonic::Status::new(tonic::Code::Internal, message)))
}


#[tokio::test]
async fn a_server_status_message_is_bounded_in_every_agent_log_line() -> TestResult {
    init_logging()?;
    let huge = hostile_status(format!("{}{STATUS_MARKER}", "x".repeat(HUGE_STATUS_BYTES)));
    let text = error_text(&huge);
    assert!(text.contains("Internal"));
    assert!(text.len() < LOG_LINE_BOUND_BYTES);
    assert!(!text.contains(STATUS_MARKER));
    assert_eq!(error_text(&ChannelError::EndpointLost), ChannelError::EndpointLost.to_string());
    let (captured, _guard) = captured_log();
    let pause = |_delay: Duration| Box::pin(async {}) as agent_channel::types::PauseFuture;
    let first = format!("{}{STATUS_MARKER}", "y".repeat(HUGE_STATUS_BYTES));
    let attempts = run_attempts(|| async { Err::<(), _>(hostile_status(first.clone())) }, &pause).await;
    assert!(attempts.is_err());
    let controlled = hostile_status("first\nforged line level=ERROR\u{1b}[31m".to_owned());
    let again = run_attempts(|| async { Err::<(), _>(controlled_clone(&controlled)) }, &pause).await;
    assert!(again.is_err());
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(!log.contains(STATUS_MARKER));
    assert!(log.lines().all(|line| line.len() < LOG_LINE_BOUND_BYTES));
    assert!(log.contains("first\\nforged line"));
    assert!(!log.contains('\u{1b}'));
    Ok(())
}


fn controlled_clone(error: &ChannelError) -> ChannelError {
    hostile_status(match error {
        ChannelError::Status(status) => status.message().to_owned(),
        other => other.to_string(),
    })
}


#[tokio::test]
async fn a_selection_refused_on_rate_fails_the_run_without_a_hold_down_or_another_endpoint() -> TestResult {
    let _logging = scoped_logging();
    let rig = rig()?;
    let directory = sub_directory(rig.dir.path(), "limited")?;
    let state = make_state(
        settings(|bounds| {
            bounds.max_requests_per_window = 1;
            bounds.rate_window_seconds = RATE_WINDOW_FOR_TEST;
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
    );
    let paths = server_paths(&directory, &rig.platform)?;
    let internal = start_server_state(&paths, empty_revocation(&paths)?, state).await?;
    let relay = good_server(&rig, "relay").await?;
    let addresses = [internal.address, relay.address];
    let hold = HoldDown::default();
    let first = bounded(select_endpoint(&addresses, &rig.config, SERVER_NAME, &hold)).await??;
    assert_eq!(first.kind, EndpointKind::Internal);
    let refused = bounded(select_endpoint(&addresses, &rig.config, SERVER_NAME, &hold)).await?;
    assert!(refused.is_err_and(|error| is_rate_refusal(&error)));
    assert!(!is_held(&hold));
    stop_server(internal).await?;
    stop_server(relay).await
}

use crate::harness::{
    attempt, bounded, client_paths, empty_revocation, make_platform, scoped_logging, server_paths, start_server_state, stop_server, Platform,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{counter, settings};
use crate::state::{discarding_audit, envelope_source, make_audited_state, make_state, new_stored, recording_sink};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, deliver_events, heartbeat, read_acks, send_pending};
use agent_channel::error::ChannelError;
use agent_channel::model::{
    ChannelSettings, Identity, PendingHandshake, ATTEMPT_TIMEOUT_SECONDS, IPV6_HOST_BITS, MAX_ACK_READS, MAX_IGNORED_ACKS, MAX_RECONNECT_ATTEMPTS,
};
use agent_channel::proto::{EventAck, EventBatch};
use agent_channel::server::{busiest_oldest, peer_source, register_handshake, source_of};
use agent_channel::tls::{client_config, server_config};
use agent_channel::types::{DialFuture, EventSink, PauseFuture, SinkFuture};
use futures_util::{stream, StreamExt};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{oneshot, Notify};
use tokio::time::{sleep, timeout, Instant};
use tokio_rustls::TlsAcceptor;
use tonic::Status;


const PENDING_BATCHES: u64 = 3;


const FOREIGN_SEQUENCE: u64 = 99;


const SETTLE_MILLIS: u64 = 25;


const FLOOD: usize = 5;


const PER_SOURCE: usize = 2;


const GLOBAL_CAP: usize = 3;


const LONG_WAIT_SECONDS: u64 = 600;


const SECOND_SOURCE_BYTE: u8 = 2;


const SECOND_SEQUENCE: u64 = 2;


const LOOPBACK_OCTET: u8 = 127;


fn batches(count: u64) -> Vec<EventBatch> {
    (1..=count)
        .map(|sequence| EventBatch {
            sequence,
            ecs_json: b"{}".to_vec(),
            ..EventBatch::default()
        })
        .collect()
}


fn ack(sequence: u64) -> Result<EventAck, Status> {
    Ok(EventAck { sequence })
}


fn soon() -> Instant {
    Instant::now() + Duration::from_secs(ATTEMPT_TIMEOUT_SECONDS)
}


fn handshake(source: IpAddr) -> (PendingHandshake, oneshot::Receiver<()>) {
    let (stop, receiver) = oneshot::channel();
    (PendingHandshake { source, stop }, receiver)
}


fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(LOOPBACK_OCTET, 0, 0, last))
}


#[tokio::test]
async fn endless_foreign_acknowledgements_are_cut_at_the_cap() -> TestResult {
    let (acknowledged, ended) = read_acks(Box::pin(stream::repeat_with(|| ack(FOREIGN_SEQUENCE))), &batches(PENDING_BATCHES), soon()).await;
    assert_eq!(acknowledged.len(), usize::try_from(PENDING_BATCHES)? + MAX_IGNORED_ACKS);
    assert!(ended.is_ok());
    Ok(())
}


#[tokio::test]
async fn the_read_loop_has_an_absolute_bound_whatever_the_pending_count() -> TestResult {
    let pending = batches(u64::try_from(MAX_ACK_READS)? + 1);
    let (acknowledged, ended) = read_acks(Box::pin(stream::repeat_with(|| ack(FOREIGN_SEQUENCE))), &pending, soon()).await;
    assert_eq!(acknowledged.len(), MAX_ACK_READS);
    assert!(ended.is_ok());
    Ok(())
}


#[tokio::test]
async fn reading_stops_once_every_pending_batch_is_settled_without_polling_again() -> TestResult {
    let acks = stream::iter((1..=PENDING_BATCHES).map(ack)).chain(stream::pending());
    let (acknowledged, ended) = read_acks(Box::pin(acks), &batches(PENDING_BATCHES), soon()).await;
    assert_eq!(acknowledged, (1..=PENDING_BATCHES).collect::<Vec<u64>>());
    assert!(ended.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_stream_that_ends_or_fails_ends_the_read() -> TestResult {
    let (acknowledged, ended) = read_acks(Box::pin(stream::iter([ack(1)])), &batches(PENDING_BATCHES), soon()).await;
    assert_eq!(acknowledged, vec![1]);
    assert!(ended.is_ok());
    let failing = stream::iter([ack(1), Err(Status::unavailable("gone")), ack(SECOND_SEQUENCE)]);
    let (kept, failed) = read_acks(Box::pin(failing), &batches(PENDING_BATCHES), soon()).await;
    assert_eq!(kept, vec![1]);
    assert!(matches!(failed, Err(ChannelError::Status(_))));
    Ok(())
}


#[tokio::test]
async fn a_stream_held_open_without_acknowledgements_hits_the_deadline() -> TestResult {
    tokio::time::pause();
    let (acknowledged, ended) = read_acks(Box::pin(stream::pending()), &batches(PENDING_BATCHES), soon()).await;
    assert!(acknowledged.is_empty());
    assert!(matches!(ended, Err(ChannelError::AttemptTimedOut { seconds }) if seconds == ATTEMPT_TIMEOUT_SECONDS));
    Ok(())
}


#[tokio::test]
async fn a_dial_that_never_completes_is_cut_and_the_delivery_gives_up() -> TestResult {
    tokio::time::pause();
    let dial = || -> DialFuture { Box::pin(std::future::pending()) };
    let (hung, ended) = send_pending(&dial, &batches(1)).await;
    assert!(hung.is_empty());
    assert!(matches!(ended, Err(ChannelError::AttemptTimedOut { .. })));
    let pause = |_delay: Duration| -> PauseFuture { Box::pin(async {}) };
    let outcome = deliver_events(&dial, &pause, batches(PENDING_BATCHES)).await;
    assert!(matches!(outcome, Err(ChannelError::RetriesExhausted { attempts, .. }) if attempts == MAX_RECONNECT_ATTEMPTS));
    Ok(())
}


fn stalling_sink(entered: Arc<Notify>) -> EventSink {
    Box::new(move |_identity: Identity, _batch: EventBatch| -> SinkFuture {
        let signal = Arc::clone(&entered);
        Box::pin(async move {
            signal.notify_one();
            std::future::pending::<()>().await;
            Ok(())
        })
    })
}


#[tokio::test]
async fn a_server_holding_the_stream_open_without_acknowledging_ends_in_give_up() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = client_config(&agent)?;
    let entered = Arc::new(Notify::new());
    let state = make_state(
        ChannelSettings::default(),
        stalling_sink(Arc::clone(&entered)),
        envelope_source(Vec::new()),
    );
    let server = start_server_state(&paths, empty_revocation(&paths)?, state).await?;
    let address = server.address;
    let dial = move || -> DialFuture {
        let dial_config = Arc::clone(&config);
        Box::pin(async move { connect_channel(address, dial_config, SERVER_NAME).await })
    };
    let pause = |_delay: Duration| -> PauseFuture { Box::pin(async {}) };
    let delivery = tokio::spawn(async move { deliver_events(&dial, &pause, batches(1)).await });
    bounded(entered.notified()).await?;
    tokio::time::pause();
    let outcome = timeout(Duration::from_secs(LONG_WAIT_SECONDS), delivery).await??;
    assert!(matches!(outcome, Err(ChannelError::RetriesExhausted { .. })));
    Ok(())
}


async fn start_mute_server(platform: &Platform, dir: &Path) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let paths = server_paths(dir, platform)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(server_config(&paths)?);
    tokio::spawn(async move {
        match listener.accept().await {
            Ok((stream, _peer)) => match acceptor.accept(stream).await {
                Ok(held) => {
                    std::future::pending::<()>().await;
                    drop(held);
                }
                Err(error) => tracing::warn!(%error, "mute server handshake failed"),
            },
            Err(error) => tracing::warn!(%error, "mute server accept failed"),
        }
    });
    Ok(address)
}


#[tokio::test]
async fn a_server_that_goes_mute_is_detected_by_the_keepalive() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let address = start_mute_server(&platform, dir.path()).await?;
    let channel = bounded(connect_channel(address, client_config(&agent)?, SERVER_NAME)).await??;
    tokio::time::pause();
    let outcome = timeout(Duration::from_secs(LONG_WAIT_SECONDS), heartbeat(channel, "test")).await?;
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn sources_are_folded_like_the_api_does() -> TestResult {
    let first: Ipv6Addr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse()?;
    let second: Ipv6Addr = "2001:db8:1:2:1:2:3:4".parse()?;
    let other: Ipv6Addr = "2001:db8:1:3::1".parse()?;
    assert_eq!(source_of(IpAddr::V6(first)), source_of(IpAddr::V6(second)));
    assert_ne!(source_of(IpAddr::V6(first)), source_of(IpAddr::V6(other)));
    assert_eq!(IPV6_HOST_BITS, u64::BITS);
    assert_eq!(source_of(host(1)), host(1));
    assert_eq!(source_of(IpAddr::V6(Ipv4Addr::new(LOOPBACK_OCTET, 0, 0, 1).to_ipv6_mapped())), host(1));
    assert_eq!(peer_source(Ok(SocketAddr::new(host(1), 1))), Some(host(1)));
    assert_eq!(peer_source(Err(io::Error::from(io::ErrorKind::NotConnected))), None);
    Ok(())
}


#[test]
fn a_source_at_its_cap_is_refused_and_the_global_eviction_hits_the_busiest_source() -> TestResult {
    let _logging = scoped_logging();
    let state = make_audited_state(
        settings(|base| {
            base.max_pending_handshakes_per_source = PER_SOURCE;
            base.max_pending_handshakes = GLOBAL_CAP;
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let mut waiting = Vec::new();
    let busy = host(1);
    let quiet = host(SECOND_SOURCE_BYTE);
    let first = register_handshake(&mut waiting, busy, &state).ok_or("first refused")?;
    let second = register_handshake(&mut waiting, busy, &state).ok_or("second refused")?;
    assert!(register_handshake(&mut waiting, busy, &state).is_none());
    assert_eq!(counter(&state.counters.handshakes_refused), 1);
    let quiet_first = register_handshake(&mut waiting, quiet, &state).ok_or("quiet refused")?;
    let mut quiet_second = register_handshake(&mut waiting, quiet, &state).ok_or("quiet refused")?;
    assert_eq!(counter(&state.counters.handshakes_evicted), 1);
    assert!(first.blocking_recv().is_ok());
    drop(second);
    drop(quiet_first);
    assert!(quiet_second.try_recv().is_err());
    assert_eq!(waiting.len(), GLOBAL_CAP);
    Ok(())
}


#[test]
fn the_busiest_source_gives_its_oldest_handshake() -> TestResult {
    assert_eq!(busiest_oldest(&[]), None);
    let (quiet, _quiet_receiver) = handshake(host(SECOND_SOURCE_BYTE));
    let (busy_first, _first) = handshake(host(1));
    let (busy_second, _second) = handshake(host(1));
    assert_eq!(busiest_oldest(&[quiet, busy_first, busy_second]), Some(1));
    Ok(())
}


#[tokio::test]
async fn a_flooding_source_is_refused_while_an_agent_from_another_address_connects() -> TestResult {
    let _logging = scoped_logging();
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let state = make_audited_state(
        settings(|base| base.max_pending_handshakes_per_source = PER_SOURCE),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let server = start_server_state(&paths, empty_revocation(&paths)?, Arc::clone(&state)).await?;
    let mut flood = Vec::new();
    for _ in 0..FLOOD {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(host(SECOND_SOURCE_BYTE), 0))?;
        flood.push(socket.connect(server.address).await?);
    }
    sleep(Duration::from_millis(SETTLE_MILLIS)).await;
    assert_eq!(counter(&state.counters.handshakes_refused), u64::try_from(FLOOD - PER_SOURCE)?);
    let closed = stream::iter(flood.iter_mut())
        .then(|connection: &mut TcpStream| async move {
            let mut buffer = [u8::MIN; 1];
            timeout(Duration::from_millis(SETTLE_MILLIS), connection.read(&mut buffer)).await
        })
        .filter(|read| std::future::ready(matches!(read, Ok(Ok(0) | Err(_)))))
        .count()
        .await;
    assert_eq!(closed, FLOOD - PER_SOURCE);
    assert!(bounded(attempt(server.address, &agent)).await?.is_ok());
    assert_eq!(counter(&state.counters.handshakes_evicted), 0);
    drop(flood);
    stop_server(server).await
}

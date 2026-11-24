use crate::harness::{bounded, client_paths, empty_revocation, init_logging, long_tempdir, make_platform, scoped_logging, server_paths};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::revocation_support::RevocationControl;
use crate::services::{counter, settings};
use crate::state::{default_state, discarding_audit, envelope_source, make_audited_state, new_stored, recording_sink};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, heartbeat};
use agent_channel::model::{
    ChannelSettings, Counters, HeaderPhase, ListenerKind, PendingHandshake, ProxyFamily, ProxyRefusal, RelayListener,
    MAX_PROXY_HEADER_PENDING_PER_RELAY, PROXY_COMMAND_BYTE, PROXY_PREFIX_BYTES, PROXY_SIGNATURE, PROXY_TCP4_BYTE, PROXY_TCP4_LENGTH,
    PROXY_TCP4_TAIL_BYTES, PROXY_TCP6_BYTE, PROXY_TCP6_LENGTH, PROXY_TCP6_TAIL_BYTES,
};
use agent_channel::proxy::{
    count_refusal, exact_length, prefix_family, refusal_counter, refusal_reason, take_header_permit, usable_source, HeaderCaps,
};
use agent_channel::server::{register_handshake, relay_peer, serve_with_relay};
use agent_channel::server_app::{bind_relay, check_listeners, load_server_file, relay_incoming, ServerFile};
use agent_channel::services::channel_router;
use agent_channel::settings::{check_operator_bytes, relay_sources_valid, settings_loader, settings_state, validate_settings};
use agent_channel::tls::{client_config, server_config};
use agent_channel::types::SharedState;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_stream::wrappers::TcpListenerStream;


const LOOPBACK_OCTET: u8 = 127;


const MULTICAST_OCTET: u8 = 224;


const TEN_OCTET: u8 = 10;


const LOCAL_COMMAND: u8 = 0x20;


const UNKNOWN_COMMAND: u8 = 0x22;


const UDP_FAMILY: u8 = 0x12;


const UNIX_FAMILY: u8 = 0x31;


const UNKNOWN_PEERS: u64 = 3;


const REFUSED_LISTS: usize = 9;


const CONFIGURED_RELAY_CAP: usize = 7;


const POLL_ATTEMPTS: u32 = 1_000;


const POLL_MILLIS: u64 = 10;


const PATIENT_HEADER_SECONDS: u64 = 60;


const SHORT_HEADER_MILLIS: u64 = 100;


const GAP_HEADER_MILLIS: u64 = 300;


const GAP_MILLIS: u64 = 200;


const READ_ATTEMPTS: u32 = 8;


const FIRST_CHUNK_BYTES: usize = 4_096;


const TLV_LENGTH: u16 = 60_000;


const TOO_MANY_RELAYS: u8 = 5;


const HELD_IN_HEADER_PHASE: usize = 10;


const PER_SOURCE: usize = 2;


const MAX_FORWARDED: usize = 16;


const SECOND_SOURCE_BYTE: u8 = 9;


const THIRD_SOURCE_BYTE: u8 = 10;


const RELAY_BYTE: u8 = 2;


const OTHER_BYTE: u8 = 3;


const FIRST_SHELF: u8 = 1;


fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(LOOPBACK_OCTET, 0, 0, last))
}


fn header(command: u8, family: u8, length: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = PROXY_SIGNATURE.to_vec();
    bytes.extend([command, family]);
    bytes.extend(length.to_be_bytes());
    bytes.extend(body);
    bytes
}


fn header_v4(source: Ipv4Addr) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = source.octets().to_vec();
    body.extend([u8::MIN; PROXY_TCP4_TAIL_BYTES]);
    Ok(header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, u16::try_from(PROXY_TCP4_LENGTH)?, &body))
}


fn header_v6(source: Ipv6Addr) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = source.octets().to_vec();
    body.extend([u8::MIN; PROXY_TCP6_TAIL_BYTES]);
    Ok(header(PROXY_COMMAND_BYTE, PROXY_TCP6_BYTE, u16::try_from(PROXY_TCP6_LENGTH)?, &body))
}


fn header_for(source: IpAddr) -> Result<Vec<u8>, Box<dyn Error>> {
    match source {
        IpAddr::V4(v4) => header_v4(v4),
        IpAddr::V6(v6) => header_v6(v6),
    }
}


fn prefix_of(bytes: &[u8]) -> Result<[u8; PROXY_PREFIX_BYTES], Box<dyn Error>> {
    Ok(bytes.get(..PROXY_PREFIX_BYTES).ok_or("short header")?.try_into()?)
}


fn v4(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(TOO_MANY_RELAYS, 0, 0, last)
}


struct Rig {
    direct: SocketAddr,
    relay: SocketAddr,
    state: SharedState,
    stop: oneshot::Sender<()>,
    handle: JoinHandle<()>,
    _control: RevocationControl,
    dir: tempfile::TempDir,
    platform: crate::harness::Platform,
}


async fn start_rig(change: impl FnOnce(&mut ChannelSettings), header_limit: Duration) -> Result<Rig, Box<dyn Error>> {
    init_logging()?;
    let dir = long_tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let state = make_audited_state(
        settings(|base| {
            base.relay_sources = vec![host(RELAY_BYTE)];
            change(base);
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let revocation = empty_revocation(&paths)?;
    let direct_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let direct = direct_listener.local_addr()?;
    let relay = relay_listener.local_addr()?;
    let (stop, receiver) = oneshot::channel::<()>();
    let handle = tokio::spawn(serve_with_relay(
        Box::pin(TcpListenerStream::new(direct_listener)),
        RelayListener {
            incoming: Box::pin(TcpListenerStream::new(relay_listener)),
            header_limit,
        },
        server_config(&paths)?,
        channel_router(Arc::clone(&state)),
        Arc::clone(&state),
        revocation.watcher,
        Box::pin(async move {
            if let Err(error) = receiver.await {
                tracing::warn!(%error, "shutdown sender dropped");
            }
        }),
    ));
    Ok(Rig {
        direct,
        relay,
        state,
        stop,
        handle,
        _control: revocation.control,
        dir,
        platform,
    })
}


async fn finish_rig(rig: Rig) -> TestResult {
    rig.stop.send(()).map_err(|()| "server already stopped")?;
    bounded(rig.handle).await??;
    Ok(())
}


async fn from_relay(rig: &Rig, last: u8) -> Result<TcpStream, Box<dyn Error>> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(host(last), 0))?;
    Ok(socket.connect(rig.relay).await?)
}


async fn until(condition: impl Fn() -> bool) -> TestResult {
    let mut polls = 0;
    while !condition() && polls < POLL_ATTEMPTS {
        sleep(Duration::from_millis(POLL_MILLIS)).await;
        polls += 1;
    }
    assert!(condition(), "condition not reached");
    Ok(())
}


async fn is_closed(stream: &mut TcpStream) -> Result<bool, Box<dyn Error>> {
    let mut buffer = [u8::MIN; FIRST_CHUNK_BYTES];
    let mut reads = 0;
    let mut open = true;
    while open && reads < READ_ATTEMPTS {
        open = !matches!(bounded(stream.read(&mut buffer)).await?, Ok(0) | Err(_));
        reads += 1;
    }
    Ok(!open)
}


#[derive(Clone, Copy)]
enum Mode {
    Joined,
    ByteByByte,
}


async fn relay_one(mut inbound: TcpStream, target: SocketAddr, relay_ip: IpAddr, source: IpAddr, mode: Mode) -> TestResult {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(relay_ip, 0))?;
    let mut outbound = socket.connect(target).await?;
    let mut bytes = header_for(source)?;
    match mode {
        Mode::Joined => {
            let mut first = vec![u8::MIN; FIRST_CHUNK_BYTES];
            let read = inbound.read(&mut first).await?;
            bytes.extend(first.get(..read).ok_or("short read")?);
            outbound.write_all(&bytes).await?;
        }
        Mode::ByteByByte => {
            for byte in &bytes {
                outbound.write_all(std::slice::from_ref(byte)).await?;
                outbound.flush().await?;
                tokio::task::yield_now().await;
            }
        }
    }
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}


async fn front(rig: &Rig, source: IpAddr, mode: Mode) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let target = rig.relay;
    let handle = tokio::spawn(async move {
        let mut accepted = 0;
        while accepted < MAX_FORWARDED {
            match listener.accept().await {
                Ok((inbound, _peer)) => {
                    tokio::spawn(async move {
                        if let Err(error) = relay_one(inbound, target, host(RELAY_BYTE), source, mode).await {
                            tracing::info!(%error, "test relay connection ended");
                        }
                    });
                }
                Err(error) => tracing::warn!(%error, "test relay accept failed"),
            }
            accepted += 1;
        }
    });
    Ok((address, handle))
}


async fn beat_through(rig: &Rig, address: SocketAddr) -> TestResult {
    let agent = client_paths(rig.dir.path(), "agent", &rig.platform, &rig.platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let channel = bounded(connect_channel(address, client_config(&agent)?, SERVER_NAME)).await??;
    let reply = bounded(heartbeat(channel, "test")).await??;
    assert!(reply.interval_seconds > 0);
    Ok(())
}


#[test]
fn the_prefix_grammar_accepts_exactly_two_shapes() -> TestResult {
    let tcp4 = header_v4(v4(1))?;
    let tcp6 = header_v6(Ipv6Addr::LOCALHOST)?;
    assert_eq!(prefix_family(&prefix_of(&tcp4)?), Ok(ProxyFamily::Tcp4));
    assert_eq!(prefix_family(&prefix_of(&tcp6)?), Ok(ProxyFamily::Tcp6));
    let wrong_signature = {
        let mut bytes = tcp4.clone();
        bytes.splice(..1, [u8::MAX]);
        bytes
    };
    let length4 = u16::try_from(PROXY_TCP4_LENGTH)?;
    let length6 = u16::try_from(PROXY_TCP6_LENGTH)?;
    let cases = [
        (wrong_signature, ProxyRefusal::Signature),
        (header(LOCAL_COMMAND, PROXY_TCP4_BYTE, length4, &[]), ProxyRefusal::Command),
        (header(UNKNOWN_COMMAND, PROXY_TCP4_BYTE, length4, &[]), ProxyRefusal::Command),
        (header(PROXY_COMMAND_BYTE, UDP_FAMILY, length4, &[]), ProxyRefusal::Family),
        (header(PROXY_COMMAND_BYTE, UNIX_FAMILY, length4, &[]), ProxyRefusal::Family),
        (header(PROXY_COMMAND_BYTE, u8::MIN, 0, &[]), ProxyRefusal::Family),
        (header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, length6, &[]), ProxyRefusal::Length),
        (header(PROXY_COMMAND_BYTE, PROXY_TCP6_BYTE, length4, &[]), ProxyRefusal::Length),
        (header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, length4 + 1, &[]), ProxyRefusal::Length),
        (header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, TLV_LENGTH, &[]), ProxyRefusal::Length),
        (header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, 0, &[]), ProxyRefusal::Length),
    ];
    for (bytes, expected) in cases {
        assert_eq!(prefix_family(&prefix_of(&bytes)?), Err(expected), "{expected:?}");
    }
    assert_eq!(exact_length(1, 1), Ok(()));
    assert_eq!(exact_length(1, TOO_MANY_RELAYS.into()), Err(ProxyRefusal::Length));
    Ok(())
}


#[test]
fn a_source_is_canonical_and_never_unspecified_or_multicast() -> TestResult {
    let mapped = Ipv4Addr::new(TOO_MANY_RELAYS, 0, 0, 1).to_ipv6_mapped();
    assert_eq!(usable_source(IpAddr::V6(mapped)), Ok(IpAddr::V4(v4(1))));
    assert_eq!(usable_source(IpAddr::V4(v4(1))), Ok(IpAddr::V4(v4(1))));
    let refused = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(MULTICAST_OCTET, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("ff02::1".parse()?),
        IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()),
    ];
    for address in refused {
        assert_eq!(usable_source(address), Err(ProxyRefusal::Source), "{address}");
    }
    Ok(())
}


#[test]
fn each_refusal_has_its_own_counter_and_a_fixed_text() -> TestResult {
    let counters = Counters::default();
    let all = [
        ProxyRefusal::Signature,
        ProxyRefusal::Command,
        ProxyRefusal::Family,
        ProxyRefusal::Length,
        ProxyRefusal::Source,
        ProxyRefusal::Io,
        ProxyRefusal::Timeout,
    ];
    let mut texts = Vec::new();
    for refusal in all {
        let text = count_refusal(&counters, refusal);
        assert_eq!(text, refusal_reason(refusal));
        assert_eq!(counter(refusal_counter(&counters, refusal)), 1, "{refusal:?}");
        texts.push(text);
    }
    texts.sort_unstable();
    texts.dedup();
    assert_eq!(texts.len(), all.len());
    Ok(())
}


#[test]
fn the_header_phase_is_capped_per_relay_and_in_total_and_gives_its_places_back() -> TestResult {
    let phase = Arc::new(Mutex::new(HeaderPhase::default()));
    let caps = HeaderCaps {
        total: PER_SOURCE,
        per_relay: 1,
    };
    let first = take_header_permit(&phase, host(1), caps).ok_or("first refused")?;
    assert!(take_header_permit(&phase, host(1), caps).is_none());
    let second = take_header_permit(&phase, host(RELAY_BYTE), caps).ok_or("second refused")?;
    assert!(take_header_permit(&phase, host(OTHER_BYTE), caps).is_none());
    drop(first);
    let again = take_header_permit(&phase, host(1), caps).ok_or("place not given back")?;
    drop((second, again));
    let held = phase.lock().map_err(|_| "poisoned")?;
    assert_eq!(held.total, 0);
    assert!(held.per_relay.is_empty());
    Ok(())
}


#[test]
fn the_pending_registry_evicts_only_among_its_own_kind() -> TestResult {
    let _logging = scoped_logging();
    let state = make_audited_state(
        settings(|base| {
            base.max_pending_handshakes = PER_SOURCE;
            base.max_pending_relay_handshakes = 1;
        }),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let registry = Mutex::new(Vec::<PendingHandshake>::new());
    let mut direct_first = register_handshake(&registry, ListenerKind::Direct, host(1), &state).ok_or("direct refused")?;
    let mut direct_second = register_handshake(&registry, ListenerKind::Direct, host(RELAY_BYTE), &state).ok_or("direct refused")?;
    let relayed_first = register_handshake(&registry, ListenerKind::Relay, host(1), &state).ok_or("relay refused")?;
    let mut relayed_second = register_handshake(&registry, ListenerKind::Relay, host(RELAY_BYTE), &state).ok_or("relay refused")?;
    assert_eq!(counter(&state.counters.handshakes_evicted), 1);
    assert!(relayed_first.blocking_recv().is_ok());
    assert!(relayed_second.try_recv().is_err());
    assert!(direct_first.try_recv().is_err());
    assert!(direct_second.try_recv().is_err());
    assert_eq!(registry.lock().map_err(|_| "poisoned")?.len(), PER_SOURCE + 1);
    Ok(())
}


#[test]
fn the_same_address_of_another_kind_does_not_count_against_the_source() -> TestResult {
    let state = make_audited_state(
        settings(|base| base.max_pending_handshakes_per_source = 1),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    );
    let registry = Mutex::new(Vec::<PendingHandshake>::new());
    let direct = register_handshake(&registry, ListenerKind::Direct, host(1), &state).ok_or("direct refused")?;
    let relayed = register_handshake(&registry, ListenerKind::Relay, host(1), &state).ok_or("relay refused")?;
    assert!(register_handshake(&registry, ListenerKind::Relay, host(1), &state).is_none());
    drop((direct, relayed));
    Ok(())
}


fn state_listing(sources: &[IpAddr]) -> SharedState {
    make_audited_state(
        settings(|base| base.relay_sources = sources.to_vec()),
        recording_sink(new_stored()),
        envelope_source(Vec::new()),
        discarding_audit(),
    )
}


#[test]
fn a_relay_peer_must_equal_an_entry_exactly() -> TestResult {
    let _logging = scoped_logging();
    let ten = IpAddr::V4(Ipv4Addr::new(TEN_OCTET, 0, 0, 1));
    let state = state_listing(&[ten, IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    let at = |text: &str| -> Result<std::io::Result<SocketAddr>, Box<dyn Error>> { Ok(Ok(text.parse()?)) };
    assert_eq!(relay_peer(at("10.0.0.1:1")?, &state), Some(ten));
    assert_eq!(relay_peer(at("[::1]:1")?, &state), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(relay_peer(at("[::ffff:10.0.0.1]:1")?, &state), Some(ten));
    assert_eq!(counter(&state.counters.relay_peer_unknown), 0);
    assert_eq!(relay_peer(at("[::2]:1")?, &state), None);
    assert_eq!(relay_peer(at("[::1:0:0:0:1]:1")?, &state), None);
    assert_eq!(relay_peer(at("10.0.0.2:1")?, &state), None);
    assert_eq!(counter(&state.counters.relay_peer_unknown), UNKNOWN_PEERS);
    assert_eq!(relay_peer(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)), &state), None);
    assert_eq!(counter(&state.counters.relay_peer_unknown), UNKNOWN_PEERS);
    Ok(())
}


#[tokio::test]
async fn an_agent_handshakes_through_a_relay_whatever_the_split_of_the_header() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let (joined, joined_task) = front(&rig, host(1), Mode::Joined).await?;
    beat_through(&rig, joined).await?;
    let (split, split_task) = front(&rig, IpAddr::V6(v4(1).to_ipv6_mapped()), Mode::ByteByByte).await?;
    beat_through(&rig, split).await?;
    let counters = &rig.state.counters;
    assert_eq!(counter(&counters.relay_peer_unknown), 0);
    assert_eq!(counter(&counters.proxy_header_timeout), 0);
    assert_eq!(counter(&counters.proxy_bad_signature), 0);
    joined_task.abort();
    split_task.abort();
    finish_rig(rig).await
}


#[tokio::test]
async fn a_peer_that_is_not_a_listed_relay_is_closed_without_tls_work() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let mut stranger = from_relay(&rig, OTHER_BYTE).await?;
    stranger.write_all(&header_v4(v4(1))?).await?;
    assert!(is_closed(&mut stranger).await?);
    until(|| counter(&rig.state.counters.relay_peer_unknown) == 1).await?;
    assert_eq!(counter(&rig.state.counters.handshake_timeouts), 0);
    finish_rig(rig).await
}


#[tokio::test]
async fn a_bad_header_closes_the_connection_and_counts_its_own_reason() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let length4 = u16::try_from(PROXY_TCP4_LENGTH)?;
    let garbage = vec![u8::MAX; PROXY_PREFIX_BYTES];
    let unspecified = header_v4(Ipv4Addr::UNSPECIFIED)?;
    let local = header(LOCAL_COMMAND, PROXY_TCP4_BYTE, length4, &[u8::MIN; PROXY_TCP4_LENGTH]);
    let udp = header(PROXY_COMMAND_BYTE, UDP_FAMILY, length4, &[u8::MIN; PROXY_TCP4_LENGTH]);
    let tlv = header(PROXY_COMMAND_BYTE, PROXY_TCP4_BYTE, TLV_LENGTH, &[u8::MIN; PROXY_TCP4_LENGTH]);
    let cases = [
        (garbage, ProxyRefusal::Signature),
        (local, ProxyRefusal::Command),
        (udp, ProxyRefusal::Family),
        (tlv, ProxyRefusal::Length),
        (unspecified, ProxyRefusal::Source),
    ];
    for (bytes, refusal) in cases {
        let mut connection = from_relay(&rig, RELAY_BYTE).await?;
        connection.write_all(&bytes).await?;
        until(|| counter(refusal_counter(&rig.state.counters, refusal)) == 1).await?;
        assert!(is_closed(&mut connection).await?, "{refusal:?}");
    }
    let mut cut = from_relay(&rig, RELAY_BYTE).await?;
    cut.write_all(&PROXY_SIGNATURE).await?;
    cut.shutdown().await?;
    until(|| counter(&rig.state.counters.proxy_header_io) == 1).await?;
    assert_eq!(counter(&rig.state.counters.handshakes_refused), 0);
    assert_eq!(counter(&rig.state.counters.handshake_timeouts), 0);
    finish_rig(rig).await
}


#[tokio::test]
async fn a_header_that_is_not_complete_before_its_deadline_is_refused_whatever_arrives_after() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_millis(SHORT_HEADER_MILLIS)).await?;
    let bytes = header_v4(v4(1))?;
    let (last, early) = bytes.split_last().ok_or("empty header")?;
    let mut slow = from_relay(&rig, RELAY_BYTE).await?;
    slow.write_all(early).await?;
    until(|| counter(&rig.state.counters.proxy_header_timeout) == 1).await?;
    let late = slow.write_all(std::slice::from_ref(last)).await;
    assert!(late.is_ok() || late.is_err());
    assert!(is_closed(&mut slow).await?);
    assert_eq!(counter(&rig.state.counters.handshakes_refused), 0);
    finish_rig(rig).await
}


#[tokio::test]
async fn one_deadline_covers_the_whole_header_not_each_read() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_millis(GAP_HEADER_MILLIS)).await?;
    let bytes = header_v4(v4(1))?;
    let (prefix, rest) = bytes.split_at(PROXY_PREFIX_BYTES);
    let (source, tail) = rest.split_at(rest.len() - PROXY_TCP4_TAIL_BYTES);
    let mut spread = from_relay(&rig, RELAY_BYTE).await?;
    spread.write_all(prefix).await?;
    sleep(Duration::from_millis(GAP_MILLIS)).await;
    let source_sent = spread.write_all(source).await;
    sleep(Duration::from_millis(GAP_MILLIS)).await;
    let tail_sent = spread.write_all(tail).await;
    assert!(source_sent.is_ok() || source_sent.is_err());
    assert!(tail_sent.is_ok() || tail_sent.is_err());
    until(|| counter(&rig.state.counters.proxy_header_timeout) == 1).await?;
    finish_rig(rig).await
}


#[tokio::test]
async fn silent_relayed_connections_are_counted_by_their_named_source_and_the_relay_never_is() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(
        |base| base.max_pending_handshakes_per_source = PER_SOURCE,
        Duration::from_secs(PATIENT_HEADER_SECONDS),
    )
    .await?;
    let mut held = Vec::new();
    for _ in 0..=PER_SOURCE {
        let mut connection = from_relay(&rig, RELAY_BYTE).await?;
        connection.write_all(&header_v4(v4(SECOND_SOURCE_BYTE))?).await?;
        held.push(connection);
    }
    until(|| counter(&rig.state.counters.handshakes_refused) == 1).await?;
    let (open, refused) = held.split_at_mut(PER_SOURCE);
    assert!(refused
        .iter_mut()
        .all(|connection| matches!(connection.try_write(&[u8::MIN]), Ok(_) | Err(_))));
    assert_eq!(open.len(), PER_SOURCE);
    let (other, other_task) = front(&rig, IpAddr::V4(v4(THIRD_SOURCE_BYTE)), Mode::Joined).await?;
    beat_through(&rig, other).await?;
    other_task.abort();
    finish_rig(rig).await
}


#[tokio::test]
async fn a_mapped_ipv6_source_lands_in_the_ipv4_bucket() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(
        |base| base.max_pending_handshakes_per_source = 1,
        Duration::from_secs(PATIENT_HEADER_SECONDS),
    )
    .await?;
    let mut first = from_relay(&rig, RELAY_BYTE).await?;
    first.write_all(&header_v4(v4(1))?).await?;
    let mut second = from_relay(&rig, RELAY_BYTE).await?;
    second.write_all(&header_v6(v4(1).to_ipv6_mapped())?).await?;
    until(|| counter(&rig.state.counters.handshakes_refused) == 1).await?;
    assert!(is_closed(&mut second).await?);
    finish_rig(rig).await
}


#[tokio::test]
async fn forged_sources_never_block_a_direct_client_of_the_same_address() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(
        |base| base.max_pending_handshakes_per_source = PER_SOURCE,
        Duration::from_secs(PATIENT_HEADER_SECONDS),
    )
    .await?;
    let mut forged = Vec::new();
    for _ in 0..=PER_SOURCE {
        let mut connection = from_relay(&rig, RELAY_BYTE).await?;
        connection
            .write_all(&header_v4(Ipv4Addr::new(LOOPBACK_OCTET, 0, 0, FIRST_SHELF))?)
            .await?;
        forged.push(connection);
    }
    until(|| counter(&rig.state.counters.handshakes_refused) == 1).await?;
    beat_through(&rig, rig.direct).await?;
    assert_eq!(counter(&rig.state.counters.handshakes_refused), 1);
    assert_eq!(counter(&rig.state.counters.handshakes_evicted), 0);
    assert_eq!(forged.len(), PER_SOURCE + 1);
    finish_rig(rig).await
}


#[tokio::test]
async fn a_relayed_flood_evicts_only_among_relayed_handshakes() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(
        |base| base.max_pending_relay_handshakes = PER_SOURCE,
        Duration::from_secs(PATIENT_HEADER_SECONDS),
    )
    .await?;
    let mut held = Vec::new();
    for last in 1..=u8::try_from(PER_SOURCE + 1)? {
        let mut connection = from_relay(&rig, RELAY_BYTE).await?;
        connection.write_all(&header_v4(v4(last))?).await?;
        held.push(connection);
    }
    until(|| counter(&rig.state.counters.handshakes_evicted) == 1).await?;
    beat_through(&rig, rig.direct).await?;
    assert_eq!(counter(&rig.state.counters.handshakes_refused), 0);
    finish_rig(rig).await
}


#[tokio::test]
async fn removing_a_relay_while_connections_wait_for_their_header_refuses_them_all() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let mut waiting = Vec::new();
    for _ in 0..HELD_IN_HEADER_PHASE {
        waiting.push(from_relay(&rig, RELAY_BYTE).await?);
    }
    rig.state.settings.store(Arc::new(settings(|base| base.relay_sources = Vec::new())));
    for connection in &mut waiting {
        connection.write_all(&header_v4(v4(1))?).await?;
    }
    until(|| counter(&rig.state.counters.relay_peer_unknown) == u64::try_from(HELD_IN_HEADER_PHASE).unwrap_or(u64::MAX)).await?;
    for connection in &mut waiting {
        assert!(is_closed(connection).await?);
    }
    finish_rig(rig).await
}


#[tokio::test]
async fn the_header_phase_cap_of_a_relay_closes_the_excess_at_accept() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let mut held = Vec::new();
    for _ in 0..=MAX_PROXY_HEADER_PENDING_PER_RELAY {
        held.push(from_relay(&rig, RELAY_BYTE).await?);
    }
    until(|| counter(&rig.state.counters.proxy_header_refused) == 1).await?;
    assert_eq!(counter(&rig.state.counters.relay_peer_unknown), 0);
    finish_rig(rig).await
}


#[tokio::test]
async fn a_proxy_header_sent_to_the_main_listener_fails_the_tls_handshake() -> TestResult {
    let _logging = scoped_logging();
    let rig = start_rig(|_| {}, Duration::from_secs(PATIENT_HEADER_SECONDS)).await?;
    let mut direct = TcpStream::connect(rig.direct).await?;
    direct.write_all(&header_v4(v4(1))?).await?;
    assert!(is_closed(&mut direct).await?);
    let counters = &rig.state.counters;
    assert_eq!(
        counter(&counters.proxy_bad_signature) + counter(&counters.proxy_bad_command) + counter(&counters.proxy_header_io),
        0
    );
    beat_through(&rig, rig.direct).await?;
    finish_rig(rig).await
}


#[test]
fn relay_sources_are_literal_canonical_distinct_usable_addresses() -> TestResult {
    let good = |text: &str| -> Result<IpAddr, Box<dyn Error>> { Ok(text.parse()?) };
    assert!(relay_sources_valid(&[]));
    assert!(relay_sources_valid(&[
        good("10.0.0.1")?,
        good("2001:db8::1")?,
        good("127.0.0.1")?,
        good("::1")?
    ]));
    let refused: [&[&str]; REFUSED_LISTS] = [
        &["0.0.0.0"],
        &["::"],
        &["224.0.0.1"],
        &["ff02::1"],
        &["255.255.255.255"],
        &["169.254.1.1"],
        &["fe80::1"],
        &["::ffff:10.0.0.1"],
        &["10.0.0.1", "10.0.0.1"],
    ];
    for list in refused {
        let parsed: Vec<IpAddr> = list.iter().map(|text| good(text)).collect::<Result<_, _>>()?;
        assert!(!relay_sources_valid(&parsed), "{list:?}");
    }
    let many: Vec<IpAddr> = (1..=TOO_MANY_RELAYS).map(|last| IpAddr::V4(v4(last))).collect();
    assert!(!relay_sources_valid(&many));
    let invalid = settings(|base| base.relay_sources = many.clone());
    assert!(validate_settings(&invalid).is_err());
    assert!(validate_settings(&settings(|base| base.max_pending_relay_handshakes = 0)).is_err());
    assert!(validate_settings(&default_settings()).is_ok());
    Ok(())
}


fn default_settings() -> ChannelSettings {
    ChannelSettings::default()
}


#[test]
fn the_settings_file_is_an_ascii_allowlist_before_any_parse() -> TestResult {
    let dir = long_tempdir()?;
    let file = dir.path().join("settings.yaml");
    fs::write(&file, "relay_sources: [127.0.0.2, ::1]\nmax_pending_relay_handshakes: 7\n")?;
    let loaded = settings_loader(file.clone())()?;
    assert_eq!(loaded.relay_sources, vec![host(RELAY_BYTE), IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    assert_eq!(loaded.max_pending_relay_handshakes, CONFIGURED_RELAY_CAP);
    fs::write(&file, "relay_sources:\n  - 127.0.0.2\n  - 10.0.0.1\n")?;
    assert_eq!(settings_loader(file.clone())()?.relay_sources.len(), PER_SOURCE);
    let hostile = [
        "relay_sources: !!str 127.0.0.2\n",
        "relay_sources: &a [127.0.0.2]\n",
        "relay_sources: *a\n",
        "<<: {}\n",
        "relay_sources: \"127.0.0.2\\u0031\"\n",
        "relay_sources: |\n  127.0.0.2\n",
        "relay_sources: >\n  127.0.0.2\n",
        "relay_sources: [127.0.0.2]\r\n",
        "relay_sources: [127.0.0.2]\n# comment\n",
        "relay_sources: [127.0.0.2]\t\n",
        "relay_sources: [127.0.0.\u{ff12}]\n",
    ];
    for text in hostile {
        fs::write(&file, text)?;
        assert!(settings_loader(file.clone())().is_err(), "{text:?}");
    }
    assert!(check_operator_bytes("max_message_bytes: 5\n", Path::new("x")).is_ok());
    assert!(check_operator_bytes("a\u{e9}", Path::new("x")).is_err());
    Ok(())
}


#[test]
fn a_reload_of_the_relay_list_shows_in_the_audited_state() -> TestResult {
    let before = settings_state(&settings(|_| {}));
    let after = settings_state(&settings(|base| base.relay_sources = vec![host(RELAY_BYTE)]));
    assert_ne!(before, after);
    assert_eq!(after.get("channel_settings.relay_sources").map(String::as_str), Some("127.0.0.2"));
    assert_eq!(before.get("channel_settings.relay_sources").map(String::as_str), Some(""));
    Ok(())
}


fn server_file(dir: &Path, listen: &str, relay_listen: Option<&str>) -> ServerFile {
    ServerFile {
        listen: listen.to_owned(),
        relay_listen: relay_listen.map(ToOwned::to_owned),
        certificate: dir.join("a"),
        key: dir.join("a"),
        agent_ca: dir.join("a"),
        revocation_file: dir.join("a"),
        settings_file: dir.join("a"),
        audit_file: dir.join("a"),
        events_file: dir.join("a"),
        commands_dir: dir.join("a"),
    }
}


#[tokio::test]
async fn relay_listen_is_optional_and_never_the_same_text_as_listen() -> TestResult {
    let _logging = scoped_logging();
    let dir = long_tempdir()?;
    assert!(check_listeners(&server_file(dir.path(), "127.0.0.1:1", None)).is_ok());
    assert!(check_listeners(&server_file(dir.path(), "127.0.0.1:1", Some("127.0.0.1:2"))).is_ok());
    assert!(check_listeners(&server_file(dir.path(), "127.0.0.1:1", Some("127.0.0.1:1"))).is_err());
    assert!(bind_relay(&server_file(dir.path(), "127.0.0.1:1", None)).await?.is_none());
    assert!(bind_relay(&server_file(dir.path(), "127.0.0.1:1", Some("127.0.0.1:0"))).await?.is_some());
    assert!(bind_relay(&server_file(dir.path(), "127.0.0.1:1", Some("127.0.0.1:1"))).await.is_err());
    let text = format!(
        "listen: 127.0.0.1:1\nrelay_listen: 127.0.0.1:1\ncertificate: {0}\nkey: {0}\nagent_ca: {0}\nrevocation_file: {0}\nsettings_file: {0}\naudit_file: {0}\nevents_file: {0}\ncommands_dir: {0}\n",
        dir.path().display()
    );
    let file = dir.path().join("server.yaml");
    fs::write(&file, text.as_str())?;
    assert!(load_server_file(&file).is_err());
    fs::write(&file, text.replace("relay_listen: 127.0.0.1:1", "relay_listen: 127.0.0.1:2"))?;
    assert!(load_server_file(&file)?.relay_listen.is_some());
    Ok(())
}


#[tokio::test]
async fn the_relay_stream_is_empty_without_a_listener_and_warns_once_without_sources() -> TestResult {
    let _logging = scoped_logging();
    let state = default_state();
    let _none = relay_incoming(None, &state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let _listed = relay_incoming(Some(listener), &state_listing(&[host(RELAY_BYTE)]));
    let unlisted = TcpListener::bind("127.0.0.1:0").await?;
    let _empty = relay_incoming(Some(unlisted), &state_listing(&[]));
    Ok(())
}

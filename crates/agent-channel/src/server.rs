use crate::error::{error_class, serve_kind, ChannelError, IdentityError};
use crate::identity::{identity_from_chain, serials_from_chain};
use crate::limits::{bounded_text, bump, open_slot};
use crate::model::{
    Admission, ChannelSettings, HeaderPermit, HeaderPhase, Identity, ListenerKind, PendingHandshake, RelayListener, ServerState, Serving, SlotKind,
    IPV6_HOST_BITS, MAX_PROXY_HEADER_PENDING, MAX_PROXY_HEADER_PENDING_PER_RELAY, PROXY_HEADER_SECONDS, SERVER_KEEPALIVE_INTERVAL_SECONDS,
    SERVER_KEEPALIVE_TIMEOUT_SECONDS, TCP_KEEPALIVE_IDLE_SECONDS, TCP_KEEPALIVE_INTERVAL_SECONDS,
};
use crate::proxy::{count_refusal, read_proxy_header, take_header_permit, HeaderCaps};
use crate::revocation::{revoked_in, revoked_now};
use crate::settings::{resize_total, settings_of};
use crate::types::{IncomingConnections, RevocationWatch, SharedServerConfig, SharedState, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::{FutureExt, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use socket2::{SockRef, TcpKeepalive};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Notify, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;


/// Accepts connections until `shutdown` completes; handshakes are capped per source and globally, authenticated connections are capped apart.
pub async fn serve(
    incoming: IncomingConnections,
    config: SharedServerConfig,
    router: Router,
    state: SharedState,
    revocations: RevocationWatch,
    shutdown: ShutdownSignal,
) {
    let relay = RelayListener {
        incoming: Box::pin(tokio_stream::empty()),
        header_limit: Duration::from_secs(PROXY_HEADER_SECONDS),
    };
    serve_with_relay(incoming, relay, config, router, state, revocations, shutdown).await;
}


/// `serve` with a second listener whose connections must open with a PROXY v2 header naming their source; one loop, one total cap.
pub async fn serve_with_relay(
    incoming: IncomingConnections,
    relay: RelayListener,
    config: SharedServerConfig,
    router: Router,
    state: SharedState,
    revocations: RevocationWatch,
    shutdown: ShutdownSignal,
) {
    let initial = settings_of(&state).max_total_connections;
    let serving = Serving {
        acceptor: TlsAcceptor::from(config),
        router,
        state,
        revocations,
        connections: Arc::new(Semaphore::new(initial)),
        registry: Arc::new(Mutex::new(Vec::new())),
        phase: Arc::new(Mutex::new(HeaderPhase::default())),
        header_limit: relay.header_limit,
    };
    let mut capacity = initial;
    let tagged = futures_util::stream::select(
        incoming.map(|accepted| (ListenerKind::Direct, accepted)),
        relay.incoming.map(|accepted| (ListenerKind::Relay, accepted)),
    );
    tagged
        .take_until(shutdown)
        .for_each(|(kind, accepted)| {
            match accepted {
                Ok(stream) => {
                    capacity = resize_total(&serving.connections, capacity, settings_of(&serving.state).max_total_connections);
                    admit(&serving, kind, stream, capacity);
                }
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
            std::future::ready(())
        })
        .await;
}


/// Routes an accepted stream to the direct or the relay path.
pub fn admit(serving: &Serving, kind: ListenerKind, stream: TcpStream, capacity: usize) {
    match kind {
        ListenerKind::Direct => admit_direct(serving, stream, capacity),
        ListenerKind::Relay => admit_relay(serving, stream, capacity),
    }
}


pub fn admit_direct(serving: &Serving, stream: TcpStream, capacity: usize) {
    let source = peer_source(stream.peer_addr());
    let evicted = source.and_then(|known| register_handshake(&serving.registry, ListenerKind::Direct, known, &serving.state));
    if let Some(signal) = evicted {
        let admission = admission_of(serving, capacity, signal);
        let connection = run_connection(
            stream,
            serving.acceptor.clone(),
            serving.router.clone(),
            Arc::clone(&serving.state),
            serving.revocations.clone(),
            admission,
        );
        tokio::spawn(connection.map(log_outcome));
    }
}


pub fn admission_of(serving: &Serving, capacity: usize, evicted: oneshot::Receiver<()>) -> Admission {
    Admission {
        connections: Arc::clone(&serving.connections),
        capacity,
        evicted,
    }
}


/// Relay listener: the peer must be a listed relay and must get a place in the header phase before any task is spawned.
pub fn admit_relay(serving: &Serving, stream: TcpStream, capacity: usize) {
    let relay = relay_peer(stream.peer_addr(), &serving.state);
    let permit = relay.and_then(|address| header_permit(serving, address));
    if let (Some(address), Some(held)) = (relay, permit) {
        let connection = run_relay_connection(stream, address, held, serving.clone(), capacity);
        tokio::spawn(connection.map(log_outcome));
    }
}


/// The canonical address of an accepted relay peer when it equals one `relay_sources` entry exactly (no folding), else counted and dropped.
pub fn relay_peer(peer: io::Result<SocketAddr>, state: &ServerState) -> Option<IpAddr> {
    let known = peer
        .map(|address| address.ip().to_canonical())
        .map_err(|error| tracing::warn!(%error, "relay peer address unknown"));
    known.ok().filter(|address| is_listed_relay(state, *address))
}


pub fn is_listed_relay(state: &ServerState, address: IpAddr) -> bool {
    let listed = settings_of(state).relay_sources.contains(&address);
    if !listed {
        bump(&state.counters.relay_peer_unknown);
        tracing::debug!("peer of the relay listener is not a listed relay, connection closed");
    }
    listed
}


pub fn header_permit(serving: &Serving, relay: IpAddr) -> Option<HeaderPermit> {
    let caps = HeaderCaps {
        total: MAX_PROXY_HEADER_PENDING,
        per_relay: MAX_PROXY_HEADER_PENDING_PER_RELAY,
    };
    let permit = take_header_permit(&serving.phase, relay, caps);
    if permit.is_none() {
        bump(&serving.state.counters.proxy_header_refused);
        tracing::debug!("relay header phase at its cap, connection closed");
    }
    permit
}


/// Header under one deadline, then the allowlist again on a fresh snapshot, then the pending-handshake registry under the named source.
pub async fn run_relay_connection(
    mut stream: TcpStream,
    relay: IpAddr,
    permit: HeaderPermit,
    serving: Serving,
    capacity: usize,
) -> Result<(), ChannelError> {
    let header = read_proxy_header(&mut stream, serving.header_limit).await;
    drop(permit);
    let announced = header.map_err(|refusal| ChannelError::RelayRefused {
        reason: count_refusal(&serving.state.counters, refusal),
    })?;
    if !is_listed_relay(&serving.state, relay) {
        Err(ChannelError::RelayRefused {
            reason: "relay removed from relay_sources",
        })?;
    }
    let evicted =
        register_handshake(&serving.registry, ListenerKind::Relay, source_of(announced), &serving.state).ok_or(ChannelError::RelayRefused {
            reason: "pending handshake cap of the source",
        })?;
    let admission = admission_of(&serving, capacity, evicted);
    run_connection(stream, serving.acceptor, serving.router, serving.state, serving.revocations, admission).await
}


/// The address a handshake is counted against: IPv4 as is, IPv6 folded to its /64, IPv4-mapped IPv6 as IPv4.
pub fn source_of(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << IPV6_HOST_BITS))),
        other => other,
    }
}


/// The folded source of an accepted connection; a connection whose peer address cannot be read is dropped.
pub fn peer_source(peer: io::Result<SocketAddr>) -> Option<IpAddr> {
    match peer {
        Ok(address) => Some(source_of(address.ip())),
        Err(error) => {
            tracing::warn!(%error, "peer address unknown, connection dropped");
            None
        }
    }
}


/// No code holding the lock can panic, so a poisoned lock still guards consistent data.
pub fn lock_registry(registry: &Mutex<Vec<PendingHandshake>>) -> MutexGuard<'_, Vec<PendingHandshake>> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}


/// The total cap of the listener kind.
pub fn pending_cap(settings: &ChannelSettings, kind: ListenerKind) -> usize {
    match kind {
        ListenerKind::Direct => settings.max_pending_handshakes,
        ListenerKind::Relay => settings.max_pending_relay_handshakes,
    }
}


/// Notes a new handshake: `None` when its source is at its cap, else the oldest of the busiest source of the same kind is evicted at the kind's cap.
pub fn register_handshake(
    registry: &Mutex<Vec<PendingHandshake>>,
    kind: ListenerKind,
    source: IpAddr,
    state: &ServerState,
) -> Option<oneshot::Receiver<()>> {
    let settings = settings_of(state);
    let mut handshakes = lock_registry(registry);
    handshakes.retain(|waiting| !waiting.stop.is_closed());
    if handshakes
        .iter()
        .filter(|waiting| waiting.kind == kind && waiting.source == source)
        .count()
        >= settings.max_pending_handshakes_per_source
    {
        bump(&state.counters.handshakes_refused);
        tracing::debug!(%source, "pending handshake cap of the source reached, connection refused");
        None
    } else {
        if handshakes.iter().filter(|waiting| waiting.kind == kind).count() >= pending_cap(&settings, kind) {
            let victim = busiest_oldest(&handshakes, kind).map(|position| handshakes.remove(position).stop);
            evict(victim, state);
        }
        let (sender, receiver) = oneshot::channel();
        handshakes.push(PendingHandshake { kind, source, stop: sender });
        Some(receiver)
    }
}


/// Position of the oldest handshake of `kind` among those of the source holding the most.
pub fn busiest_oldest(handshakes: &[PendingHandshake], kind: ListenerKind) -> Option<usize> {
    let mut per_source: HashMap<IpAddr, usize> = HashMap::new();
    handshakes
        .iter()
        .filter(|waiting| waiting.kind == kind)
        .for_each(|waiting| *per_source.entry(waiting.source).or_insert(0) += 1);
    let busiest = per_source.values().max();
    handshakes
        .iter()
        .position(|waiting| waiting.kind == kind && per_source.get(&waiting.source) == busiest)
}


pub fn evict(oldest: Option<oneshot::Sender<()>>, state: &ServerState) {
    if let Some(sender) = oldest {
        bump(&state.counters.handshakes_evicted);
        if sender.send(()).is_err() {
            tracing::debug!("handshake finished while it was being evicted");
        }
    }
}


/// The TLS handshake, cut after `seconds` and when `evicted` fires; a dropped sender never evicts.
pub async fn handshake(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    state: &ServerState,
    seconds: u64,
    evicted: oneshot::Receiver<()>,
) -> Result<TlsStream<TcpStream>, ChannelError> {
    let limit = Duration::from_secs(seconds);
    let finished = tokio::select! {
        accepted = timeout(limit, acceptor.accept(stream)) => accepted.map_err(|_elapsed| handshake_timed_out(state, seconds)),
        Ok(()) = evicted => Err(ChannelError::HandshakeEvicted),
    };
    finished?.map_err(|error| ChannelError::Handshake(error_class(&error)))
}


/// Handshake, identity and serial from the certificate, then a total-cap permit and HTTP/2; ends as soon as the serial is revoked.
pub async fn run_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    router: Router,
    state: SharedState,
    revocations: RevocationWatch,
    admission: Admission,
) -> Result<(), ChannelError> {
    log_keepalive(set_keepalive(&stream));
    let settings = settings_of(&state);
    let tls = handshake(stream, acceptor, &state, settings.handshake_timeout_seconds, admission.evicted).await?;
    let identity = identity_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let serials = serials_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let revoked = revoked_now(&revocations, &serials);
    if revoked.is_empty() {
        let _total = admission
            .connections
            .try_acquire_owned()
            .map_err(|_refused| connection_capped(&state, settings.max_total_connections, admission.capacity))?;
        let _connection = open_slot(&state, &identity, SlotKind::Connection).map_err(|_refused| too_many_connections(&identity))?;
        let first_request = Arc::new(Notify::new());
        let noted = Arc::clone(&first_request);
        let service = router.layer(Extension(identity)).map_request(move |request| {
            noted.notify_one();
            request
        });
        let limit = Duration::from_secs(settings.first_request_timeout_seconds);
        let mut builder = Builder::new(TokioExecutor::new()).http2_only();
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(settings.max_streams_per_connection)
            .keep_alive_interval(Duration::from_secs(SERVER_KEEPALIVE_INTERVAL_SECONDS))
            .keep_alive_timeout(Duration::from_secs(SERVER_KEEPALIVE_TIMEOUT_SECONDS));
        tokio::select! {
            served = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(service)) => {
                served.map_err(|error| ChannelError::Serve(serve_kind(&*error)))
            }
            closed = watch_revocation(revocations, &serials) => Err(closed),
            late = first_request_deadline(&first_request, limit, &state) => Err(late),
        }
    } else {
        Err(refused_revoked(revoked.join(",")))
    }
}


/// Completes with `FirstRequestTimeout` when no request reached the service within `limit`; never completes once one did.
pub async fn first_request_deadline(first_request: &Notify, limit: Duration, state: &ServerState) -> ChannelError {
    match timeout(limit, first_request.notified()).await {
        Ok(()) => std::future::pending::<ChannelError>().await,
        Err(_elapsed) => {
            bump(&state.counters.first_request_timeouts);
            tracing::warn!(seconds = limit.as_secs(), "no HTTP/2 request after the handshake, connection dropped");
            ChannelError::FirstRequestTimeout { seconds: limit.as_secs() }
        }
    }
}


/// Keepalive probes on the accepted socket, so a silent peer is detected at every phase.
pub fn set_keepalive(stream: &TcpStream) -> io::Result<()> {
    SockRef::from(stream).set_tcp_keepalive(&keepalive_settings())
}


#[cfg(unix)]
pub fn keepalive_settings() -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECONDS))
        .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECONDS))
        .with_retries(crate::model::TCP_KEEPALIVE_RETRIES)
}


#[cfg(not(unix))]
pub fn keepalive_settings() -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECONDS))
        .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECONDS))
}


pub fn log_keepalive(outcome: io::Result<()>) {
    if let Err(error) = outcome {
        tracing::warn!(%error, "tcp keepalive not set");
    }
}


pub fn connection_capped(state: &ServerState, snapshot_limit: usize, limit: usize) -> ChannelError {
    bump(&state.counters.connections_capped);
    tracing::warn!(limit, snapshot_limit, "total connection cap reached, connection dropped");
    ChannelError::ConnectionCapped { limit }
}


pub fn handshake_timed_out(state: &ServerState, seconds: u64) -> ChannelError {
    bump(&state.counters.handshake_timeouts);
    ChannelError::HandshakeTimeout { seconds }
}


pub fn too_many_connections(identity: &Identity) -> ChannelError {
    ChannelError::TooManyConnections {
        tenant: identity.tenant.clone(),
        agent_id: identity.agent_id.clone(),
    }
}


pub fn refused_revoked(serial: String) -> ChannelError {
    tracing::warn!(%serial, "revoked agent certificate refused");
    ChannelError::Revoked { serial }
}


/// Completes with the reason as soon as a serial of `chain` is on the list, or when the list is no longer maintained.
pub async fn watch_revocation(mut revocations: RevocationWatch, chain: &[String]) -> ChannelError {
    let outcome = revocations
        .wait_for(|list| !revoked_in(list, chain).is_empty())
        .await
        .map(|list| revoked_in(&list, chain));
    match outcome {
        Ok(revoked) => refused_revoked(revoked.join(",")),
        Err(source) => ChannelError::RevocationClosed(source),
    }
}


pub fn refuse(error: IdentityError) -> ChannelError {
    let reason = bounded_text(&error.to_string());
    tracing::warn!(?reason, "client certificate refused");
    ChannelError::Identity(error)
}


/// These refusals were logged where they were decided, with bounded text.
pub fn already_logged(error: &ChannelError) -> bool {
    matches!(
        error,
        ChannelError::Identity(_)
            | ChannelError::FirstRequestTimeout { .. }
            | ChannelError::Revoked { .. }
            | ChannelError::TooManyConnections { .. }
            | ChannelError::ConnectionCapped { .. }
            | ChannelError::RelayRefused { .. }
    )
}


pub fn log_outcome(outcome: Result<(), ChannelError>) {
    match outcome {
        Err(error) if !already_logged(&error) => tracing::warn!(%error, "agent connection ended"),
        Err(_) | Ok(()) => (),
    }
}

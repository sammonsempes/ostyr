use crate::error::{ChannelError, IdentityError};
use crate::identity::{identity_from_chain, serials_from_chain};
use crate::limits::{bounded_text, bump, open_slot};
use crate::model::{
    Admission, Identity, PendingHandshake, ServerState, SlotKind, HANDSHAKE_TIMEOUT_SECONDS, IPV6_HOST_BITS, SERVER_KEEPALIVE_INTERVAL_SECONDS,
    SERVER_KEEPALIVE_TIMEOUT_SECONDS,
};
use crate::revocation::{revoked_in, revoked_now};
use crate::settings::{resize_total, settings_of};
use crate::types::{IncomingConnections, RevocationWatch, SharedServerConfig, SharedState, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::{FutureExt, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;


/// Accepts connections until `shutdown` completes; handshakes are capped per source and globally, authenticated connections are capped apart.
pub async fn serve(
    incoming: IncomingConnections,
    config: SharedServerConfig,
    router: Router,
    state: SharedState,
    revocations: RevocationWatch,
    shutdown: ShutdownSignal,
) {
    let acceptor = TlsAcceptor::from(config);
    let connections = Arc::new(Semaphore::new(settings_of(&state).max_total_connections));
    let mut capacity = settings_of(&state).max_total_connections;
    let mut handshakes = Vec::new();
    incoming
        .take_until(shutdown)
        .for_each(|accepted| {
            match accepted {
                Ok(stream) => {
                    capacity = resize_total(&connections, capacity, settings_of(&state).max_total_connections);
                    let source = peer_source(stream.peer_addr());
                    let evicted = source.and_then(|known| register_handshake(&mut handshakes, known, &state));
                    if let Some(signal) = evicted {
                        let admission = Admission {
                            connections: Arc::clone(&connections),
                            evicted: signal,
                        };
                        let connection = run_connection(
                            stream,
                            acceptor.clone(),
                            router.clone(),
                            Arc::clone(&state),
                            revocations.clone(),
                            admission,
                        );
                        tokio::spawn(connection.map(log_outcome));
                    }
                }
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
            std::future::ready(())
        })
        .await;
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


/// Notes a new handshake: `None` when its source is at its cap, else the oldest of the busiest source is evicted at the global cap.
pub fn register_handshake(handshakes: &mut Vec<PendingHandshake>, source: IpAddr, state: &ServerState) -> Option<oneshot::Receiver<()>> {
    let settings = settings_of(state);
    handshakes.retain(|waiting| !waiting.stop.is_closed());
    if handshakes.iter().filter(|waiting| waiting.source == source).count() >= settings.max_pending_handshakes_per_source {
        bump(&state.counters.handshakes_refused);
        tracing::debug!(%source, "pending handshake cap of the source reached, connection refused");
        None
    } else {
        if handshakes.len() >= settings.max_pending_handshakes {
            let victim = busiest_oldest(handshakes).map(|position| handshakes.remove(position).stop);
            evict(victim, state);
        }
        let (sender, receiver) = oneshot::channel();
        handshakes.push(PendingHandshake { source, stop: sender });
        Some(receiver)
    }
}


/// Position of the oldest handshake among those of the source holding the most.
pub fn busiest_oldest(handshakes: &[PendingHandshake]) -> Option<usize> {
    let mut per_source: HashMap<IpAddr, usize> = HashMap::new();
    handshakes.iter().for_each(|waiting| *per_source.entry(waiting.source).or_insert(0) += 1);
    let busiest = per_source.values().max();
    handshakes.iter().position(|waiting| per_source.get(&waiting.source) == busiest)
}


pub fn evict(oldest: Option<oneshot::Sender<()>>, state: &ServerState) {
    if let Some(sender) = oldest {
        bump(&state.counters.handshakes_evicted);
        if sender.send(()).is_err() {
            tracing::debug!("handshake finished while it was being evicted");
        }
    }
}


/// The TLS handshake, cut at `HANDSHAKE_TIMEOUT_SECONDS` and when `evicted` fires; a dropped sender never evicts.
pub async fn handshake(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    state: &ServerState,
    evicted: oneshot::Receiver<()>,
) -> Result<TlsStream<TcpStream>, ChannelError> {
    let limit = Duration::from_secs(HANDSHAKE_TIMEOUT_SECONDS);
    let finished = tokio::select! {
        accepted = timeout(limit, acceptor.accept(stream)) => accepted.map_err(|_elapsed| handshake_timed_out(state)),
        Ok(()) = evicted => Err(ChannelError::HandshakeEvicted),
    };
    finished?.map_err(ChannelError::Handshake)
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
    let tls = handshake(stream, acceptor, &state, admission.evicted).await?;
    let identity = identity_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let serials = serials_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let revoked = revoked_now(&revocations, &serials);
    if revoked.is_empty() {
        let _total = admission.connections.try_acquire_owned().map_err(|_refused| connection_capped(&state))?;
        let _connection = open_slot(&state, &identity, SlotKind::Connection).map_err(|_refused| too_many_connections(&identity))?;
        let service = router.layer(Extension(identity));
        let mut builder = Builder::new(TokioExecutor::new()).http2_only();
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(settings_of(&state).max_streams_per_connection)
            .keep_alive_interval(Duration::from_secs(SERVER_KEEPALIVE_INTERVAL_SECONDS))
            .keep_alive_timeout(Duration::from_secs(SERVER_KEEPALIVE_TIMEOUT_SECONDS));
        tokio::select! {
            served = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(service)) => {
                served.map_err(ChannelError::Serve)
            }
            closed = watch_revocation(revocations, &serials) => Err(closed),
        }
    } else {
        Err(refused_revoked(revoked.join(",")))
    }
}


pub fn connection_capped(state: &ServerState) -> ChannelError {
    bump(&state.counters.connections_capped);
    let limit = settings_of(state).max_total_connections;
    tracing::warn!(limit, "total connection cap reached, connection dropped");
    ChannelError::ConnectionCapped { limit }
}


pub fn handshake_timed_out(state: &ServerState) -> ChannelError {
    bump(&state.counters.handshake_timeouts);
    ChannelError::HandshakeTimeout {
        seconds: HANDSHAKE_TIMEOUT_SECONDS,
    }
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
        ChannelError::Identity(_) | ChannelError::Revoked { .. } | ChannelError::TooManyConnections { .. } | ChannelError::ConnectionCapped { .. }
    )
}


pub fn log_outcome(outcome: Result<(), ChannelError>) {
    match outcome {
        Err(error) if !already_logged(&error) => tracing::warn!(%error, "agent connection ended"),
        Err(_) | Ok(()) => (),
    }
}

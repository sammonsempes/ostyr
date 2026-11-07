use crate::error::{ChannelError, IdentityError};
use crate::identity::{identity_from_chain, serial_from_chain};
use crate::limits::{bounded_text, bump, open_slot};
use crate::model::{Admission, Identity, ServerState, SlotKind, HANDSHAKE_TIMEOUT_SECONDS};
use crate::revocation::{is_revoked, is_revoked_now};
use crate::types::{IncomingConnections, RevocationWatch, SharedServerConfig, SharedState, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::{FutureExt, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;


/// Accepts connections until `shutdown` completes; the oldest pending handshake is evicted at the cap, authenticated ones are capped apart.
pub async fn serve(
    incoming: IncomingConnections,
    config: SharedServerConfig,
    router: Router,
    state: SharedState,
    revocations: RevocationWatch,
    shutdown: ShutdownSignal,
) {
    let acceptor = TlsAcceptor::from(config);
    let connections = Arc::new(Semaphore::new(state.settings.max_total_connections));
    let mut handshakes = VecDeque::new();
    incoming
        .take_until(shutdown)
        .for_each(|accepted| {
            match accepted {
                Ok(stream) => {
                    let admission = Admission {
                        connections: Arc::clone(&connections),
                        evicted: register_handshake(&mut handshakes, &state),
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
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
            std::future::ready(())
        })
        .await;
}


/// Notes a new handshake; when `max_pending_handshakes` are already waiting the oldest one is told to stop. Finished handshakes are forgotten first.
pub fn register_handshake(handshakes: &mut VecDeque<oneshot::Sender<()>>, state: &ServerState) -> oneshot::Receiver<()> {
    handshakes.retain(|waiting| !waiting.is_closed());
    if handshakes.len() >= state.settings.max_pending_handshakes {
        evict(handshakes.pop_front(), state);
    }
    let (sender, receiver) = oneshot::channel();
    handshakes.push_back(sender);
    receiver
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
    let serial = serial_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    if is_revoked_now(&revocations, &serial) {
        Err(refused_revoked(serial))
    } else {
        let _total = admission.connections.try_acquire_owned().map_err(|_refused| connection_capped(&state))?;
        let _connection = open_slot(&state, &identity, SlotKind::Connection).map_err(|_refused| too_many_connections(&identity))?;
        let service = router.layer(Extension(identity));
        let mut builder = Builder::new(TokioExecutor::new()).http2_only();
        builder.http2().max_concurrent_streams(state.settings.max_streams_per_connection);
        tokio::select! {
            served = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(service)) => {
                served.map_err(ChannelError::Serve)
            }
            closed = watch_revocation(revocations, &serial) => Err(closed),
        }
    }
}


pub fn connection_capped(state: &ServerState) -> ChannelError {
    bump(&state.counters.connections_capped);
    let limit = state.settings.max_total_connections;
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


/// Completes with the reason as soon as `serial` is on the list, or when the list is no longer maintained.
pub async fn watch_revocation(mut revocations: RevocationWatch, serial: &str) -> ChannelError {
    let outcome = revocations.wait_for(|list| is_revoked(list, serial)).await.map(|_list| ());
    match outcome {
        Ok(()) => refused_revoked(serial.to_owned()),
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

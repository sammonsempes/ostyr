use crate::limiter::source_key;
use crate::model::{ConnectionGuard, PageSettings, PageState, PeerIp};
use crate::types::{IncomingConnections, SharedState, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::StreamExt;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};


pub const ACCEPT_BACKOFF_MILLIS: u64 = 100;


impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        let mut table = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let remaining = table.get(&self.key).copied().unwrap_or(1).saturating_sub(1);
        if remaining == 0 {
            table.remove(&self.key);
        } else {
            table.insert(self.key, remaining);
        }
    }
}


/// Counts a new connection unless its source already holds `per_source` or `maximum` are open; the source is checked first.
pub fn admit_connection(state: &PageState, key: IpAddr, settings: &PageSettings) -> Option<ConnectionGuard> {
    let mut table = state.sources.lock().unwrap_or_else(PoisonError::into_inner);
    if table.get(&key).copied().unwrap_or(0) >= settings.max_connections_per_source {
        None
    } else {
        *table.entry(key).or_insert(0) += 1;
        drop(table);
        let guard = ConnectionGuard {
            active: Arc::clone(&state.active),
            sources: Arc::clone(&state.sources),
            key,
        };
        let taken = state.active.fetch_add(1, Ordering::SeqCst);
        (taken < settings.max_connections).then_some(guard)
    }
}


pub fn log_outcome(outcome: Result<Result<(), hyper::Error>, tokio::time::error::Elapsed>) {
    match outcome {
        Ok(Ok(())) => tracing::debug!("connection closed"),
        Ok(Err(error)) => tracing::debug!(%error, "connection ended"),
        Err(_elapsed) => tracing::debug!("connection cut at its total deadline"),
    }
}


/// One HTTP/1 connection: header read deadline per request (idle included), header count and size caps, and a total deadline; no keep-alive past either.
pub async fn run_connection(stream: TcpStream, peer: SocketAddr, router: Router, settings: Arc<PageSettings>, guard: ConnectionGuard) {
    let service = router.layer(Extension(PeerIp(peer.ip())));
    let mut builder = Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(settings.header_read_timeout_seconds))
        .max_headers(settings.max_headers)
        .max_buf_size(settings.max_header_bytes);
    let served = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
    let outcome = timeout(Duration::from_secs(settings.connection_timeout_seconds), served).await;
    drop(guard);
    log_outcome(outcome);
}


/// Starts one connection task, unless the connection cap is reached or the peer address is unknown.
pub fn accept_connection(stream: TcpStream, peer_address: io::Result<SocketAddr>, router: &Router, state: &SharedState) {
    let settings = state.settings.load_full();
    match peer_address {
        Ok(peer) => match admit_connection(state, source_key(peer.ip()), &settings) {
            Some(guard) => {
                tokio::spawn(run_connection(stream, peer, router.clone(), settings, guard));
            }
            None => tracing::debug!("connection cap reached, connection refused"),
        },
        Err(error) => tracing::warn!(%error, "peer address unknown, connection dropped"),
    }
}


/// Handles one accept result; a failed accept is logged with its class and followed by a pause, so a persistent error cannot spin.
pub async fn accept_one(accepted: io::Result<TcpStream>, router: &Router, state: &SharedState) {
    match accepted {
        Ok(stream) => {
            let peer = stream.peer_addr();
            accept_connection(stream, peer, router, state);
        }
        Err(error) => {
            let class = error.kind();
            tracing::warn!(?class, %error, "accept failed, backing off");
            sleep(Duration::from_millis(ACCEPT_BACKOFF_MILLIS)).await;
        }
    }
}


/// Accepts connections until `shutdown` completes.
pub async fn serve(incoming: IncomingConnections, router: Router, state: SharedState, shutdown: ShutdownSignal) {
    incoming
        .take_until(shutdown)
        .for_each(|accepted| accept_one(accepted, &router, &state))
        .await;
}

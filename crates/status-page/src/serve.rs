use crate::model::{ConnectionGuard, PageSettings, PeerIp};
use crate::types::{IncomingConnections, SharedState, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::StreamExt;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;


impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}


/// Counts a new connection unless `maximum` are already open.
pub fn admit_connection(active: &Arc<AtomicUsize>, maximum: usize) -> Option<ConnectionGuard> {
    let taken = active.fetch_add(1, Ordering::SeqCst);
    let guard = ConnectionGuard { active: Arc::clone(active) };
    (taken < maximum).then_some(guard)
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
    match (admit_connection(&state.active, settings.max_connections), peer_address) {
        (Some(guard), Ok(peer)) => {
            tokio::spawn(run_connection(stream, peer, router.clone(), settings, guard));
        }
        (None, _) => tracing::debug!("connection cap reached, connection refused"),
        (Some(_released), Err(error)) => tracing::warn!(%error, "peer address unknown, connection dropped"),
    }
}


pub fn accept_one(accepted: io::Result<TcpStream>, router: &Router, state: &SharedState) -> std::future::Ready<()> {
    match accepted {
        Ok(stream) => {
            let peer = stream.peer_addr();
            accept_connection(stream, peer, router, state);
        }
        Err(error) => tracing::warn!(%error, "accept failed"),
    }
    std::future::ready(())
}


/// Accepts connections until `shutdown` completes.
pub async fn serve(incoming: IncomingConnections, router: Router, state: SharedState, shutdown: ShutdownSignal) {
    incoming
        .take_until(shutdown)
        .for_each(|accepted| accept_one(accepted, &router, &state))
        .await;
}

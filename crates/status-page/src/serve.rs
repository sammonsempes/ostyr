use crate::limiter::{source_key, wide_key};
use crate::model::ProxyOutcome;
use crate::model::{ConnectionCaps, ConnectionGuard, PageSettings, PageState, PeerIp};
use crate::proxy::{is_trusted, read_header};
use crate::types::{IncomingConnections, SharedState, ShutdownSignal, SourceConnections};
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


pub fn release(table: &SourceConnections, key: &IpAddr) {
    let mut guarded = table.lock().unwrap_or_else(PoisonError::into_inner);
    let remaining = guarded.get(key).copied().unwrap_or(1).saturating_sub(1);
    if remaining == 0 {
        guarded.remove(key);
    } else {
        guarded.insert(*key, remaining);
    }
}


impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        release(&self.sources, &self.key);
        if let Some(wide) = &self.wide_key {
            release(&self.wide_sources, wide);
        }
    }
}


/// Counts a new connection unless its source holds `per_source`, its wide aggregate `per_wide`, or `maximum` are open; narrow, wide, then global.
pub fn admit_counted(state: &PageState, source: IpAddr, caps: ConnectionCaps) -> Option<ConnectionGuard> {
    let key = source_key(source);
    let wide = wide_key(source, caps.wide_bits);
    let mut table = state.sources.lock().unwrap_or_else(PoisonError::into_inner);
    let mut wide_table = state.wide_sources.lock().unwrap_or_else(PoisonError::into_inner);
    let narrow_full = table.get(&key).copied().unwrap_or(0) >= caps.per_source;
    let wide_full = wide.is_some_and(|prefix| wide_table.get(&prefix).copied().unwrap_or(0) >= caps.per_wide);
    if narrow_full || wide_full {
        None
    } else {
        *table.entry(key).or_insert(0) += 1;
        if let Some(prefix) = wide {
            *wide_table.entry(prefix).or_insert(0) += 1;
        }
        drop(wide_table);
        drop(table);
        let guard = ConnectionGuard {
            active: Arc::clone(&state.active),
            sources: Arc::clone(&state.sources),
            key,
            wide_sources: Arc::clone(&state.wide_sources),
            wide_key: wide,
        };
        let taken = state.active.fetch_add(1, Ordering::SeqCst);
        (taken < caps.maximum).then_some(guard)
    }
}


/// The caps of the settings for a source address.
pub fn settings_caps(settings: &PageSettings) -> ConnectionCaps {
    ConnectionCaps {
        per_source: settings.max_connections_per_source,
        per_wide: settings
            .max_connections_per_source
            .saturating_mul(usize::try_from(settings.wide_multiplier).unwrap_or(usize::MAX)),
        maximum: settings.max_connections,
        wide_bits: settings.wide_prefix_bits,
    }
}


pub fn admit_connection(state: &PageState, source: IpAddr, settings: &PageSettings) -> Option<ConnectionGuard> {
    admit_counted(state, source, settings_caps(settings))
}


/// Before the header is read a trusted proxy only counts against the global cap; the client's own caps apply once it is known.
pub fn proxy_caps(settings: &PageSettings) -> ConnectionCaps {
    ConnectionCaps {
        per_source: settings.max_connections,
        per_wide: settings.max_connections,
        maximum: settings.max_connections,
        wide_bits: settings.wide_prefix_bits,
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
pub async fn run_connection(stream: TcpStream, source: IpAddr, router: Router, settings: Arc<PageSettings>, guard: ConnectionGuard) {
    let service = router.layer(Extension(PeerIp(source)));
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


/// The connection of a trusted proxy: one PROXY v2 header names the client, read within the header deadline; a bad one closes the connection.
pub async fn run_proxied(
    mut stream: TcpStream,
    proxy: SocketAddr,
    router: Router,
    state: SharedState,
    settings: Arc<PageSettings>,
    early: ConnectionGuard,
) {
    let wait = Duration::from_secs(settings.header_read_timeout_seconds);
    let read = timeout(wait, read_header(&mut stream, settings.max_proxy_header_bytes)).await;
    drop(early);
    match read {
        Ok(Ok(ProxyOutcome::Client(client))) => start_with_source(stream, client, router, &state, settings),
        Ok(Ok(ProxyOutcome::Local)) => start_with_source(stream, proxy.ip(), router, &state, settings),
        Ok(Ok(ProxyOutcome::Malformed)) => {
            let total = state.proxy_malformed.fetch_add(1, Ordering::SeqCst) + 1;
            tracing::warn!(total, "malformed PROXY header from a trusted proxy, connection closed");
        }
        Ok(Err(error)) => tracing::debug!(%error, "PROXY header not read, connection closed"),
        Err(_elapsed) => tracing::debug!("PROXY header deadline, connection closed"),
    }
}


/// Admits the connection under the derived source's caps and serves it.
pub fn start_with_source(stream: TcpStream, source: IpAddr, router: Router, state: &SharedState, settings: Arc<PageSettings>) {
    match admit_connection(state, source, &settings) {
        Some(guard) => {
            tokio::spawn(run_connection(stream, source, router, settings, guard));
        }
        None => tracing::debug!("connection cap reached, connection refused"),
    }
}


/// Starts one connection task, unless the connection cap is reached or the peer address is unknown.
pub fn accept_connection(stream: TcpStream, peer_address: io::Result<SocketAddr>, router: &Router, state: &SharedState) {
    let settings = state.settings.load_full();
    match peer_address {
        Ok(peer) if is_trusted(&settings.trusted_proxies, peer.ip()) => match admit_counted(state, peer.ip(), proxy_caps(&settings)) {
            Some(early) => {
                tokio::spawn(run_proxied(stream, peer, router.clone(), Arc::clone(state), settings, early));
            }
            None => tracing::debug!("connection cap reached, connection refused"),
        },
        Ok(peer) => start_with_source(stream, peer.ip(), router.clone(), state, settings),
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

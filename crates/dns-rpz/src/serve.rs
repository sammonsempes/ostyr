use crate::limits::{
    ACCEPT_BACKOFF_MILLIS, ALLOWED_METHODS, COUNTER_CLASSES, CSP_VALUE, CUT_TEXT, FAILED_TEXT, HTML_TYPE, IPV6_HOST_BITS, MAX_REQUEST_HEADERS,
    MAX_REQUEST_HEAD_BYTES, REFUSED_TEXT, REPORT_INTERVAL_SECONDS,
};
use crate::model::{ConnectionClass, ConnectionGuard, ServeState};
use crate::policy::{Policy, SinkholeServer};
use crate::sinkhole::render_page;
use crate::types::{ConnectionOutcome, PageResponse};
use bytes::Bytes;
use core_config::reload::{current_config, ReloadEngine};
use futures_util::StreamExt;
use http_body_util::Full;
use hyper::header::{
    HeaderValue, ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::future::ready;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot::Receiver;
use tokio::time::{sleep, timeout, Instant};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::warn;


/// The key of a source: IPv4 as is (mapped IPv6 included), other IPv6 folded to its /64.
pub fn source_key(source: IpAddr) -> IpAddr {
    match source.to_canonical() {
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from((u128::from(address) >> IPV6_HOST_BITS) << IPV6_HOST_BITS)),
        other => other,
    }
}


/// Takes a slot unless the global cap or the source's cap is reached; both are checked and taken under one lock, before anything is read.
pub fn admit(state: &ServeState, source: IpAddr, server: &SinkholeServer) -> Option<ConnectionGuard> {
    let key = source_key(source);
    let mut admission = state.admission.lock().unwrap_or_else(PoisonError::into_inner);
    let held = admission.sources.get(&key).copied().unwrap_or(0);
    if admission.total >= server.max_connections || held >= server.max_connections_per_source {
        state.refused.fetch_add(1, Ordering::Relaxed);
        None
    } else {
        admission.total += 1;
        admission.sources.insert(key, held + 1);
        Some(ConnectionGuard {
            admission: Arc::clone(&state.admission),
            key,
        })
    }
}


impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut admission = self.admission.lock().unwrap_or_else(PoisonError::into_inner);
        admission.total = admission.total.saturating_sub(1);
        let remaining = admission.sources.get(&self.key).map_or(0, |held| held.saturating_sub(1));
        if remaining == 0 {
            admission.sources.remove(&self.key);
        } else {
            admission.sources.insert(self.key, remaining);
        }
    }
}


/// The `Host` bytes when there is exactly one such header; none or several show "unknown domain".
pub fn host_of(headers: &HeaderMap) -> Option<&[u8]> {
    let mut values = headers.get_all(HOST).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => Some(value.as_bytes()),
        _ => None,
    }
}


/// The same headers on every response built here, the refusal included.
pub fn add_headers(response: &mut PageResponse) {
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP_VALUE));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
}


/// `GET` and `HEAD` get the page for the `Host` header whatever the path; any other method a fixed 405 with no body. A body is never looked at.
pub fn handle(policy: &Policy, method: &Method, headers: &HeaderMap) -> Result<PageResponse, Infallible> {
    let mut response = if *method == Method::GET || *method == Method::HEAD {
        let rendered = render_page(policy.sinkhole_page.as_ref(), host_of(headers));
        let mut page = Response::new(Full::new(Bytes::from(rendered.html)));
        page.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(HTML_TYPE));
        page
    } else {
        let mut refused = Response::new(Full::new(Bytes::new()));
        *refused.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        refused.headers_mut().insert(ALLOW, HeaderValue::from_static(ALLOWED_METHODS));
        refused
    };
    add_headers(&mut response);
    Ok(response)
}


pub fn connection_class(outcome: ConnectionOutcome) -> ConnectionClass {
    match outcome {
        Ok(Ok(())) => ConnectionClass::Closed,
        Ok(Err(_error)) => ConnectionClass::Failed,
        Err(_elapsed) => ConnectionClass::Deadline,
    }
}


/// A connection that ended in an error or at a deadline is counted, never logged one by one.
pub fn count_class(state: &ServeState, class: ConnectionClass) -> ConnectionClass {
    if class != ConnectionClass::Closed {
        state.cut.fetch_add(1, Ordering::Relaxed);
    }
    class
}


/// One HTTP/1 request per connection: the whole head within the header deadline, bounded head and header count, no keep-alive, one total deadline.
pub async fn run_connection(stream: TcpStream, policy: Arc<Policy>, server: SinkholeServer, state: Arc<ServeState>, guard: ConnectionGuard) {
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| ready(handle(&policy, request.method(), request.headers())));
    let mut builder = Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_millis(server.header_read_timeout_ms))
        .max_headers(MAX_REQUEST_HEADERS)
        .max_buf_size(MAX_REQUEST_HEAD_BYTES)
        .keep_alive(false);
    let served = builder.serve_connection(TokioIo::new(stream), service);
    let outcome = timeout(Duration::from_millis(server.response_timeout_ms), served).await;
    drop(guard);
    count_class(&state, connection_class(outcome));
}


/// One line per class that counted something since the last report, at most once per interval; no peer text in it.
pub fn report_due(state: &ServeState) -> bool {
    let now = Instant::now();
    let mut reported_at = state.reported_at.lock().unwrap_or_else(PoisonError::into_inner);
    let due = reported_at.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(REPORT_INTERVAL_SECONDS));
    if due {
        *reported_at = Some(now);
        let classes: [(&AtomicU64, &str); COUNTER_CLASSES] = [(&state.refused, REFUSED_TEXT), (&state.cut, CUT_TEXT), (&state.failed, FAILED_TEXT)];
        classes.into_iter().for_each(|(counter, text)| report_class(counter, text));
    }
    due
}


pub fn report_class(counter: &AtomicU64, text: &str) {
    let count = counter.swap(0, Ordering::Relaxed);
    if count > 0 {
        warn!(count, text, "sinkhole counters of the last interval");
    }
}


/// Admits and serves one accepted connection with the policy snapshot taken now; a refused one is closed unread.
pub fn accept_connection(stream: TcpStream, peer: io::Result<SocketAddr>, policy: Arc<Policy>, state: &Arc<ServeState>) {
    match (peer, policy.sinkhole_server) {
        (Ok(peer_address), Some(server)) => {
            if let Some(guard) = admit(state, peer_address.ip(), &server) {
                tokio::spawn(run_connection(stream, policy, server, Arc::clone(state), guard));
            }
        }
        (Ok(_), None) => {
            state.refused.fetch_add(1, Ordering::Relaxed);
        }
        (Err(_error), _) => {
            state.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}


/// A failed accept is counted and followed by a pause, so a persistent error cannot spin.
pub async fn accept_one(accepted: io::Result<TcpStream>, engine: &ReloadEngine<Policy>, state: &Arc<ServeState>) {
    report_due(state);
    match accepted {
        Ok(stream) => {
            let peer = stream.peer_addr();
            accept_connection(stream, peer, current_config(engine), state);
        }
        Err(_error) => {
            state.failed.fetch_add(1, Ordering::Relaxed);
            sleep(Duration::from_millis(ACCEPT_BACKOFF_MILLIS)).await;
        }
    }
}


/// Accepts connections until `shutdown` completes (or its sender is dropped).
pub async fn serve(listener: TcpListener, engine: Arc<ReloadEngine<Policy>>, state: Arc<ServeState>, shutdown: Receiver<()>) {
    TcpListenerStream::new(listener)
        .take_until(shutdown)
        .for_each(|accepted| accept_one(accepted, &engine, &state))
        .await;
}

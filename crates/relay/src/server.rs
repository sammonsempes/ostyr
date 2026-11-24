use crate::admission::{admit, gauges, new_admission};
use crate::copy::relay_halves;
use crate::model::{Accepted, Bounds, Counters, End, Halves, Options, Permit, Refusal, RelaySettings, Server, Summary};
use crate::types::{AcceptFn, ConnectFn, ConnectFuture, SharedStop, ShutdownSignal};
use core_config::reload::{current_config, ReloadEngine};
use futures_util::{stream, FutureExt, StreamExt};
use rustix::io::Errno;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{interval_at, sleep, timeout, Instant};


pub const RESOURCE_ERRNOS: [i32; 4] = [
    Errno::MFILE.raw_os_error(),
    Errno::NFILE.raw_os_error(),
    Errno::NOBUFS.raw_os_error(),
    Errno::NOMEM.raw_os_error(),
];


pub fn bounds_of(settings: &RelaySettings) -> Bounds {
    Bounds {
        connect: Duration::from_secs(settings.connect_timeout_seconds),
        idle: Duration::from_secs(settings.idle_seconds),
        lifetime: Duration::from_secs(settings.max_lifetime_seconds),
    }
}


/// Descriptor, buffer or memory exhaustion: the next accept would fail the same way, so the loop pauses first.
pub fn is_resource_error(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| RESOURCE_ERRNOS.contains(&code))
}


pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}


pub fn record(counters: &Counters, end: End) {
    match end {
        End::Completed => bump(&counters.completed),
        End::CopyError => bump(&counters.copy_error),
        End::Idle => bump(&counters.idle_end),
        End::Lifetime => bump(&counters.lifetime_end),
        End::Cut => bump(&counters.shutdown_cut),
        End::ConnectFailed => bump(&counters.connect_failed),
        End::ConnectTimeout => bump(&counters.connect_timeout),
    }
}


/// Connects upstream under the connect timeout, then copies until the connection ends.
pub async fn relay_connection(server: &Server, client: Halves, settings: &RelaySettings) -> End {
    let bounds = bounds_of(settings);
    match timeout(bounds.connect, (server.connect)(settings.upstream)).await {
        Err(_elapsed) => End::ConnectTimeout,
        Ok(Err(_error)) => End::ConnectFailed,
        Ok(Ok(upstream)) => relay_halves(client, upstream, &bounds, server.cut.subscribe()).await,
    }
}


/// The permit is released after `relay_connection` returned, so both sockets are closed first.
pub async fn serve_connection(server: Arc<Server>, client: Halves, permit: Permit, settings: Arc<RelaySettings>) {
    let end = relay_connection(&server, client, &settings).await;
    record(&server.counters, end);
    drop(permit);
}


/// Takes the settings snapshot of this connection, then refuses it over a cap or spawns its task.
pub fn admit_connection(server: &Arc<Server>, accepted: Accepted) {
    match accepted.peer {
        Err(_error) => bump(&server.counters.peer_unknown),
        Ok(address) => {
            let settings = current_config(&server.engine);
            match admit(
                &server.admission,
                address.ip(),
                settings.max_connections,
                settings.max_connections_per_source,
            ) {
                Err(Refusal::Total) => bump(&server.counters.refused_total),
                Err(Refusal::Source) => bump(&server.counters.refused_source),
                Ok(permit) => {
                    tokio::spawn(serve_connection(Arc::clone(server), accepted.halves, permit, settings));
                }
            }
        }
    }
}


/// Every accept error is counted; only a resource error pauses, so a descriptor shortage cannot spin.
pub async fn handle_accepted(server: &Arc<Server>, result: io::Result<Accepted>, pause: Duration) {
    match result {
        Err(error) => {
            bump(&server.counters.accept_error);
            if is_resource_error(&error) {
                sleep(pause).await;
            }
        }
        Ok(accepted) => admit_connection(server, accepted),
    }
}


/// Accepts until `stop` completes; a pending accept is dropped then.
pub async fn accept_loop(server: Arc<Server>, accept: AcceptFn, stop: SharedStop, pause: Duration) {
    let accepting = &accept;
    stream::unfold((), |()| async move { Some((accepting().await, ())) })
        .take_until(stop)
        .for_each(|result| handle_accepted(&server, result, pause))
        .await;
}


fn take(counter: &AtomicU64) -> u64 {
    counter.swap(0, Ordering::Relaxed)
}


/// The counts of the window ending now (reset to zero) and the gauges.
pub fn take_summary(server: &Server) -> Summary {
    let (live, sources) = gauges(&server.admission);
    Summary {
        refused_total: take(&server.counters.refused_total),
        refused_source: take(&server.counters.refused_source),
        connect_failed: take(&server.counters.connect_failed),
        connect_timeout: take(&server.counters.connect_timeout),
        idle_end: take(&server.counters.idle_end),
        lifetime_end: take(&server.counters.lifetime_end),
        copy_error: take(&server.counters.copy_error),
        accept_error: take(&server.counters.accept_error),
        peer_unknown: take(&server.counters.peer_unknown),
        completed: take(&server.counters.completed),
        shutdown_cut: take(&server.counters.shutdown_cut),
        live,
        sources,
    }
}


/// One line per window, counts and gauges only, never an address.
pub async fn summary_loop(server: Arc<Server>, every: Duration, stop: SharedStop) {
    stream::unfold(interval_at(Instant::now() + every, every), |mut ticker| async move {
        ticker.tick().await;
        Some(((), ticker))
    })
    .take_until(stop)
    .for_each(|()| async {
        let summary = take_summary(&server);
        tracing::info!(?summary, "relay summary per window");
    })
    .await;
}


/// Waits for the live connections to end for `grace`, then cuts the rest; returns how many were cut.
pub async fn drain(server: &Server, grace: Duration) -> usize {
    let mut live = server.admission.live.subscribe();
    if timeout(grace, live.wait_for(|count| *count == 0)).await.is_ok() {
        0
    } else {
        let remaining = *live.borrow();
        server.cut.send_replace(true);
        let settled = timeout(grace, live.wait_for(|count| *count == 0)).await.is_ok();
        if !settled {
            tracing::warn!(remaining, "connections still open after the cut");
        }
        remaining
    }
}


/// Serves until `stop` completes, then drains; returns the number of connections cut.
pub async fn run_relay(
    accept: AcceptFn,
    connect: ConnectFn,
    engine: Arc<ReloadEngine<RelaySettings>>,
    stop: ShutdownSignal,
    options: Options,
) -> usize {
    let (cut, _first_receiver) = watch::channel(false);
    let server = Arc::new(Server {
        engine,
        admission: new_admission(),
        counters: Counters::default(),
        connect,
        cut,
    });
    let stopped = stop.shared();
    tokio::spawn(summary_loop(Arc::clone(&server), options.summary_every, stopped.clone()));
    accept_loop(Arc::clone(&server), accept, stopped, options.accept_pause).await;
    drain(&server, options.shutdown_grace).await
}


pub fn note_nodelay(error: &io::Error) {
    tracing::debug!(%error, "cannot set TCP_NODELAY");
}


/// Splits a TCP stream into boxed halves and reads its peer address.
pub fn split_stream(stream: TcpStream) -> Accepted {
    let peer = stream.peer_addr();
    stream.set_nodelay(true).inspect_err(note_nodelay).unwrap_or(());
    let (read, write) = stream.into_split();
    Accepted {
        halves: Halves {
            read: Box::new(read),
            write: Box::new(write),
        },
        peer,
    }
}


pub fn tcp_accept(listener: TcpListener) -> AcceptFn {
    let shared = Arc::new(listener);
    Box::new(move || {
        let listening = Arc::clone(&shared);
        Box::pin(async move { Ok(split_stream(listening.accept().await?.0)) })
    })
}


pub fn tcp_connect() -> ConnectFn {
    Box::new(|address: SocketAddr| -> ConnectFuture { Box::pin(async move { Ok(split_stream(TcpStream::connect(address).await?).halves) }) })
}

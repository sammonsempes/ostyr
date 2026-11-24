use crate::support::{
    accepted, black_hole_connect, failing_connect, link, recording_connect, rig, scripted_accept, settle, Rig, TestResult, BASE_YAML,
};
use core_config::reload::{current_config, reload};
use futures_util::FutureExt;
use relay::admission::{admit, gauges, new_admission};
use relay::header::proxy_header;
use relay::model::{Accepted, Counters, End, Options, Server, Summary};
use relay::server::{
    accept_loop, bounds_of, bump, drain, enable_nodelay, handle_accepted, is_resource_error, record, run_relay, serve_connection, split_stream,
    summary_loop, take_summary, tcp_accept, tcp_connect,
};
use relay::types::{ConnectFn, NodelayFn, SharedStop, ShutdownSignal};
use rustix::io::Errno;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::time::advance;


const TWO: usize = 2;


const THREE: usize = 3;


const HELLO_LEN: usize = 5;


const PAUSE: Duration = Duration::from_millis(100);


const GRACE: Duration = Duration::from_secs(1);


const WINDOW: Duration = Duration::from_secs(60);


const CAPPED: &str = "max_connections: 2\nmax_connections_per_source: 1\n";


fn make_server(rig: &Rig, connect: ConnectFn) -> Arc<Server> {
    let (cut, _receiver) = watch::channel(false);
    Arc::new(Server {
        engine: Arc::clone(&rig.engine),
        admission: new_admission(),
        counters: Counters::default(),
        connect,
        cut,
    })
}


fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::SeqCst)
}


fn stopper() -> (oneshot::Sender<()>, ShutdownSignal) {
    let (sender, receiver) = oneshot::channel();
    (
        sender,
        Box::pin(async move {
            let outcome = receiver.await;
            drop(outcome);
        }),
    )
}


fn shared_stopper() -> (oneshot::Sender<()>, SharedStop) {
    let (sender, signal) = stopper();
    (sender, signal.shared())
}


fn options() -> Options {
    Options {
        shutdown_grace: GRACE,
        summary_every: WINDOW,
        accept_pause: PAUSE,
    }
}


fn with_caps(extra: &str) -> String {
    format!("{BASE_YAML}{extra}")
}


#[tokio::test(start_paused = true)]
async fn both_caps_refuse_at_accept_before_any_upstream_connect() -> TestResult {
    let rig = rig(&with_caps(CAPPED))?;
    let (connect, upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let pause = PAUSE;
    let (first, _first_end) = accepted("192.0.2.1:40000")?;
    let (same_source, _same_end) = accepted("192.0.2.1:40001")?;
    let (second, _second_end) = accepted("192.0.2.2:40000")?;
    let (third, _third_end) = accepted("192.0.2.3:40000")?;
    handle_accepted(&server, Ok(first), pause).await;
    handle_accepted(&server, Ok(same_source), pause).await;
    handle_accepted(&server, Ok(second), pause).await;
    handle_accepted(&server, Ok(third), pause).await;
    assert_eq!(load(&server.counters.refused_source), 1);
    assert_eq!(load(&server.counters.refused_total), 1);
    assert_eq!(gauges(&server.admission), (TWO, TWO));
    settle().await;
    assert_eq!(upstreams.asked.lock().unwrap_or_else(PoisonError::into_inner).len(), TWO);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_reload_applies_to_new_connections_only() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let (first, _first_end) = accepted("192.0.2.1:40000")?;
    handle_accepted(&server, Ok(first), PAUSE).await;
    settle().await;
    std::fs::write(&rig.settings_path, "listen: 0.0.0.0:443\nupstream: 10.0.0.2:8443\n")?;
    reload(&rig.engine);
    let (second, _second_end) = accepted("192.0.2.2:40000")?;
    handle_accepted(&server, Ok(second), PAUSE).await;
    settle().await;
    let asked = upstreams.asked.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(asked, vec!["10.0.0.1:8443".parse()?, "10.0.0.2:8443".parse()?]);
    assert_eq!(gauges(&server.admission), (TWO, TWO));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_lowered_cap_keeps_live_connections_and_refuses_new_ones() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, _upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let (first, _first_end) = accepted("192.0.2.1:40000")?;
    let (second, _second_end) = accepted("192.0.2.2:40000")?;
    handle_accepted(&server, Ok(first), PAUSE).await;
    handle_accepted(&server, Ok(second), PAUSE).await;
    std::fs::write(&rig.settings_path, with_caps("max_connections: 1\nmax_connections_per_source: 1\n"))?;
    reload(&rig.engine);
    assert_eq!(current_config(&rig.engine).max_connections, 1);
    let (third, _third_end) = accepted("192.0.2.3:40000")?;
    handle_accepted(&server, Ok(third), PAUSE).await;
    assert_eq!(load(&server.counters.refused_total), 1);
    assert_eq!(gauges(&server.admission), (TWO, TWO));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_unknown_peer_is_counted_and_closed() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let (relay_side, _test_side) = link();
    let unknown = Accepted {
        halves: relay_side,
        peer: Err(io::Error::from(io::ErrorKind::NotConnected)),
        local: Ok("198.51.100.7:443".parse()?),
    };
    handle_accepted(&server, Ok(unknown), PAUSE).await;
    assert_eq!(load(&server.counters.peer_unknown), 1);
    assert_eq!(gauges(&server.admission), (0, 0));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn each_end_is_counted_under_its_reason() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let source: IpAddr = "192.0.2.1".parse()?;
    let settings = current_config(&rig.engine);
    let failing = make_server(&rig, failing_connect());
    let permit = admit(&failing.admission, source, 1, 1)?;
    let (client, _client_end) = link();
    serve_connection(Arc::clone(&failing), client, Vec::new(), permit, Arc::clone(&settings)).await;
    assert_eq!(load(&failing.counters.connect_failed), 1);
    assert_eq!(gauges(&failing.admission), (0, 0));
    let hole = make_server(&rig, black_hole_connect());
    let permit_hole = admit(&hole.admission, source, 1, 1)?;
    let (client_hole, _hole_end) = link();
    serve_connection(Arc::clone(&hole), client_hole, Vec::new(), permit_hole, Arc::clone(&settings)).await;
    assert_eq!(load(&hole.counters.connect_timeout), 1);
    let (connect, _upstreams) = recording_connect();
    let idle = make_server(&rig, connect);
    let permit_idle = admit(&idle.admission, source, 1, 1)?;
    let (client_idle, _idle_end) = link();
    serve_connection(Arc::clone(&idle), client_idle, Vec::new(), permit_idle, settings).await;
    assert_eq!(load(&idle.counters.idle_end), 1);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn record_maps_every_end() -> TestResult {
    let counters = Counters::default();
    [
        End::Completed,
        End::CopyError,
        End::Idle,
        End::Lifetime,
        End::Cut,
        End::ConnectFailed,
        End::ConnectTimeout,
        End::HeaderFailed,
    ]
    .into_iter()
    .for_each(|end| record(&counters, end));
    let all = [
        &counters.completed,
        &counters.copy_error,
        &counters.idle_end,
        &counters.lifetime_end,
        &counters.shutdown_cut,
        &counters.connect_failed,
        &counters.connect_timeout,
        &counters.header_failed,
    ];
    assert!(all.iter().all(|counter| load(counter) == 1));
    Ok(())
}


#[test]
fn only_exhaustion_errors_are_resource_errors() -> TestResult {
    [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM]
        .iter()
        .for_each(|errno| assert!(is_resource_error(&io::Error::from_raw_os_error(errno.raw_os_error()))));
    assert!(!is_resource_error(&io::Error::from_raw_os_error(Errno::CONNABORTED.raw_os_error())));
    assert!(!is_resource_error(&io::Error::from(io::ErrorKind::Other)));
    Ok(())
}


fn resource_error() -> io::Error {
    io::Error::from_raw_os_error(Errno::MFILE.raw_os_error())
}


fn aborted() -> io::Error {
    io::Error::from_raw_os_error(Errno::CONNABORTED.raw_os_error())
}


#[tokio::test(start_paused = true)]
async fn a_resource_error_pauses_the_accept_loop() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let calls = Arc::new(AtomicUsize::new(0));
    let accept = scripted_accept(vec![Err(resource_error())], Arc::clone(&calls));
    let (_stop, stopped) = shared_stopper();
    let running = tokio::spawn(accept_loop(Arc::clone(&server), accept, stopped, PAUSE));
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(load(&server.counters.accept_error), 1);
    advance(PAUSE - Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    advance(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), TWO);
    running.abort();
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_per_connection_error_costs_no_pause() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let calls = Arc::new(AtomicUsize::new(0));
    let accept = scripted_accept(vec![Err(aborted()), Err(aborted())], Arc::clone(&calls));
    let (_stop, stopped) = shared_stopper();
    let running = tokio::spawn(accept_loop(Arc::clone(&server), accept, stopped, PAUSE));
    settle().await;
    assert_eq!(calls.load(Ordering::SeqCst), THREE);
    assert_eq!(load(&server.counters.accept_error), TWO as u64);
    running.abort();
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_accept_loop_ends_at_stop() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let calls = Arc::new(AtomicUsize::new(0));
    let accept = scripted_accept(Vec::new(), calls);
    let (stop, stopped) = shared_stopper();
    let running = tokio::spawn(accept_loop(server, accept, stopped, PAUSE));
    settle().await;
    stop.send(()).map_err(|()| "stop dropped")?;
    running.await?;
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_summary_takes_and_resets_the_window() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let all = [
        &server.counters.refused_total,
        &server.counters.refused_source,
        &server.counters.connect_failed,
        &server.counters.connect_timeout,
        &server.counters.header_failed,
        &server.counters.idle_end,
        &server.counters.lifetime_end,
        &server.counters.copy_error,
        &server.counters.accept_error,
        &server.counters.peer_unknown,
        &server.counters.completed,
        &server.counters.shutdown_cut,
    ];
    all.iter().for_each(|counter| bump(counter));
    let permit = admit(&server.admission, "192.0.2.1".parse()?, 1, 1)?;
    let summary = take_summary(&server);
    let expected = Summary {
        refused_total: 1,
        refused_source: 1,
        connect_failed: 1,
        connect_timeout: 1,
        header_failed: 1,
        idle_end: 1,
        lifetime_end: 1,
        copy_error: 1,
        accept_error: 1,
        peer_unknown: 1,
        completed: 1,
        shutdown_cut: 1,
        live: 1,
        sources: 1,
    };
    assert_eq!(summary, expected);
    assert!(all.iter().all(|counter| load(counter) == 0));
    drop(permit);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_summary_loop_resets_every_window_and_stops() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let (stop, stopped) = shared_stopper();
    let running = tokio::spawn(summary_loop(Arc::clone(&server), WINDOW, stopped));
    bump(&server.counters.completed);
    settle().await;
    assert_eq!(load(&server.counters.completed), 1);
    advance(WINDOW).await;
    settle().await;
    assert_eq!(load(&server.counters.completed), 0);
    stop.send(()).map_err(|()| "stop dropped")?;
    running.await?;
    Ok(())
}


async fn serve_two(rig: &Rig, connect: ConnectFn) -> Result<(Arc<Server>, Vec<tokio::io::DuplexStream>), Box<dyn std::error::Error>> {
    let server = make_server(rig, connect);
    let (first, first_end) = accepted("192.0.2.1:40000")?;
    let (second, second_end) = accepted("192.0.2.2:40000")?;
    handle_accepted(&server, Ok(first), PAUSE).await;
    handle_accepted(&server, Ok(second), PAUSE).await;
    settle().await;
    Ok((server, vec![first_end, second_end]))
}


#[tokio::test(start_paused = true)]
async fn drain_waits_for_a_clean_end_then_cuts_the_rest() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, _upstreams) = recording_connect();
    let (idle_server, _ends) = serve_two(&rig, connect).await?;
    assert_eq!(drain(&idle_server, GRACE).await, TWO);
    assert_eq!(gauges(&idle_server.admission), (0, 0));
    let empty = make_server(&rig, failing_connect());
    assert_eq!(drain(&empty, GRACE).await, 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn drain_reports_a_connection_stuck_in_connect() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (server, _ends) = serve_two(&rig, black_hole_connect()).await?;
    assert_eq!(drain(&server, GRACE).await, TWO);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn run_relay_stops_with_nothing_cut_when_connections_finish() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, upstreams) = recording_connect();
    let (relay_side, mut client_end) = link();
    let calls = Arc::new(AtomicUsize::new(0));
    let item = Accepted {
        halves: relay_side,
        peer: Ok("192.0.2.1:40000".parse()?),
        local: Ok("198.51.100.7:443".parse()?),
    };
    let accept = scripted_accept(vec![Ok(item)], calls);
    let (stop, signal) = stopper();
    let running = tokio::spawn(run_relay(accept, connect, Arc::clone(&rig.engine), signal, options()));
    settle().await;
    stop.send(()).map_err(|()| "stop dropped")?;
    settle().await;
    client_end.shutdown().await?;
    let mut upstream_end = upstreams.ends.lock().unwrap_or_else(PoisonError::into_inner).pop().ok_or("no upstream")?;
    upstream_end.shutdown().await?;
    let mut rest = Vec::new();
    client_end.read_to_end(&mut rest).await?;
    assert_eq!(running.await?, 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn run_relay_cuts_what_is_left_after_the_grace() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, _upstreams) = recording_connect();
    let (relay_side, _client_end) = link();
    let item = Accepted {
        halves: relay_side,
        peer: Ok("192.0.2.1:40000".parse()?),
        local: Ok("198.51.100.7:443".parse()?),
    };
    let accept = scripted_accept(vec![Ok(item)], Arc::new(AtomicUsize::new(0)));
    let (stop, signal) = stopper();
    let running = tokio::spawn(run_relay(accept, connect, Arc::clone(&rig.engine), signal, options()));
    settle().await;
    stop.send(()).map_err(|()| "stop dropped")?;
    assert_eq!(running.await?, 1);
    Ok(())
}


#[tokio::test]
async fn real_sockets_split_into_halves() -> TestResult {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = upstream_listener.local_addr()?;
    let connect = tcp_connect();
    let mut connected = connect(address).await?;
    let (served, _) = upstream_listener.accept().await?;
    let mut served_side = split_stream(served, enable_nodelay)?;
    connected.write.write_all(b"hello").await?;
    let mut buffer = [u8::MIN; HELLO_LEN];
    served_side.halves.read.read_exact(&mut buffer).await?;
    assert_eq!(&buffer, b"hello");
    assert!(served_side.peer.is_ok());
    let refused = connect("127.0.0.1:0".parse()?).await;
    assert!(refused.is_err());
    Ok(())
}


#[tokio::test]
async fn the_tcp_accept_function_reports_the_peer() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accept = tcp_accept(listener);
    let client = tokio::net::TcpStream::connect(address).await?;
    let accepted_one = accept().await?;
    assert_eq!(accepted_one.peer?, client.local_addr()?);
    assert_eq!(accepted_one.local?, address);
    assert_eq!(
        bounds_of(&current_config(&rig(BASE_YAML)?.engine)).connect,
        Duration::from_secs(relay::model::DEFAULT_CONNECT_TIMEOUT_SECONDS)
    );
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_slot_is_released_only_after_both_sockets_are_closed() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let settings = current_config(&rig.engine);
    let permit = admit(&server.admission, "192.0.2.1".parse()?, 1, 1)?;
    let (client, mut client_end) = link();
    let serving = tokio::spawn(serve_connection(Arc::clone(&server), client, Vec::new(), permit, settings));
    settle().await;
    let mut upstream_end = upstreams.ends.lock().unwrap_or_else(PoisonError::into_inner).pop().ok_or("no upstream")?;
    server.cut.send_replace(true);
    server.admission.live.subscribe().wait_for(|count| *count == 0).await?;
    let mut buffer = [u8::MIN; 1];
    let upstream_read = upstream_end.read(&mut buffer).now_or_never();
    let client_read = client_end.read(&mut buffer).now_or_never();
    assert_eq!(upstream_read.transpose()?, Some(0));
    assert_eq!(client_read.transpose()?, Some(0));
    serving.await?;
    Ok(())
}


const FORGED_BLOCK: [u8; 12] = [10, 9, 9, 9, 10, 8, 8, 8, 0, 1, 1, 187];


const SHORT_HEADER: [u8; THREE] = [1, 2, 3];


const SIX_BYTES: usize = 6;


const CLIENT_ADDRESS: &str = "192.0.2.1:40000";


const LOCAL_ADDRESS: &str = "198.51.100.7:443";


const PROXY_V2_CLIENT_HEADER: [u8; 16] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C,
];


fn failing_nodelay(_stream: &tokio::net::TcpStream) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::NotConnected))
}


#[tokio::test(start_paused = true)]
async fn the_header_is_the_first_upstream_write_before_any_client_byte() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let (relay_side, mut client_end) = link();
    client_end.write_all(b"client bytes").await?;
    let item = Accepted {
        halves: relay_side,
        peer: Ok(CLIENT_ADDRESS.parse()?),
        local: Ok(LOCAL_ADDRESS.parse()?),
    };
    handle_accepted(&server, Ok(item), PAUSE).await;
    settle().await;
    let mut upstream_end = upstreams.ends.lock().unwrap_or_else(PoisonError::into_inner).pop().ok_or("no upstream")?;
    let header = proxy_header(CLIENT_ADDRESS.parse()?, LOCAL_ADDRESS.parse()?);
    let mut received = vec![u8::MIN; header.len() + b"client bytes".len()];
    upstream_end.read_exact(&mut received).await?;
    assert_eq!(received, [header, b"client bytes".to_vec()].concat());
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_client_sent_proxy_header_always_lands_after_the_relay_header() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let (connect, upstreams) = recording_connect();
    let server = make_server(&rig, connect);
    let (relay_side, mut client_end) = link();
    let forged = [PROXY_V2_CLIENT_HEADER.to_vec(), FORGED_BLOCK.to_vec()].concat();
    client_end.write_all(&forged).await?;
    let item = Accepted {
        halves: relay_side,
        peer: Ok(CLIENT_ADDRESS.parse()?),
        local: Ok(LOCAL_ADDRESS.parse()?),
    };
    handle_accepted(&server, Ok(item), PAUSE).await;
    settle().await;
    let mut upstream_end = upstreams.ends.lock().unwrap_or_else(PoisonError::into_inner).pop().ok_or("no upstream")?;
    let header = proxy_header(CLIENT_ADDRESS.parse()?, LOCAL_ADDRESS.parse()?);
    let mut received = vec![u8::MIN; header.len() + forged.len()];
    upstream_end.read_exact(&mut received).await?;
    assert_eq!(received.get(..header.len()), Some(header.as_slice()));
    assert_eq!(received.get(header.len()..), Some(forged.as_slice()));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_unknown_local_address_is_counted_like_an_unknown_peer() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let server = make_server(&rig, failing_connect());
    let (relay_side, _test_side) = link();
    let item = Accepted {
        halves: relay_side,
        peer: Ok(CLIENT_ADDRESS.parse()?),
        local: Err(io::Error::from(io::ErrorKind::NotConnected)),
    };
    handle_accepted(&server, Ok(item), PAUSE).await;
    assert_eq!(load(&server.counters.peer_unknown), 1);
    assert_eq!(gauges(&server.admission), (0, 0));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failed_header_write_is_counted_and_closes_the_client() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let closed: ConnectFn = Box::new(|_address| {
        let (relay_side, test_side) = link();
        drop(test_side);
        Box::pin(async move { Ok(relay_side) })
    });
    let server = make_server(&rig, closed);
    let settings = current_config(&rig.engine);
    let permit = admit(&server.admission, "192.0.2.1".parse()?, 1, 1)?;
    let (client, mut client_end) = link();
    serve_connection(Arc::clone(&server), client, SHORT_HEADER.to_vec(), permit, settings).await;
    assert_eq!(load(&server.counters.header_failed), 1);
    assert_eq!(load(&server.counters.connect_failed), 0);
    let mut rest = Vec::new();
    client_end.read_to_end(&mut rest).await?;
    assert!(rest.is_empty());
    assert_eq!(gauges(&server.admission), (0, 0));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_stalled_header_write_is_counted_after_the_connect_timeout() -> TestResult {
    let rig = rig(BASE_YAML)?;
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let keeper = Arc::clone(&held);
    let stalled: ConnectFn = Box::new(move |_address| {
        let (relay_side, test_side) = tokio::io::duplex(1);
        keeper.lock().unwrap_or_else(PoisonError::into_inner).push(test_side);
        Box::pin(async move { Ok(crate::support::halves(relay_side)) })
    });
    let server = make_server(&rig, stalled);
    let settings = current_config(&rig.engine);
    let permit = admit(&server.admission, "192.0.2.1".parse()?, 1, 1)?;
    let (client, _client_end) = link();
    let serving = tokio::spawn(serve_connection(
        Arc::clone(&server),
        client,
        [u8::MIN; SIX_BYTES].to_vec(),
        permit,
        settings,
    ));
    settle().await;
    assert_eq!(load(&server.counters.header_failed), 0);
    advance(Duration::from_secs(relay::model::DEFAULT_CONNECT_TIMEOUT_SECONDS)).await;
    serving.await?;
    assert_eq!(load(&server.counters.header_failed), 1);
    assert_eq!(gauges(&server.admission), (0, 0));
    Ok(())
}


#[tokio::test]
async fn a_socket_that_refuses_nodelay_is_an_error() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let client = tokio::net::TcpStream::connect(address).await?;
    let (served, _) = listener.accept().await?;
    let nodelay: NodelayFn = failing_nodelay;
    assert!(split_stream(served, nodelay).is_err());
    drop(client);
    Ok(())
}

use crate::support::{rig, TestResult, BASE_YAML, HUGE_SOFT};
use core_audit::log::open_file_log;
use core_config::reload::current_config;
use relay::app::{exit_code, lock_audit, main_exit, open_runtime, parse_args, refuse_root, run_from_args, run_main, run_runtime, stop_signals};
use relay::audit::{append_entry, lifecycle_entry, START_ACTION};
use relay::error::RelayError;
use relay::header::proxy_header;
use relay::model::{Options, Paths};
use rustix::process::{getpid, kill_process, Signal};
use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;


const IPV4_HEADER_BYTES: usize = 28;


const NON_ROOT: u32 = 1000;


const LOWERED: usize = 7;


const POLL_ATTEMPTS: usize = 400;


const POLL_STEP: Duration = Duration::from_millis(25);


const REAL_GRACE: Duration = Duration::from_secs(10);


const SIGNAL_WAIT: Duration = Duration::from_secs(10);


fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}


fn real_options() -> Options {
    Options {
        shutdown_grace: REAL_GRACE,
        ..Options::default()
    }
}


async fn echo_server() -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let served = listener.accept().await;
        if let Ok((mut stream, _peer)) = served {
            let (mut reader, mut writer) = stream.split();
            let mut header = [u8::MIN; IPV4_HEADER_BYTES];
            let read_header = reader.read_exact(&mut header).await;
            drop(read_header);
            let copied = tokio::io::copy(&mut reader, &mut writer).await;
            let closed = writer.shutdown().await;
            drop((copied, closed));
        }
    });
    Ok(address)
}


fn settings_text(listen: &str, upstream: &str) -> String {
    format!("listen: {listen}\nupstream: {upstream}\n")
}


fn stop_pair() -> (oneshot::Sender<()>, relay::types::ShutdownSignal) {
    let (sender, receiver) = oneshot::channel();
    (
        sender,
        Box::pin(async move {
            let outcome = receiver.await;
            drop(outcome);
        }),
    )
}


async fn connect_when_listening(address: std::net::SocketAddr) -> io::Result<TcpStream> {
    let mut connected = Err(io::Error::from(io::ErrorKind::NotConnected));
    for _attempt in 0..POLL_ATTEMPTS {
        if connected.is_err() {
            connected = TcpStream::connect(address).await;
            if connected.is_err() {
                tokio::time::sleep(POLL_STEP).await;
            }
        }
    }
    connected
}


async fn roundtrip(address: std::net::SocketAddr) -> TestResult {
    let mut client = connect_when_listening(address).await?;
    client.write_all(b"echo me").await?;
    client.shutdown().await?;
    let mut answer = String::new();
    client.read_to_string(&mut answer).await?;
    assert_eq!(answer, "echo me");
    Ok(())
}


async fn audit_contains(path: &Path, needle: &str) -> TestResult {
    let mut seen = false;
    for _attempt in 0..POLL_ATTEMPTS {
        seen = seen || std::fs::read_to_string(path)?.contains(needle);
        if !seen {
            tokio::time::sleep(POLL_STEP).await;
        }
    }
    assert!(seen, "{needle} never reached the audit file");
    Ok(())
}


#[test]
fn arguments_are_the_settings_and_audit_paths() -> TestResult {
    let paths = parse_args(&strings(&["relay.yaml", "audit.log"]))?;
    assert_eq!(paths.settings, Path::new("relay.yaml"));
    assert_eq!(paths.audit, Path::new("audit.log"));
    [strings(&[]), strings(&["one"]), strings(&["one", "two", "three"])]
        .iter()
        .for_each(|args| assert!(matches!(parse_args(args), Err(RelayError::Usage))));
    Ok(())
}


#[test]
fn root_is_refused() -> TestResult {
    assert!(matches!(refuse_root(0), Err(RelayError::Root)));
    assert!(refuse_root(NON_ROOT).is_ok());
    Ok(())
}


#[test]
fn the_exit_code_follows_the_result() -> TestResult {
    assert_eq!(format!("{:?}", exit_code(Ok(()))), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(format!("{:?}", exit_code(Err(RelayError::Usage))), format!("{:?}", ExitCode::FAILURE));
    Ok(())
}


#[tokio::test]
async fn running_as_root_is_refused_before_anything_is_opened() -> TestResult {
    let (_stop, signal) = stop_pair();
    let dir = tempfile::tempdir()?;
    let args = strings(&["settings", &dir.path().join("audit.log").display().to_string()]);
    let refused = run_from_args(&args, 0, signal).await;
    assert!(matches!(refused, Err(RelayError::Root)));
    assert!(!dir.path().join("audit.log").exists());
    assert!(matches!(run_main(&args, 0).await, Err(RelayError::Root)));
    Ok(())
}


#[tokio::test]
async fn bad_arguments_and_bad_settings_stop_the_start() -> TestResult {
    let (_stop, signal) = stop_pair();
    assert!(matches!(
        run_from_args(&strings(&["only"]), NON_ROOT, signal).await,
        Err(RelayError::Usage)
    ));
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    std::fs::write(&settings, "listen: 0.0.0.0:443\n")?;
    let args = strings(&[&settings.display().to_string(), &dir.path().join("audit.log").display().to_string()]);
    let (_other, second) = stop_pair();
    assert!(matches!(run_from_args(&args, NON_ROOT, second).await, Err(RelayError::Settings(_))));
    Ok(())
}


#[tokio::test]
async fn a_busy_listen_port_is_an_io_error() -> TestResult {
    let holder = TcpListener::bind("127.0.0.1:0").await?;
    let busy = holder.local_addr()?;
    let echo = echo_server().await?;
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    std::fs::write(&settings, settings_text(&busy.to_string(), &echo.to_string()))?;
    let args = strings(&[&settings.display().to_string(), &dir.path().join("audit.log").display().to_string()]);
    let (_stop, signal) = stop_pair();
    assert!(matches!(run_from_args(&args, NON_ROOT, signal).await, Err(RelayError::Io(_))));
    Ok(())
}


#[tokio::test]
async fn the_relay_forwards_audits_start_and_stop_and_reloads_on_file_change() -> TestResult {
    let echo = echo_server().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_address = listener.local_addr()?;
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    let audit = dir.path().join("audit.log");
    std::fs::write(&settings, settings_text("127.0.0.1:443", &echo.to_string()))?;
    let runtime = open_runtime(
        &Paths {
            settings: settings.clone(),
            audit: audit.clone(),
        },
        HUGE_SOFT,
    )?;
    let engine = std::sync::Arc::clone(&runtime.engine);
    let (stop, signal) = stop_pair();
    let running = tokio::spawn(run_runtime(runtime, listener, signal, real_options()));
    roundtrip(relay_address).await?;
    audit_contains(&audit, "relay.start").await?;
    let lowered = format!(
        "{}max_connections: {LOWERED}\nmax_connections_per_source: {LOWERED}\n",
        settings_text("127.0.0.1:443", &echo.to_string())
    );
    std::fs::write(&settings, lowered)?;
    audit_contains(&audit, "applied").await?;
    assert_eq!(current_config(&engine).max_connections, LOWERED);
    stop.send(()).map_err(|()| "stop dropped")?;
    timeout(SIGNAL_WAIT, running).await???;
    let text = std::fs::read_to_string(&audit)?;
    assert!(text.contains("relay.stop"));
    assert!(text.contains("\"cut\":\"0\""));
    Ok(())
}


#[tokio::test]
async fn run_from_args_binds_serves_and_stops() -> TestResult {
    let echo = echo_server().await?;
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let relay_address = probe.local_addr()?;
    drop(probe);
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    std::fs::write(&settings, settings_text(&relay_address.to_string(), &echo.to_string()))?;
    let args = strings(&[&settings.display().to_string(), &dir.path().join("audit.log").display().to_string()]);
    let (stop, signal) = stop_pair();
    let running = tokio::spawn(async move { run_from_args(&args, NON_ROOT, signal).await });
    roundtrip(relay_address).await?;
    stop.send(()).map_err(|()| "stop dropped")?;
    timeout(SIGNAL_WAIT, running).await???;
    Ok(())
}


#[tokio::test]
async fn sigterm_and_sigint_both_stop() -> TestResult {
    let terminate = stop_signals()?;
    kill_process(getpid(), Signal::TERM)?;
    timeout(SIGNAL_WAIT, terminate).await?;
    let interrupt = stop_signals()?;
    kill_process(getpid(), Signal::INT)?;
    timeout(SIGNAL_WAIT, interrupt).await?;
    Ok(())
}


#[tokio::test]
async fn main_exit_fails_without_valid_arguments() -> TestResult {
    let code = main_exit(Vec::new()).await;
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    Ok(())
}


#[test]
fn the_binary_exits_with_failure_and_no_arguments() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_ostyr-relay")).output()?;
    assert!(!output.status.success());
    Ok(())
}


#[test]
fn lifecycle_records_keep_only_declared_parameters() -> TestResult {
    let dir = tempfile::tempdir()?;
    let log = open_file_log(&dir.path().join("audit.log"))?;
    let entry = lifecycle_entry(
        Path::new("relay.yaml"),
        START_ACTION,
        &[("listen", "0.0.0.0:443".to_owned()), ("secret", "hunter2".to_owned())],
    );
    let record = append_entry(&log, entry)?;
    assert_eq!(record.parameters.get("listen").map(String::as_str), Some("0.0.0.0:443"));
    assert_eq!(record.parameters.get("secret").map(String::as_str), Some("[REDACTED]"));
    assert_eq!(record.action, START_ACTION);
    Ok(())
}


#[test]
fn the_rig_builds() -> TestResult {
    let built = rig(BASE_YAML)?;
    assert!(built.dir.path().exists());
    Ok(())
}


async fn header_server() -> io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<io::Result<Vec<u8>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let reading = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        let mut header = [u8::MIN; IPV4_HEADER_BYTES];
        stream.read_exact(&mut header).await?;
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await?;
        Ok([header.to_vec(), rest].concat())
    });
    Ok((address, reading))
}


#[tokio::test]
async fn the_first_upstream_bytes_are_the_proxy_header_of_the_accepted_socket() -> TestResult {
    let (upstream, reading) = header_server().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_address = listener.local_addr()?;
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    std::fs::write(&settings, settings_text("127.0.0.1:443", &upstream.to_string()))?;
    let runtime = open_runtime(
        &Paths {
            settings,
            audit: dir.path().join("audit.log"),
        },
        HUGE_SOFT,
    )?;
    let (stop, signal) = stop_pair();
    let running = tokio::spawn(run_runtime(runtime, listener, signal, real_options()));
    let mut client = connect_when_listening(relay_address).await?;
    let client_address = client.local_addr()?;
    client.write_all(b"after").await?;
    client.shutdown().await?;
    let received = timeout(SIGNAL_WAIT, reading).await???;
    let expected = [proxy_header(client_address, relay_address), b"after".to_vec()].concat();
    assert_eq!(received, expected);
    stop.send(()).map_err(|()| "stop dropped")?;
    timeout(SIGNAL_WAIT, running).await???;
    Ok(())
}


#[test]
fn a_second_relay_on_one_audit_file_is_a_named_start_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let settings = dir.path().join("relay.yaml");
    std::fs::write(&settings, settings_text("127.0.0.1:443", "127.0.0.1:8443"))?;
    let paths = Paths {
        settings,
        audit: dir.path().join("audit.log"),
    };
    let first = open_runtime(&paths, HUGE_SOFT)?;
    let second = open_runtime(&paths, HUGE_SOFT);
    let refused = second.err().ok_or("the second start was accepted")?;
    assert!(matches!(refused, RelayError::AuditLocked(_)));
    assert!(refused.to_string().contains("held by another relay"));
    drop(first);
    Ok(())
}


#[test]
fn locking_a_missing_audit_file_is_an_io_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = lock_audit(&dir.path().join("absent.log"));
    assert!(matches!(missing, Err(RelayError::Io(_))));
    Ok(())
}

#![cfg(unix)]


#[path = "common/private.rs"]
mod private;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{current_config, reload, ReloadOutcome};
use core_pg::scope::tenant_scope;
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use private::write_private;
use rcgen::SanType;
use std::cell::Cell;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use synthetic_checks::error::ProbeError;
use synthetic_checks::load::load_checks;
use synthetic_checks::model::{Check, CheckFile};
use synthetic_checks::probe::{FetchCaps, HttpRequest, HttpResponse};
use synthetic_checks::round::{new_runner, reload_checks, RoundReport};
use synthetic_checks::serve::{
    apply_live, boxed_reload_audit, explicit_port, failure_label, finish_code, last_refused, literal_target, live_state, load_service, log_round,
    open_live, pause, probe_check, run_probe, run_service, seconds_since_epoch, serve_rounds, skip_refused_literals, start_with, stop_on_signals,
    store_alerts, system_resolve, validate_service, Applied, Finish, LiveConfig, ProbeTools, Refusals, RunControl, ServiceSettings,
    FAILURE_EXIT_CODE, IDLE_SUMMARY_ROUNDS, PAUSE_SLICE, ROUND_CAP_EXIT_CODE,
};
use synthetic_checks::target::METADATA_V4;
use tempfile::tempdir;
use types::TestResult;


const CHILD_MARKER_GUARD: Duration = Duration::from_secs(600);


const LAST_LINES_SHOWN: usize = 20;


const WAIT_TEST_GUARD: Duration = Duration::from_millis(200);


const WAIT_TEST_HANG_GUARD: Duration = Duration::from_secs(30);


const WAIT_TEST_LINE_PERIOD: Duration = Duration::from_millis(5);


const MAX_LINES_READ: usize = 1_000_000;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-synthetic");


const PG_PASSWORD: &str = "p";


const CLOSED_PORT: u16 = 1;


const FOUR_ROUNDS: usize = 4;


const FIVE_ROUNDS: usize = 5;


const TWO_FAILED_INSERTS: usize = 2;


const TEN_SECONDS: u64 = 10;


const SLICES_PER_PAUSE: usize = 10;


const HTTP_PORT: u16 = 8080;


const TLS_DEFAULT_PORT: u16 = 443;


const SERVING_MARKER: &str = "serving";


const ROUND_MARKER: &str = "probed=";


const OUTSIDE_TARGET: &str = "10.255.255.1:9";


const STATUS_OK: u16 = 200;


const STATUS_UNAVAILABLE: u16 = 503;


const CHAIN: [u8; 3] = [1, 2, 3];


const PRIVATE_OCTET: u8 = 10;


const SECOND: u8 = 2;


const THIRD: u8 = 3;


const SECOND_GENERATION: u64 = 2;


const TWO_CHECKS: usize = 2;


const TWO_ROUNDS: usize = 2;


const SECRET_HOST: &str = "secret-host.internal";


fn service_text(dir: &Path, tenant: &str, location: &str) -> String {
    format!(
        "tenant: {tenant}\nlocation: {location}\nchecks_file: {}\npg_settings: {}\naudit_file: {}\n",
        dir.join("checks.yaml").display(),
        dir.join("pg.yaml").display(),
        dir.join("audit.log").display()
    )
}


fn write_site(dir: &Path, port: u16, ca_pem: &str, checks: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_private(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    fs::write(dir.join("checks.yaml"), checks)?;
    let settings_file = dir.join("synthetic.yaml");
    fs::write(&settings_file, service_text(dir, "acme", "paris"))?;
    Ok(settings_file)
}


struct Site {
    fake: Fake,
    inserts: Arc<AtomicUsize>,
    settings_file: PathBuf,
}


fn handler(inserts: Arc<AtomicUsize>, failing: usize) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("jsonb_to_recordset") {
            if inserts.fetch_add(1, Ordering::SeqCst) < failing {
                Reply::Error("insert refused")
            } else {
                Reply::Rows(vec![vec!["1".to_owned()]])
            }
        } else {
            Reply::Done
        }
    })
}


async fn site(dir: &Path, checks: &str, failing: usize) -> Result<Site, Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let inserts = Arc::new(AtomicUsize::new(0));
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler(Arc::clone(&inserts), failing)).await?;
    let settings_file = write_site(dir, fake.port, &pki.ca_pem, checks)?;
    Ok(Site {
        fake,
        inserts,
        settings_file,
    })
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut running = spawn_child(Command::new(PROGRAM).args(arguments))?;
    let lines = drain_lines(&running.lines, CHILD_MARKER_GUARD)?;
    let status = running.child.wait()?;
    Ok(Output {
        status,
        stdout: Vec::new(),
        stderr: lines.iter().map(|line| format!("{line}\n")).collect::<String>().into_bytes(),
    })
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn last_lines(seen: &[String]) -> String {
    seen.iter()
        .skip(seen.len().saturating_sub(LAST_LINES_SHOWN))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}


fn wait_for_either_within(lines: &Receiver<String>, first: &str, second: &str, guard: Duration) -> Result<String, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + guard;
    let mut seen: Vec<String> = Vec::new();
    let outcome = std::iter::repeat_with(|| lines.recv_timeout(deadline.saturating_duration_since(Instant::now())))
        .take(MAX_LINES_READ)
        .find_map(|received| match received {
            Ok(text) if text.contains(first) || text.contains(second) => Some(Ok(text)),
            Ok(text) => {
                seen.push(text);
                None
            }
            Err(failure) => Some(Err(failure)),
        });
    match outcome {
        Some(Ok(text)) => Ok(text),
        Some(Err(RecvTimeoutError::Timeout)) => {
            Err(format!("no marker {first:?} or {second:?} within {guard:?}; last lines:\n{}", last_lines(&seen)).into())
        }
        Some(Err(RecvTimeoutError::Disconnected)) => Err(format!("the child ended before a marker; last lines:\n{}", last_lines(&seen)).into()),
        None => Err(format!("no marker in {MAX_LINES_READ} lines; last lines:\n{}", last_lines(&seen)).into()),
    }
}


fn wait_for_either(lines: &Receiver<String>, first: &str, second: &str) -> Result<String, Box<dyn std::error::Error>> {
    wait_for_either_within(lines, first, second, CHILD_MARKER_GUARD)
}


fn wait_for(lines: &Receiver<String>, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    wait_for_either(lines, marker, marker)
}


fn drain_lines(lines: &Receiver<String>, guard: Duration) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + guard;
    let mut seen: Vec<String> = Vec::new();
    let end = std::iter::repeat_with(|| lines.recv_timeout(deadline.saturating_duration_since(Instant::now())))
        .take(MAX_LINES_READ)
        .find_map(|received| match received {
            Ok(text) => {
                seen.push(text);
                None
            }
            Err(failure) => Some(failure),
        });
    match end {
        Some(RecvTimeoutError::Disconnected) => Ok(seen),
        Some(RecvTimeoutError::Timeout) => Err(format!("the child did not end within {guard:?}; last lines:\n{}", last_lines(&seen)).into()),
        None => Err(format!("the child wrote more than {MAX_LINES_READ} lines; last lines:\n{}", last_lines(&seen)).into()),
    }
}


#[test]
fn a_wait_ends_at_one_deadline_while_the_child_never_stops_writing() -> TestResult {
    let (sender, lines) = channel::<String>();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer = thread::spawn(move || {
        std::iter::repeat_with(|| {
            thread::sleep(WAIT_TEST_LINE_PERIOD);
            sender.send("round".to_owned())
        })
        .take(MAX_LINES_READ)
        .take_while(|sent| sent.is_ok() && !writer_stop.load(Ordering::SeqCst))
        .count()
    });
    let (outcome_sender, outcome) = channel();
    let waiter = thread::spawn(move || {
        let waited = wait_for_either_within(&lines, "never-a", "never-b", WAIT_TEST_GUARD).map_err(|failure| failure.to_string());
        outcome_sender.send(waited)
    });
    let received = outcome.recv_timeout(WAIT_TEST_HANG_GUARD);
    stop.store(true, Ordering::SeqCst);
    let waited = received.map_err(|_| "the wait did not end at its deadline: the guard is applied per line")?;
    assert!(waited.is_err_and(|text| text.contains("no marker") && text.contains("round")));
    waiter.join().map_err(|_| "waiter panicked")??;
    writer.join().map_err(|_| "writer panicked")?;
    Ok(())
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


struct Running {
    child: Child,
    lines: Receiver<String>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(failure) = self.child.kill() {
            tracing::warn!(%failure, "the test service could not be killed");
        }
        if let Err(failure) = self.child.wait() {
            tracing::warn!(%failure, "the test service could not be reaped");
        }
    }
}


fn spawn_child(command: &mut Command) -> Result<Running, Box<dyn std::error::Error>> {
    let mut child = command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    thread::spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .try_for_each(|line| sender.send(line))
    });
    Ok(Running { child, lines })
}


fn spawn_service(settings_file: &Path) -> Result<Running, Box<dyn std::error::Error>> {
    spawn_child(Command::new(PROGRAM).arg(settings_file))
}


fn finish(running: &mut Running) -> Result<String, Box<dyn std::error::Error>> {
    let rest = drain_lines(&running.lines, CHILD_MARKER_GUARD)?.join("\n");
    let exit = running.child.wait()?;
    assert_eq!(exit.code(), Some(0), "{rest}");
    Ok(rest)
}


fn live_of(dir: &Path, yaml: &str) -> Result<LiveConfig, Box<dyn std::error::Error>> {
    let file = dir.join("live-checks.yaml");
    fs::write(&file, yaml)?;
    Ok(LiveConfig {
        settings: ServiceSettings {
            tenant: "acme".to_owned(),
            location: "paris".to_owned(),
            checks_file: file.clone(),
            pg_settings: dir.join("pg.yaml"),
            audit_file: dir.join("audit.log"),
        },
        checks: load_checks(&file)?,
        roots: vec![vec![1]],
        generation: 1,
        skipped: 0,
    })
}


fn one_check(kind: &str, target: &str) -> String {
    format!("scope: [127.0.0.0/8, \"::1/128\"]\nchecks:\n  - name: probe\n    kind: {kind}\n    target: {target}\n    interval_seconds: 10\n    locations: [paris]\n")
}


struct Net {
    refuse_connect: AtomicBool,
    roots_seen: AtomicUsize,
    answers: Vec<IpAddr>,
    port_seen: AtomicU64,
    resolves: AtomicUsize,
}


fn net(answers: Vec<IpAddr>) -> Net {
    Net {
        refuse_connect: AtomicBool::new(false),
        roots_seen: AtomicUsize::new(0),
        answers,
        port_seen: AtomicU64::new(0),
        resolves: AtomicUsize::new(0),
    }
}


fn with_tools<Output>(fake: &Net, clock_seconds: &AtomicU64, body: impl FnOnce(&ProbeTools) -> Output) -> Output {
    let resolve = |_name: &str, _left: Duration, _cap: usize| {
        fake.resolves.fetch_add(1, Ordering::SeqCst);
        Ok(fake.answers.clone())
    };
    let fetch = |_request: &HttpRequest, _left: Duration, _caps: FetchCaps, roots: &[Vec<u8>]| {
        fake.roots_seen.store(roots.len(), Ordering::SeqCst);
        Ok(HttpResponse {
            status: STATUS_OK,
            location: None,
            body: Vec::new(),
            certificate_chain: Vec::new(),
            certificate_verified: None,
        })
    };
    let connect = |_socket: SocketAddr, _left: Duration| {
        if fake.refuse_connect.load(Ordering::SeqCst) {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        } else {
            Ok(())
        }
    };
    let ping = |_address: IpAddr, _left: Duration| Ok(());
    let handshake = |socket: SocketAddr, _name: &str, _left: Duration, _certs: usize, _bytes: usize| {
        fake.port_seen.store(u64::from(socket.port()), Ordering::SeqCst);
        Ok(vec![CHAIN.to_vec()])
    };
    let clock = || Duration::from_secs(clock_seconds.load(Ordering::SeqCst));
    body(&ProbeTools {
        resolve: &resolve,
        fetch: &fetch,
        connect: &connect,
        ping: &ping,
        handshake: &handshake,
        clock: &clock,
    })
}


fn probe_one(dir: &Path, kind: &str, target: &str, fake: &Net) -> Result<Result<bool, String>, Box<dyn std::error::Error>> {
    let live = live_of(dir, &one_check(kind, target))?;
    let check = live.checks.checks.first().ok_or("no check")?.clone();
    let clock = AtomicU64::new(0);
    let outcome = with_tools(fake, &clock, |tools| run_probe(&check, &live, tools));
    Ok(outcome.map(|done| done.succeeded).map_err(|failure| failure_label(&failure).to_owned()))
}


#[test]
fn every_kind_probes_through_its_transport() -> TestResult {
    let dir = tempdir()?;
    let fake = net(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert_eq!(probe_one(dir.path(), "http", "http://127.0.0.1:8080/", &fake)?, Ok(true));
    assert_eq!(fake.roots_seen.load(Ordering::SeqCst), 1);
    assert_eq!(probe_one(dir.path(), "tcp", &format!("127.0.0.1:{HTTP_PORT}"), &fake)?, Ok(true));
    assert_eq!(probe_one(dir.path(), "tls", "127.0.0.1", &fake)?, Ok(true));
    assert_eq!(fake.port_seen.load(Ordering::SeqCst), u64::from(TLS_DEFAULT_PORT));
    assert_eq!(probe_one(dir.path(), "icmp", "127.0.0.1", &fake)?, Ok(true));
    assert_eq!(probe_one(dir.path(), "icmp", "::1", &fake)?, Ok(true));
    assert_eq!(probe_one(dir.path(), "icmp", "peer.test", &fake)?, Ok(true));
    assert_eq!(probe_one(dir.path(), "dns", "peer.test", &fake)?, Ok(true));
    assert_eq!(probe_one(dir.path(), "tcp", "peer.test:80", &fake)?, Ok(true));
    Ok(())
}


#[test]
fn a_refused_timed_out_or_unusable_target_fails_with_a_fixed_label() -> TestResult {
    let dir = tempdir()?;
    let fake = net(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert_eq!(probe_one(dir.path(), "tcp", "10.255.255.1:9", &fake)?, Err("refused".to_owned()));
    assert_eq!(probe_one(dir.path(), "icmp", "10.255.255.1", &fake)?, Err("refused".to_owned()));
    assert_eq!(probe_one(dir.path(), "tcp", "127.0.0.1", &fake)?, Err("failed".to_owned()));
    assert_eq!(probe_one(dir.path(), "tcp", "/x", &fake)?, Err("failed".to_owned()));
    assert_eq!(probe_one(dir.path(), "tcp", "bad host:80", &fake)?, Err("failed".to_owned()));
    fake.refuse_connect.store(true, Ordering::SeqCst);
    assert_eq!(probe_one(dir.path(), "tcp", "127.0.0.1:80", &fake)?, Err("timeout".to_owned()));
    let nobody = net(Vec::new());
    assert_eq!(probe_one(dir.path(), "tcp", "peer.test:80", &nobody)?, Err("failed".to_owned()));
    assert_eq!(probe_one(dir.path(), "icmp", "peer.test", &nobody)?, Err("failed".to_owned()));
    Ok(())
}


#[test]
fn probe_check_counts_refusals_and_logs_no_target() -> TestResult {
    let dir = tempdir()?;
    let live = live_of(dir.path(), &one_check("tcp", &format!("{SECRET_HOST}:80")))?;
    let check = live.checks.checks.first().ok_or("no check")?.clone();
    let fake = net(vec![IpAddr::V4(Ipv4Addr::new(PRIVATE_OCTET, 1, SECOND, THIRD))]);
    let refused = Refusals::default();
    let clock = AtomicU64::new(0);
    let verdict = with_tools(&fake, &clock, |tools| probe_check(&check, &live, tools, &refused));
    assert!(!verdict);
    assert_eq!(refused.total.load(Ordering::SeqCst), 1);
    assert!(last_refused(&refused, &check));
    let ok_live = live_of(dir.path(), &one_check("tcp", "127.0.0.1:80"))?;
    let ok_check: &Check = ok_live.checks.checks.first().ok_or("no check")?;
    assert!(with_tools(&fake, &clock, |tools| probe_check(ok_check, &ok_live, tools, &refused)));
    assert!(!last_refused(&refused, &check));
    let http_live = live_of(dir.path(), &one_check("http", "http://127.0.0.1:8080/"))?;
    let http_check = http_live.checks.checks.first().ok_or("no check")?;
    assert!(with_tools(&fake, &clock, |tools| probe_check(http_check, &http_live, tools, &refused)));
    assert_eq!(refused.total.load(Ordering::SeqCst), 1);
    Ok(())
}


#[test]
fn a_status_that_is_not_a_success_fails_without_an_error() -> TestResult {
    let dir = tempdir()?;
    let live = live_of(dir.path(), &one_check("http", "http://127.0.0.1:8080/"))?;
    let check = live.checks.checks.first().ok_or("no check")?.clone();
    let calls = Cell::new(0);
    let resolve = |_name: &str, _left: Duration, _cap: usize| Ok(Vec::new());
    let fetch = |_request: &HttpRequest, _left: Duration, _caps: FetchCaps, _roots: &[Vec<u8>]| {
        calls.set(calls.get() + 1);
        Ok(HttpResponse {
            status: STATUS_UNAVAILABLE,
            location: None,
            body: Vec::new(),
            certificate_chain: Vec::new(),
            certificate_verified: None,
        })
    };
    let connect = |_socket: SocketAddr, _left: Duration| Ok(());
    let ping = |_address: IpAddr, _left: Duration| Ok(());
    let handshake = |_socket: SocketAddr, _name: &str, _left: Duration, _certs: usize, _bytes: usize| Ok(Vec::new());
    let clock = || Duration::ZERO;
    let tools = ProbeTools {
        resolve: &resolve,
        fetch: &fetch,
        connect: &connect,
        ping: &ping,
        handshake: &handshake,
        clock: &clock,
    };
    assert!(!probe_check(&check, &live, &tools, &Refusals::default()));
    assert_eq!(calls.get(), 1);
    assert_eq!(failure_label(&ProbeError::NoAddress), "failed");
    Ok(())
}


#[test]
fn the_system_resolver_answers_localhost() -> TestResult {
    let answers = system_resolve("localhost", Duration::from_secs(TEN_SECONDS), 1)?;
    assert!(answers.iter().all(IpAddr::is_loopback));
    Ok(())
}


#[test]
fn a_duplicate_name_in_a_new_generation_is_logged_and_keeps_the_old_checks() -> TestResult {
    let dir = tempdir()?;
    let live = live_of(dir.path(), &one_check("tcp", "127.0.0.1:80"))?;
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    let first_state = apply_live(&mut runner, &live, Applied::default());
    assert_eq!(first_state, Applied { applied: 1, refused: 0 });
    assert_eq!(runner.states.len(), 1);
    let mut twice = live.clone();
    twice.generation = SECOND_GENERATION;
    let first = twice.checks.checks.first().ok_or("no check")?.clone();
    twice.checks.checks.push(first);
    let refused_state = apply_live(&mut runner, &twice, first_state);
    assert_eq!(
        refused_state,
        Applied {
            applied: 1,
            refused: SECOND_GENERATION
        }
    );
    assert_eq!(runner.states.len(), 1);
    assert_eq!(apply_live(&mut runner, &twice, refused_state), refused_state);
    reload_checks(&mut runner, &live.checks.checks)?;
    Ok(())
}


#[test]
fn the_pause_sleeps_in_slices_and_stops_at_the_flag() -> TestResult {
    let slept = Cell::new(0);
    let stop = AtomicBool::new(false);
    let sleep = |slice: Duration| {
        assert_eq!(slice, PAUSE_SLICE);
        slept.set(slept.get() + 1);
    };
    let control = RunControl {
        rounds: 1,
        stop: &stop,
        sleep: &sleep,
    };
    pause(&control, Duration::from_secs(1));
    assert_eq!(slept.get(), SLICES_PER_PAUSE);
    stop.store(true, Ordering::SeqCst);
    pause(&control, Duration::from_secs(1));
    assert_eq!(slept.get(), SLICES_PER_PAUSE);
    Ok(())
}


#[test]
fn a_clock_before_the_epoch_reads_zero() -> TestResult {
    let before = UNIX_EPOCH.duration_since(SystemTime::now());
    assert_eq!(seconds_since_epoch(before), 0);
    assert_eq!(seconds_since_epoch(Ok(Duration::from_secs(TEN_SECONDS))), TEN_SECONDS);
    Ok(())
}


#[test]
fn the_exit_codes_are_named() -> TestResult {
    let mut out = Vec::new();
    assert_eq!(finish_code(Ok(Finish::Interrupted), &mut out)?, 0);
    assert_eq!(finish_code(Ok(Finish::RoundCap), &mut out)?, ROUND_CAP_EXIT_CODE);
    assert!(out.is_empty());
    assert_eq!(finish_code(Err("boom".into()), &mut out)?, FAILURE_EXIT_CODE);
    assert_eq!(String::from_utf8(out)?, "boom\n");
    Ok(())
}


#[test]
fn the_stop_signals_register_and_leave_the_flag_clear() -> TestResult {
    let flag = stop_on_signals()?;
    assert!(!flag.load(Ordering::SeqCst));
    Ok(())
}


fn broken_stop_source() -> io::Result<Arc<AtomicBool>> {
    Err(io::Error::other("no signals"))
}


#[test]
fn run_service_refuses_a_bad_usage_and_a_failing_stop_source() -> TestResult {
    let usage = run_service(&[], broken_stop_source).err().ok_or("accepted")?;
    assert!(usage.to_string().contains("usage: ostyr-synthetic"));
    let arguments = ["/absent/synthetic.yaml".to_owned()];
    let first = run_service(&arguments, broken_stop_source).err().ok_or("accepted")?;
    assert!(first.to_string().contains("no signals"), "{first}");
    let second = run_service(&arguments, broken_stop_source).err().ok_or("accepted")?;
    assert!(!second.to_string().is_empty());
    Ok(())
}


#[test]
fn service_settings_need_absolute_paths_and_known_keys() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("synthetic.yaml");
    let base = service_text(dir.path(), "acme", "paris");
    fs::write(&file, &base)?;
    assert_eq!(load_service(&file)?.tenant, "acme");
    let relative_audit = base.replace(&dir.path().join("audit.log").display().to_string(), "audit.log");
    fs::write(&file, relative_audit)?;
    assert!(load_service(&file).err().ok_or("accepted")?.to_string().contains("audit_file"));
    let relative_pg = base.replace(&dir.path().join("pg.yaml").display().to_string(), "pg.yaml");
    fs::write(&file, relative_pg)?;
    assert!(load_service(&file).err().ok_or("accepted")?.to_string().contains("pg_settings"));
    let relative_checks = base.replace(&dir.path().join("checks.yaml").display().to_string(), "checks.yaml");
    fs::write(&file, relative_checks)?;
    assert!(load_service(&file).err().ok_or("accepted")?.to_string().contains("checks_file"));
    fs::write(&file, format!("{base}extra: 1\n"))?;
    assert!(load_service(&file).is_err());
    let settings = ServiceSettings {
        tenant: "a".to_owned(),
        location: "p".to_owned(),
        checks_file: PathBuf::from("/c"),
        pg_settings: PathBuf::from("/p"),
        audit_file: PathBuf::from("/a"),
    };
    assert!(validate_service(&settings).is_ok());
    Ok(())
}


#[test]
fn the_reload_engine_applies_checks_and_refuses_a_start_only_change_whole() -> TestResult {
    let dir = tempdir()?;
    let two = format!(
        "{}  - name: second\n    kind: tcp\n    target: {SECRET_HOST}:81\n    locations: [paris]\n",
        one_check("tcp", "127.0.0.1:80")
    );
    let settings_file = write_site(dir.path(), CLOSED_PORT, "", &one_check("tcp", "127.0.0.1:80"))?;
    let log = Arc::new(core_audit::log::open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_live(&settings_file, load_service(&settings_file)?, boxed_reload_audit(&log))?;
    assert_eq!(current_config(&engine).checks.checks.len(), 1);
    assert!(matches!(reload(&engine), ReloadOutcome::Unchanged));
    fs::write(dir.path().join("checks.yaml"), &two)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).checks.checks.len(), TWO_CHECKS);
    fs::write(dir.path().join("checks.yaml"), "checks: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).checks.checks.len(), TWO_CHECKS);
    fs::write(dir.path().join("checks.yaml"), one_check("tcp", "127.0.0.1:80"))?;
    fs::write(&settings_file, service_text(dir.path(), "acme", "lyon"))?;
    let refused = reload(&engine);
    assert!(
        matches!(&refused, ReloadOutcome::Refused { reason } if reason.contains("start-only")),
        "{refused:?}"
    );
    assert_eq!(current_config(&engine).checks.checks.len(), TWO_CHECKS);
    fs::write(&settings_file, service_text(dir.path(), "acme", "paris"))?;
    fs::write(
        dir.path().join("checks.yaml"),
        format!(
            "ca_file: {}\n{}",
            dir.path().join("absent-ca.pem").display(),
            one_check("tcp", "127.0.0.1:80")
        ),
    )?;
    let no_ca = reload(&engine);
    assert!(
        matches!(&no_ca, ReloadOutcome::Refused { reason } if reason.contains("ca_file")),
        "{no_ca:?}"
    );
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    assert!(audit.contains("config.reload"));
    assert!(!audit.contains(SECRET_HOST));
    assert!(!audit.contains("127.0.0.1"));
    let state = live_state(&current_config(&engine));
    assert_eq!(state.get("checks").map(String::as_str), Some("2"));
    Ok(())
}


struct Hooks {
    stop: Arc<AtomicBool>,
    connect_down: bool,
}


fn drive(settings_file: PathBuf, rounds: usize, hooks: Hooks) -> Result<Finish, String> {
    let fake = net(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    fake.refuse_connect.store(hooks.connect_down, Ordering::SeqCst);
    let clock_seconds = AtomicU64::new(TEN_SECONDS);
    let sleep = |_slice: Duration| {
        clock_seconds.fetch_add(1, Ordering::SeqCst);
    };
    with_tools(&fake, &clock_seconds, |tools| {
        let control = RunControl {
            rounds,
            stop: &hooks.stop,
            sleep: &sleep,
        };
        start_with(load_service, &settings_file, &control, tools).map_err(|failure| failure.to_string())
    })
}


fn failing_tcp_checks() -> String {
    "scope: [127.0.0.0/8]\nchecks:\n  - name: down\n    kind: tcp\n    target: 127.0.0.1:80\n    interval_seconds: 10\n    consecutive_failures: 2\n    locations: [paris]\n"
        .to_owned()
}


#[tokio::test(flavor = "multi_thread")]
async fn an_outage_is_stored_once_after_its_failed_rounds_and_not_again() -> TestResult {
    let dir = tempdir()?;
    let site = site(dir.path(), &failing_tcp_checks(), 0).await?;
    let hooks = Hooks {
        stop: Arc::new(AtomicBool::new(false)),
        connect_down: true,
    };
    let file = site.settings_file.clone();
    let finish = tokio::task::spawn_blocking(move || drive(file, FIVE_ROUNDS, hooks)).await??;
    assert_eq!(finish, Finish::RoundCap);
    assert_eq!(site.inserts.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_store_that_fails_is_retried_on_the_next_round_until_it_accepts() -> TestResult {
    let dir = tempdir()?;
    let site = site(dir.path(), &failing_tcp_checks(), TWO_FAILED_INSERTS).await?;
    let hooks = Hooks {
        stop: Arc::new(AtomicBool::new(false)),
        connect_down: true,
    };
    let file = site.settings_file.clone();
    let finish = tokio::task::spawn_blocking(move || drive(file, FIVE_ROUNDS + FOUR_ROUNDS, hooks)).await??;
    assert_eq!(finish, Finish::RoundCap);
    assert_eq!(site.inserts.load(Ordering::SeqCst), TWO_FAILED_INSERTS + 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_flag_set_before_the_first_round_runs_no_round() -> TestResult {
    let dir = tempdir()?;
    let site = site(dir.path(), &failing_tcp_checks(), 0).await?;
    let hooks = Hooks {
        stop: Arc::new(AtomicBool::new(true)),
        connect_down: true,
    };
    let file = site.settings_file.clone();
    let finish = tokio::task::spawn_blocking(move || drive(file, FIVE_ROUNDS, hooks)).await??;
    assert_eq!(finish, Finish::Interrupted);
    assert_eq!(site.inserts.load(Ordering::SeqCst), 0);
    Ok(())
}


fn read_then_swap_the_audit_path(path: &Path) -> Result<ServiceSettings, core_config::error::ConfigError> {
    let loaded = load_service(path)?;
    let text = fs::read_to_string(path).map_err(|failure| core_config::error::ConfigError::WatchedFile {
        file: "test".to_owned(),
        reason: failure.to_string(),
    })?;
    fs::write(path, text.replace("audit.log", "elsewhere.log")).map_err(|failure| core_config::error::ConfigError::WatchedFile {
        file: "test".to_owned(),
        reason: failure.to_string(),
    })?;
    Ok(loaded)
}


#[tokio::test(flavor = "multi_thread")]
async fn the_audit_path_and_the_baseline_come_from_the_first_start_read() -> TestResult {
    let dir = tempdir()?;
    let site = site(dir.path(), &failing_tcp_checks(), 0).await?;
    let file = site.settings_file.clone();
    let refusal = tokio::task::spawn_blocking(move || {
        let stop = AtomicBool::new(false);
        let sleep = |_slice: Duration| ();
        let fake = net(Vec::new());
        let clock = AtomicU64::new(0);
        with_tools(&fake, &clock, |tools| {
            let control = RunControl {
                rounds: 1,
                stop: &stop,
                sleep: &sleep,
            };
            start_with(read_then_swap_the_audit_path, &file, &control, tools).map_err(|failure| failure.to_string())
        })
    })
    .await?
    .err()
    .ok_or("the swap was accepted")?;
    assert!(refusal.contains("start-only"), "{refusal}");
    assert!(dir.path().join("audit.log").exists());
    assert!(!dir.path().join("elsewhere.log").exists());
    Ok(())
}


#[test]
fn a_store_call_with_no_database_fails_and_keeps_no_session() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "", &failing_tcp_checks())?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let session = Mutex::new(None);
    let scope = tenant_scope("acme")?;
    assert!(store_alerts(&runtime, &session, &pg, &scope, &[]).is_err());
    assert!(session.lock().map_err(|_poisoned| "poisoned")?.is_none());
    assert!(settings_file.exists());
    Ok(())
}


#[test]
fn serve_rounds_returns_at_the_cap_without_a_store_call_when_nothing_fails() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "", &one_check("tcp", "127.0.0.1:80"))?;
    let log = Arc::new(core_audit::log::open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_live(&settings_file, load_service(&settings_file)?, boxed_reload_audit(&log))?;
    let scope = tenant_scope("acme")?;
    let mut runner = new_runner(&scope, "paris")?;
    let stores = Cell::new(0);
    let store = |_alerts: &[alerts::model::Alert]| {
        stores.set(stores.get() + 1);
        Ok(0)
    };
    let stop = AtomicBool::new(false);
    let sleep = |_slice: Duration| ();
    let fake = net(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let clock = AtomicU64::new(0);
    let finish = with_tools(&fake, &clock, |tools| {
        let control = RunControl {
            rounds: TWO_ROUNDS,
            stop: &stop,
            sleep: &sleep,
        };
        serve_rounds(&mut runner, &engine, &scope, &store, tools, &control)
    });
    assert_eq!(finish, Finish::RoundCap);
    assert_eq!(stores.get(), 0);
    Ok(())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-synthetic <service.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-synthetic")
}


#[test]
fn an_unreadable_or_invalid_service_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let file = dir.path().join("synthetic.yaml");
    fs::write(&file, "tenant: [\n")?;
    refused_with(&run_to_end(&[&file])?, "synthetic.yaml")
}


#[test]
fn a_service_file_without_an_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("synthetic.yaml");
    fs::write(
        &file,
        format!(
            "tenant: acme\nlocation: paris\nchecks_file: {}\npg_settings: {}\n",
            dir.path().join("checks.yaml").display(),
            dir.path().join("pg.yaml").display()
        ),
    )?;
    refused_with(&run_to_end(&[&file])?, "audit_file")
}


#[test]
fn a_bad_tenant_or_location_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let file = write_site(dir.path(), CLOSED_PORT, "", &failing_tcp_checks())?;
    fs::write(&file, service_text(dir.path(), "-x", "paris"))?;
    let tenant = run_to_end(&[&file])?;
    assert_eq!(tenant.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!tenant.stderr.is_empty());
    fs::write(&file, service_text(dir.path(), "acme", "\"p\u{e9}\""))?;
    let location = run_to_end(&[&file])?;
    assert_eq!(location.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn a_checks_file_with_an_alias_or_a_missing_pg_file_or_database_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let aliased = "scope: []\nchecks:\n  - &one\n    name: a\n    kind: tcp\n    target: 127.0.0.1:80\n    locations: [paris]\n  - *one\n";
    let file = write_site(dir.path(), CLOSED_PORT, "", aliased)?;
    refused_with(&run_to_end(&[&file])?, "alias")?;
    fs::write(dir.path().join("checks.yaml"), failing_tcp_checks())?;
    let unreachable = run_to_end(&[&file])?;
    assert_eq!(unreachable.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    fs::remove_file(dir.path().join("pg.yaml"))?;
    refused_with(&run_to_end(&[&file])?, "pg.yaml")
}


#[test]
fn an_unwritable_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let file = write_site(dir.path(), CLOSED_PORT, "", &failing_tcp_checks())?;
    let missing = dir.path().join("absent").join("audit.log");
    let text = fs::read_to_string(&file)?.replace(&dir.path().join("audit.log").display().to_string(), &missing.display().to_string());
    fs::write(&file, text)?;
    let output = run_to_end(&[&file])?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!missing.exists());
    Ok(())
}


fn served_checks(listener: &TcpListener) -> Result<String, Box<dyn std::error::Error>> {
    let port = listener.local_addr()?.port();
    Ok(format!(
        "scope: [127.0.0.0/8]\nchecks:\n  - name: reach\n    kind: tcp\n    target: 127.0.0.1:{port}\n    interval_seconds: 10\n    locations: [paris]\n  - name: lookup\n    kind: dns\n    target: localhost\n    interval_seconds: 10\n    locations: [paris]\n  - name: outside\n    kind: tcp\n    target: {OUTSIDE_TARGET}\n    interval_seconds: 10\n    consecutive_failures: 1\n    locations: [paris]\n"
    ))
}


#[tokio::test(flavor = "multi_thread")]
async fn a_served_round_alerts_once_for_the_refused_target_then_exits_on_sigint() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let site = site(dir.path(), &served_checks(&listener)?, 0).await?;
    let mut running = spawn_service(&site.settings_file)?;
    let named = wait_for(&running.lines, "check skipped")?;
    assert!(named.contains("check_name=\"outside\""), "{named}");
    wait_for(&running.lines, SERVING_MARKER)?;
    let round = wait_for(&running.lines, ROUND_MARKER)?;
    assert!(round.contains("probed=2"), "{round}");
    signal(&running.child, "-INT")?;
    let rest = finish(&mut running)?;
    assert!(!rest.contains("10.255.255.1") && !round.contains("10.255.255.1"));
    assert!(!rest.contains("check skipped"), "{rest}");
    assert_eq!(site.inserts.load(Ordering::SeqCst), 0);
    drop(site.fake);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn sigterm_stops_the_service_with_exit_zero() -> TestResult {
    let dir = tempdir()?;
    let site = site(dir.path(), &failing_tcp_checks(), 0).await?;
    let mut running = spawn_service(&site.settings_file)?;
    wait_for(&running.lines, SERVING_MARKER)?;
    signal(&running.child, "-TERM")?;
    finish(&mut running)?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn sighup_reloads_the_checks_and_a_start_only_change_is_refused_whole() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let site = site(dir.path(), &served_checks(&listener)?, 0).await?;
    let mut running = spawn_service(&site.settings_file)?;
    wait_for(&running.lines, ROUND_MARKER)?;
    let added = format!(
        "{}  - name: extra\n    kind: tcp\n    target: {SECRET_HOST}:80\n    locations: [paris]\n",
        served_checks(&listener)?
    );
    fs::write(dir.path().join("checks.yaml"), added)?;
    signal(&running.child, "-HUP")?;
    wait_for(&running.lines, "checks reloaded")?;
    fs::write(dir.path().join("checks.yaml"), failing_tcp_checks())?;
    fs::write(&site.settings_file, service_text(dir.path(), "acme", "lyon"))?;
    signal(&running.child, "-HUP")?;
    let verdict = wait_for_either(&running.lines, "reload refused", "checks reloaded")?;
    assert!(verdict.contains("reload refused"), "{verdict}");
    signal(&running.child, "-INT")?;
    let rest = finish(&mut running)?;
    assert!(!rest.contains("checks reloaded"), "{rest}");
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    assert!(audit.contains("refused") && audit.contains("start-only"), "{audit}");
    assert!(!audit.contains(SECRET_HOST) && !audit.contains("127.0.0.1"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let failing: Handler = Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    });
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, failing).await?;
    let settings_file = write_site(dir.path(), fake.port, &pki.ca_pem, &failing_tcp_checks())?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&settings_file]))?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!output.stderr.is_empty());
    Ok(())
}


const MAX_STATEMENTS: usize = 1000;


const SKIPPED_LITERALS: usize = 5;


const PORT_EIGHTY: u16 = 80;


const PORT_EIGHTY_ONE: u16 = 81;


#[tokio::test(flavor = "multi_thread")]
async fn a_name_resolving_outside_the_scope_alerts_with_the_refusal_reason() -> TestResult {
    let dir = tempdir()?;
    let checks = "scope: [10.0.0.0/8]\nchecks:\n  - name: lo\n    kind: tcp\n    target: localhost:9\n    interval_seconds: 10\n    consecutive_failures: 1\n    locations: [paris]\n";
    let mut site = site(dir.path(), checks, 0).await?;
    let mut running = spawn_service(&site.settings_file)?;
    let round = wait_for(&running.lines, ROUND_MARKER)?;
    assert!(round.contains("probed=1"), "{round}");
    signal(&running.child, "-INT")?;
    let rest = finish(&mut running)?;
    assert!(!rest.contains("check skipped"), "{rest}");
    let statements: Vec<String> = (0..MAX_STATEMENTS).map_while(|_i| site.fake.statements.try_recv().ok()).collect();
    assert_eq!(site.inserts.load(Ordering::SeqCst), 1);
    assert!(
        statements.iter().any(|statement| statement.contains("refused_by_scope")),
        "{statements:?}"
    );
    Ok(())
}


#[test]
fn only_a_literal_target_outside_the_scope_is_skipped_at_load() -> TestResult {
    let dir = tempdir()?;
    let yaml = "scope: [127.0.0.0/8]\nchecks:\n".to_owned()
        + &[
            ("http-out", "http", "http://10.255.255.1/"),
            ("http-in", "http", "http://127.0.0.1/"),
            ("http-name", "http", "http://peer.test/"),
            ("tcp-out", "tcp", "[fd00::1]:9"),
            ("tcp-in", "tcp", "127.0.0.1:9"),
            ("tls-out", "tls", "10.255.255.1"),
            ("icmp-out", "icmp", "10.255.255.1"),
            ("icmp6-out", "icmp", "fd00::2"),
            ("icmp-in", "icmp", "127.0.0.1"),
            ("icmp-name", "icmp", "peer.test"),
            ("dns-name", "dns", "10.255.255.1"),
        ]
        .iter()
        .map(|(name, kind, target)| {
            format!("  - name: {name}\n    kind: {kind}\n    target: \"{target}\"\n    interval_seconds: 10\n    locations: [paris]\n")
        })
        .collect::<String>();
    let live = live_of(dir.path(), &yaml)?;
    let total = live.checks.checks.len();
    let (kept, skipped) = skip_refused_literals(live.checks.clone());
    let names: Vec<&str> = kept.checks.iter().map(|check| check.name.as_str()).collect();
    assert_eq!(skipped, SKIPPED_LITERALS, "{names:?}");
    assert_eq!(kept.checks.len() + skipped, total);
    assert_eq!(names, ["http-in", "http-name", "tcp-in", "icmp-in", "icmp-name", "dns-name"]);
    let unparsable = Check {
        target: "bad host:80".to_owned(),
        ..live.checks.checks.first().ok_or("no check")?.clone()
    };
    assert_eq!(literal_target(&unparsable), None);
    let mut state_source = live.clone();
    state_source.skipped = skipped;
    assert_eq!(live_state(&state_source).get("checks_skipped").map(String::as_str), Some("5"));
    Ok(())
}


#[test]
fn the_tcp_port_comes_from_the_url_that_gave_the_host() -> TestResult {
    let port_of = |target: &str| -> Result<Option<u16>, Box<dyn std::error::Error>> {
        let url = url::Url::parse(&format!("https://{target}"))?;
        Ok(explicit_port(&url, target))
    };
    assert_eq!(port_of("peer.test:81")?, Some(PORT_EIGHTY_ONE));
    assert_eq!(port_of("peer.test:443")?, Some(TLS_DEFAULT_PORT));
    assert_eq!(port_of("peer.test:80")?, Some(PORT_EIGHTY));
    assert_eq!(port_of("peer.test")?, None);
    assert_eq!(port_of("peer.test:80#@10.0.0.1:81")?, Some(PORT_EIGHTY));
    Ok(())
}


#[test]
fn a_timed_out_transport_or_lookup_is_labelled_timeout() -> TestResult {
    let timed_out = || io::Error::from(io::ErrorKind::TimedOut);
    assert_eq!(failure_label(&ProbeError::Transport(timed_out())), "timeout");
    assert_eq!(failure_label(&ProbeError::Resolve(timed_out())), "timeout");
    assert_eq!(failure_label(&ProbeError::Transport(io::Error::from(io::ErrorKind::Other))), "failed");
    Ok(())
}


#[test]
fn idle_rounds_are_counted_and_summarised_not_logged_each() -> TestResult {
    let quiet = RoundReport {
        due: 0,
        probed: 0,
        deferred: 0,
        largest_overdue: Duration::ZERO,
        never_run: 0,
        stored: 0,
        store_failed: false,
        pending: 0,
        pending_dropped: 0,
    };
    let busy = RoundReport { probed: 1, ..quiet };
    assert_eq!(log_round(&quiet, 0, 0), 1);
    assert_eq!(log_round(&quiet, 0, IDLE_SUMMARY_ROUNDS - 1), IDLE_SUMMARY_ROUNDS);
    assert_eq!(log_round(&busy, 0, IDLE_SUMMARY_ROUNDS), 0);
    Ok(())
}


const GUARD_FOR_TESTS: Duration = Duration::from_millis(200);


const EXTRA_LINES: usize = 5;


const LINE_GAP: Duration = Duration::from_millis(5);


const SPELLINGS_IN_SCOPE: [(&str, &str); 4] = [("icmp", "127.1"), ("icmp", "0x7f.1"), ("icmp", "2130706433"), ("icmp", "127.0.0.1.")];


#[test]
fn a_wait_without_the_marker_fails_at_one_deadline_with_the_last_lines() -> TestResult {
    let (sender, lines) = channel();
    sender.send("first".to_owned())?;
    let failure = wait_for_either_within(&lines, "absent", "missing", GUARD_FOR_TESTS)
        .err()
        .ok_or("expected a timeout")?;
    assert!(
        failure.to_string().contains("within") && failure.to_string().contains("first"),
        "{failure}"
    );
    let (chatty_sender, chatty) = channel();
    let talker = thread::spawn(move || {
        (0..MAX_LINES_READ).try_for_each(|index| {
            thread::sleep(LINE_GAP);
            chatty_sender.send(format!("line {index}"))
        })
    });
    let chatty_failure = wait_for_either_within(&chatty, "absent", "absent", GUARD_FOR_TESTS)
        .err()
        .ok_or("expected a timeout")?;
    assert!(chatty_failure.to_string().contains("line"), "{chatty_failure}");
    drop(chatty);
    assert!(talker.join().is_ok());
    Ok(())
}


#[test]
fn a_wait_ends_when_the_child_closes_its_output() -> TestResult {
    let (sender, lines) = channel();
    sender.send("only".to_owned())?;
    drop(sender);
    let failure = wait_for(&lines, "absent").err().ok_or("expected an end")?;
    assert!(failure.to_string().contains("ended") && failure.to_string().contains("only"), "{failure}");
    Ok(())
}


#[test]
fn a_drain_that_never_ends_fails_at_the_guard_and_a_closed_one_returns_its_lines() -> TestResult {
    let (sender, lines) = channel();
    sender.send("one".to_owned())?;
    let failure = drain_lines(&lines, GUARD_FOR_TESTS).err().ok_or("expected a timeout")?;
    assert!(
        failure.to_string().contains("did not end") && failure.to_string().contains("one"),
        "{failure}"
    );
    drop(sender);
    assert_eq!(drain_lines(&lines, GUARD_FOR_TESTS)?, Vec::<String>::new());
    Ok(())
}


#[test]
fn the_last_lines_are_a_fixed_number() -> TestResult {
    let many: Vec<String> = (0..LAST_LINES_SHOWN + EXTRA_LINES).map(|index| format!("n{index}")).collect();
    let shown = last_lines(&many);
    assert_eq!(shown.lines().count(), LAST_LINES_SHOWN);
    assert!(
        shown.starts_with(&format!("n{EXTRA_LINES}")) && shown.ends_with(&format!("n{}", LAST_LINES_SHOWN + EXTRA_LINES - 1)),
        "{shown}"
    );
    Ok(())
}


#[test]
fn a_dropped_service_is_killed_and_reaped() -> TestResult {
    let mut child = Command::new("sleep").arg("600").stdin(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    let id = child.id();
    let stderr = child.stderr.take().ok_or("no stderr")?;
    drop(stderr);
    let (_sender, lines) = channel();
    drop(Running { child, lines });
    assert!(!Path::new(&format!("/proc/{id}")).exists());
    Ok(())
}


#[test]
fn every_literal_spelling_of_an_address_is_classified_without_a_lookup() -> TestResult {
    let dir = tempdir()?;
    let fake = net(vec![IpAddr::V4(Ipv4Addr::new(PRIVATE_OCTET, 1, SECOND, THIRD))]);
    let inside: Vec<(&str, String)> = SPELLINGS_IN_SCOPE
        .iter()
        .map(|(kind, target)| (*kind, (*target).to_owned()))
        .chain([
            ("tcp", "127.1:80".to_owned()),
            ("tcp", "0x7f.1:80".to_owned()),
            ("tls", "2130706433".to_owned()),
            ("tls", "127.1".to_owned()),
        ])
        .collect();
    inside.iter().try_for_each(|(kind, target)| -> TestResult {
        assert_eq!(probe_one(dir.path(), kind, target, &fake)?, Ok(true), "{kind} {target}");
        Ok(())
    })?;
    let outside: Vec<(&str, String)> = [
        ("icmp", "10.258"),
        ("icmp", "10.1.2.3."),
        ("icmp", "2852039166"),
        ("icmp", "0xa9fea9fe"),
        ("tcp", "10.258:80"),
        ("tcp", "2852039166:80"),
        ("tls", "10.258"),
        ("tls", "2852039166"),
    ]
    .iter()
    .map(|(kind, target)| (*kind, (*target).to_owned()))
    .collect();
    outside.iter().try_for_each(|(kind, target)| -> TestResult {
        assert_eq!(probe_one(dir.path(), kind, target, &fake)?, Err("refused".to_owned()), "{kind} {target}");
        Ok(())
    })?;
    assert_eq!(fake.resolves.load(Ordering::SeqCst), 0);
    assert_eq!(probe_one(dir.path(), "icmp", "1.2.3.example", &fake)?, Err("refused".to_owned()));
    assert_eq!(fake.resolves.load(Ordering::SeqCst), 1);
    Ok(())
}


#[test]
fn an_icmp_spelling_is_read_as_the_literal_it_is_at_load_and_at_probe() -> TestResult {
    let dir = tempdir()?;
    let live = live_of(dir.path(), &one_check("icmp", "127.0.0.1"))?;
    let base = live.checks.checks.first().ok_or("no check")?.clone();
    let literal = |target: &str| {
        literal_target(&Check {
            target: target.to_owned(),
            ..base.clone()
        })
    };
    assert_eq!(literal("10.258"), Some(IpAddr::V4(Ipv4Addr::new(PRIVATE_OCTET, 0, 1, SECOND))));
    assert_eq!(literal("2852039166"), Some(IpAddr::V4(METADATA_V4)));
    assert_eq!(literal("::1"), Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    assert_eq!(literal("1.2.3.example"), None);
    assert_eq!(literal("1.2.3.256"), None);
    let skipped = skip_refused_literals(CheckFile {
        checks: vec![
            Check {
                name: "meta".to_owned(),
                target: "2852039166".to_owned(),
                ..base.clone()
            },
            Check {
                name: "near".to_owned(),
                target: "127.1".to_owned(),
                ..base.clone()
            },
        ],
        ..live.checks.clone()
    });
    assert_eq!(skipped.1, 1);
    let fake = net(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let clock = AtomicU64::new(0);
    let unusable = Check {
        target: "1.2.3.256".to_owned(),
        ..base
    };
    let outcome = with_tools(&fake, &clock, |tools| run_probe(&unusable, &live, tools));
    assert_eq!(outcome.err().map(|failure| failure_label(&failure).to_owned()), Some("failed".to_owned()));
    assert_eq!(fake.resolves.load(Ordering::SeqCst), 0);
    Ok(())
}

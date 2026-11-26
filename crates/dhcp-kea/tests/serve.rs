#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::store::INSERT_SQL;
use alerts::types::RowFuture;
use core_audit::log::open_file_log;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use dhcp_kea::alerting::{ALERTED_SQL, UNKNOWN_RULE_ID};
use dhcp_kea::cursor::{READ_SQL as CURSOR_READ_SQL, WRITE_SQL as CURSOR_WRITE_SQL};
use dhcp_kea::error::{KeaError, RoundError};
use dhcp_kea::follow::Limits;
use dhcp_kea::history::STORE_SQL;
use dhcp_kea::serve::{
    collect, known_state, load_known, load_settings, log_round, open_known, open_service_settings_from, parse_known, pause, pause_or_stop,
    reload_audit, run, run_round, start, start_only_changed, start_with, termination, validate_settings, Follower, KnownDevices, RoundReport,
    ServiceSettings, MAX_KNOWN_BYTES, MAX_KNOWN_MACS,
};
use dhcp_kea::types::InterruptWait;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::collections::BTreeSet;
use std::fs;
use std::future::{pending, ready, Future};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use types::TestResult;


#[derive(Debug, Clone)]
struct Statement {
    sql: String,
    params: Vec<String>,
}


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-dhcp");


const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const KNOWN_ROW: &str = "10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,";


const UNKNOWN_ROW: &str = "10.0.0.2,aa:bb:cc:dd:ee:02,01,3600,1700003600,1,0,0,host2.example.,0,";


const THIRD_ROW: &str = "10.0.0.3,aa:bb:cc:dd:ee:03,01,3600,1700003600,1,0,0,host3.example.,0,";


const HOSTILE_ROW: &str = "10.0.0.4,aa:bb:cc:dd:ee:04,01,3600,1700003600,1,0,0,host\u{1b}[31m,0,";


const KNOWN_MAC: &str = "AA-BB-CC-DD-EE-01";


const UNKNOWN_MAC: &str = "AA-BB-CC-DD-EE-02";


const NOW: i64 = 1_700_000_000;


const OWNER_ONLY: u32 = 0o600;


const PG_PASSWORD: &str = "p";


const CLOSED_PORT: u16 = 1;


const HANG_GUARD: Duration = Duration::from_secs(60);


const SERVING_MARKER: &str = "serving";


const MAX_STATEMENTS: usize = 1_000;


const MAX_POLLS: usize = 400;


const POLL_STEP: Duration = Duration::from_millis(50);


const HUGE_LINE: usize = 65_536 * 2;


const BYTE_RANGE: usize = 256;


const BYTE_SQUARE: usize = 65_536;


const MIN_INTERVAL: u64 = 10;


const LIVE_INTERVAL: u64 = 20;


const CHANGED_INTERVAL: u64 = 30;


const MAX_INTERVAL: u64 = 3_600;


const DEADLINE: u64 = 30;


const MAX_DEADLINE: u64 = 600;


const TWO: usize = 2;


const THREE: usize = 3;


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn lines(rows: &[&str]) -> String {
    rows.iter().map(|row| format!("{row}\n")).collect()
}


fn settings_text(dir: &Path, interval: u64) -> String {
    format!(
        "tenant: acme\npg_settings: {}\nlease_file: {}\nknown_file: {}\naudit_file: {}\ninterval_seconds: {interval}\nstatement_deadline_seconds: 30\n",
        dir.join("pg.yaml").display(),
        dir.join("leases.csv").display(),
        dir.join("known.txt").display(),
        dir.join("audit.log").display(),
    )
}


fn write_site(dir: &Path, port: u16, ca_pem: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    fs::write(dir.join("leases.csv"), lines(&[HEADER, KNOWN_ROW, UNKNOWN_ROW]))?;
    fs::write(dir.join("known.txt"), "aa:bb:cc:dd:ee:01\n\n")?;
    let settings_file = dir.join("dhcp.yaml");
    fs::write(&settings_file, settings_text(dir, MIN_INTERVAL))?;
    Ok(settings_file)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn answering() -> Handler {
    Arc::new(|sql| {
        if sql.contains("dhcp_history_store") {
            Reply::Rows(vec![["0", "2", "0", "0", "0", "0", "0"].iter().map(|cell| (*cell).to_owned()).collect()])
        } else if sql.contains("dhcp_lookup_cursor") {
            Reply::Rows(vec![vec!["0".to_owned()]])
        } else if sql.contains("rule_id = 'dhcp.unknown_device'") {
            Reply::Rows(Vec::new())
        } else if sql.contains("INSERT INTO alerts") {
            Reply::Rows(vec![vec!["1".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


struct Service {
    child: Child,
    lines: Receiver<String>,
}


impl Drop for Service {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::warn!(%error, "cannot kill the service child");
        }
        if let Err(error) = self.child.wait() {
            tracing::warn!(%error, "cannot reap the service child");
        }
    }
}


fn signal_child(service: &Service, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(service.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn spawn_service(settings_file: &Path) -> Result<Service, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    std::thread::spawn(move || {
        let sent = BufReader::new(stderr)
            .lines()
            .filter_map(|line| line.map_err(|error| tracing::warn!(%error, "cannot read the service stderr")).ok())
            .try_for_each(|line| sender.send(line));
        if sent.is_err() {
            tracing::warn!("the test stopped reading the service stderr");
        }
    });
    Ok(Service { child, lines })
}


fn lines_until(service: &Service, deadline: Instant) -> impl Iterator<Item = String> + '_ {
    std::iter::from_fn(move || {
        let left = deadline.saturating_duration_since(Instant::now());
        (!left.is_zero()).then(|| service.lines.recv_timeout(left).ok()).flatten()
    })
}


fn wait_for_line(service: &Service, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let found = lines_until(service, Instant::now() + HANG_GUARD).find(|line| line.contains(marker));
    Ok(found.ok_or_else(|| format!("hang guard: no line with {marker:?} before the child ended or the guard expired"))?)
}


fn finish(service: Service) -> TestResult {
    let rest: Vec<String> = lines_until(&service, Instant::now() + HANG_GUARD).collect();
    let mut owned = service;
    let exit = (0..MAX_POLLS)
        .find_map(|_attempt| {
            let status = owned.child.try_wait().ok().flatten();
            if status.is_none() {
                std::thread::sleep(POLL_STEP);
            }
            status
        })
        .ok_or("hang guard: the child did not exit after its signal")?;
    assert!(exit.success(), "{rest:?}");
    Ok(())
}


async fn wait_for_statement(fake: &mut Fake, needle: &str) -> TestResult {
    let mut seen = false;
    let mut attempts = 0;
    while !seen && attempts < MAX_STATEMENTS {
        seen = fake.statements.recv().await.ok_or("the fake closed")?.contains(needle);
        attempts += 1;
    }
    assert!(seen, "no statement with {needle}");
    Ok(())
}


fn wait_for_audit(path: &Path, needle: &str) -> TestResult {
    let found = (0..MAX_POLLS).any(|_attempt| {
        let hit = fs::read_to_string(path).is_ok_and(|text| text.contains(needle));
        if !hit {
            std::thread::sleep(POLL_STEP);
        }
        hit
    });
    assert!(found, "no audit record with {needle}");
    Ok(())
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn no_wait(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(ready(()))
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-dhcp <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-dhcp")
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let broken = dir.path().join("dhcp.yaml");
    fs::write(&broken, "tenant: [\n")?;
    refused_with(&run_to_end(&[&broken])?, "dhcp.yaml")
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("dhcp.yaml");
    fs::write(
        &file,
        "tenant: acme\npg_settings: a\nlease_file: b\nknown_file: c\ninterval_seconds: 10\nstatement_deadline_seconds: 30\n",
    )?;
    refused_with(&run_to_end(&[&file])?, "audit_file")
}


#[test]
fn a_missing_known_file_or_pg_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    fs::remove_file(dir.path().join("known.txt"))?;
    refused_with(&run_to_end(&[&settings_file])?, "known.txt")?;
    fs::write(dir.path().join("known.txt"), "")?;
    fs::remove_file(dir.path().join("pg.yaml"))?;
    refused_with(&run_to_end(&[&settings_file])?, "pg.yaml")
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let output = run_to_end(&[&settings_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&settings_file]))?;
    assert!(!output.status.success());
    Ok(())
}


async fn serve_one_round_then(signal: &str) -> TestResult {
    let dir = tempdir()?;
    let (mut fake, ca_pem) = fake_with(answering()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let service = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for_line(&service, SERVING_MARKER))?;
    wait_for_statement(&mut fake, "dhcp_history_store").await?;
    wait_for_statement(&mut fake, "INSERT INTO alerts").await?;
    signal_child(&service, signal)?;
    tokio::task::block_in_place(|| finish(service))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_one_round_then("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_warns_when_the_lease_file_is_absent_and_logs_without_colour() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(answering()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::remove_file(dir.path().join("leases.csv"))?;
    let service = spawn_service(&settings_file)?;
    let warning = tokio::task::block_in_place(|| wait_for_line(&service, "the lease file is absent"))?;
    assert!(warning.contains("WARN") && !warning.contains('\u{1b}'), "{warning:?}");
    signal_child(&service, "-INT")?;
    tokio::task::block_in_place(|| finish(service))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_one_round_then("-TERM").await
}


#[tokio::test(flavor = "multi_thread")]
async fn a_known_file_edit_and_a_settings_edit_are_applied_and_audited_under_all() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(answering()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let service = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for_line(&service, SERVING_MARKER))?;
    let audit = dir.path().join("audit.log");
    fs::write(dir.path().join("known.txt"), "aa:bb:cc:dd:ee:01\naa:bb:cc:dd:ee:02\n")?;
    tokio::task::block_in_place(|| wait_for_audit(&audit, "known-devices"))?;
    fs::write(&settings_file, settings_text(dir.path(), LIVE_INTERVAL))?;
    signal_child(&service, "-HUP")?;
    tokio::task::block_in_place(|| wait_for_audit(&audit, "\"request_id\":\"settings\""))?;
    let text = fs::read_to_string(&audit)?;
    assert!(text.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{text}");
    assert!(!text.contains("\"tenant\":\"acme\""));
    signal_child(&service, "-TERM")?;
    tokio::task::block_in_place(|| finish(service))
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_after_its_rounds_and_when_the_interrupt_arrives_or_fails() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(answering()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start_with(&settings_file, THREE, never(), no_wait).await?;
    start(&settings_file, usize::MAX, Box::pin(ready(Ok(())))).await?;
    let failing: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = start(&settings_file, usize::MAX, failing).await.err().ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_bad_argument_list_and_a_second_global_subscriber() -> TestResult {
    let error = run(&[], never()).await.err().ok_or("expected an error")?;
    assert!(error.to_string().contains("usage"));
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(answering()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let arguments = [settings_file.display().to_string()];
    run(&arguments, Box::pin(ready(Ok(())))).await?;
    let second = run(&arguments, Box::pin(ready(Ok(())))).await.err().ok_or("expected an error")?;
    assert!(!second.to_string().is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn termination_resolves_on_the_terminate_signal() -> TestResult {
    let wait = termination()?;
    let pid = std::process::id().to_string();
    let status = Command::new("kill").arg("-TERM").arg(&pid).status()?;
    assert!(status.success());
    wait.await?;
    Ok(())
}


fn valid_settings(dir: &Path) -> ServiceSettings {
    ServiceSettings {
        tenant: "acme".to_owned(),
        pg_settings: dir.join("pg.yaml"),
        lease_file: dir.join("leases.csv"),
        known_file: dir.join("known.txt"),
        audit_file: dir.join("audit.log"),
        interval_seconds: MIN_INTERVAL,
        statement_deadline_seconds: DEADLINE,
    }
}


#[test]
fn settings_are_bounded() -> TestResult {
    let dir = tempdir()?;
    let good = valid_settings(dir.path());
    validate_settings(&good)?;
    let cases = [
        ServiceSettings {
            tenant: "-x".to_owned(),
            ..good.clone()
        },
        ServiceSettings {
            interval_seconds: MIN_INTERVAL - 1,
            ..good.clone()
        },
        ServiceSettings {
            interval_seconds: MAX_INTERVAL + 1,
            ..good.clone()
        },
        ServiceSettings {
            statement_deadline_seconds: 0,
            ..good.clone()
        },
        ServiceSettings {
            statement_deadline_seconds: MAX_DEADLINE + 1,
            ..good.clone()
        },
    ];
    cases.iter().try_for_each(|case| {
        assert!(validate_settings(case).is_err(), "{case:?}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(!start_only_changed(
        &good,
        &ServiceSettings {
            interval_seconds: MAX_INTERVAL,
            ..good.clone()
        }
    ));
    assert!(start_only_changed(
        &good,
        &ServiceSettings {
            lease_file: dir.path().join("other"),
            ..good.clone()
        }
    ));
    Ok(())
}


#[test]
fn the_settings_engine_applies_live_values_and_refuses_start_only_changes() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("dhcp.yaml");
    fs::write(&file, settings_text(dir.path(), MIN_INTERVAL))?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_service_settings_from(&file, load_settings(&file)?, reload_audit(&log))?;
    fs::write(&file, settings_text(dir.path(), CHANGED_INTERVAL))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    fs::write(&file, settings_text(dir.path(), CHANGED_INTERVAL).replace("acme", "other"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    let text = fs::read_to_string(dir.path().join("audit.log"))?;
    assert_eq!(text.lines().count(), TWO);
    assert!(
        text.contains("denied") && text.lines().all(|line| line.contains("\"tenant\":\"all\"")),
        "{text}"
    );
    Ok(())
}


#[test]
fn the_known_file_is_an_ascii_allowlist_with_bounded_size_and_count() -> TestResult {
    let parsed = parse_known(b"aa:bb:cc:dd:ee:01\n\nAA-BB-CC-DD-EE-01\n".to_vec(), "known.txt")?;
    assert_eq!(parsed.macs.len(), 1);
    assert!(parsed.macs.contains(KNOWN_MAC));
    let refused = [
        b"aa:bb:cc:dd:ee:01\r\n".to_vec(),
        b"aa:bb:cc:dd:ee:01\t\n".to_vec(),
        "caf\u{e9}\n".as_bytes().to_vec(),
        b"\x1b[31m\n".to_vec(),
        b"not a mac\n".to_vec(),
        b"# comment\n".to_vec(),
    ];
    refused.into_iter().try_for_each(|bytes| {
        assert!(parse_known(bytes, "known.txt").is_err());
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[test]
fn more_known_devices_than_the_cap_refuse_the_file() -> TestResult {
    let many: String = (0..=MAX_KNOWN_MACS)
        .map(|index| {
            format!(
                "02:00:00:{:02x}:{:02x}:{:02x}\n",
                index / BYTE_SQUARE,
                index / BYTE_RANGE % BYTE_RANGE,
                index % BYTE_RANGE
            )
        })
        .collect();
    let error = parse_known(many.into_bytes(), "known.txt").err().ok_or("expected a refusal")?;
    assert!(error.to_string().contains("more than"));
    Ok(())
}


#[test]
fn a_known_file_over_the_byte_cap_or_not_regular_is_refused_before_parsing() -> TestResult {
    let dir = tempdir()?;
    let big = dir.path().join("big.txt");
    fs::write(&big, vec![b'\n'; usize::try_from(MAX_KNOWN_BYTES)? + 1])?;
    assert!(load_known(&big).is_err());
    let fifo = dir.path().join("fifo.txt");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(load_known(&fifo).is_err());
    assert!(load_known(&dir.path().join("absent.txt")).is_err());
    Ok(())
}


#[test]
fn the_known_engine_reloads_audits_and_keeps_the_old_list_on_a_bad_file() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("known.txt");
    fs::write(&file, "aa:bb:cc:dd:ee:01\n")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_known(&file, reload_audit(&log))?;
    assert_eq!(known_state(&load_known(&file)?).len(), 1);
    fs::write(&file, "aa:bb:cc:dd:ee:01\naa:bb:cc:dd:ee:02\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    fs::write(&file, "garbage\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(core_config::reload::current_config(&engine).macs.len(), TWO);
    let text = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(text.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{text}");
    assert!(open_known(&dir.path().join("a:b.txt"), reload_audit(&log)).is_err());
    Ok(())
}


struct Recorder {
    statements: Mutex<Vec<Statement>>,
    failing: bool,
}


fn recorder(failing: bool) -> Recorder {
    Recorder {
        statements: Mutex::new(Vec::new()),
        failing,
    }
}


fn rows_for(sql: &str) -> Vec<Vec<String>> {
    if sql == STORE_SQL {
        vec![["0", "2", "0", "0", "0", "0", "0"].iter().map(|cell| (*cell).to_owned()).collect()]
    } else if sql == CURSOR_READ_SQL || sql == CURSOR_WRITE_SQL || sql == INSERT_SQL {
        vec![vec!["1".to_owned()]]
    } else {
        Vec::new()
    }
}


fn executor(store: &Recorder) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'_> + '_ {
    move |_scope, sql, params| -> RowFuture<'_> {
        if let Ok(mut held) = store.statements.lock() {
            held.push(Statement { sql: sql.to_owned(), params });
        }
        if store.failing {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            Box::pin(ready(Ok(rows_for(sql))))
        }
    }
}


fn seen_sql(store: &Recorder) -> Result<Vec<Statement>, Box<dyn std::error::Error>> {
    Ok(store.statements.lock().map_err(|_poisoned| "poisoned")?.clone())
}


fn known_of(macs: &[&str]) -> KnownDevices {
    KnownDevices {
        macs: macs.iter().map(|mac| (*mac).to_owned()).collect(),
    }
}


#[tokio::test]
async fn rounds_over_a_growing_file_and_an_lfc_rewrite_store_each_lease_once() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    fs::write(&path, lines(&[HEADER, KNOWN_ROW, UNKNOWN_ROW]))?;
    let scope = tenant_scope("acme")?;
    let known = known_of(&[KNOWN_MAC]);
    let limits = Limits::default();
    let mut follower = Follower::default();
    let store = recorder(false);
    let exec = executor(&store);
    let first = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!((first.leases, first.alerts, first.inserted), (TWO, 1, 1));
    let before = seen_sql(&store)?.len();
    let idle = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!(idle, RoundReport::default());
    assert_eq!(seen_sql(&store)?.len(), before);
    fs::write(&path, lines(&[HEADER, KNOWN_ROW, UNKNOWN_ROW, THIRD_ROW]))?;
    let grown = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!(grown.leases, 1);
    fs::rename(&path, dir.path().join("leases.csv.1"))?;
    fs::write(&path, lines(&[HEADER, KNOWN_ROW, THIRD_ROW]))?;
    let rewritten = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!(rewritten.leases, 0);
    assert!(follower.counts.duplicate >= 1);
    let statements = seen_sql(&store)?;
    let inserts: Vec<_> = statements.iter().filter(|found| found.sql == INSERT_SQL).collect();
    assert!(inserts.iter().all(|found| found.params.iter().all(|text| !text.contains(KNOWN_MAC))));
    assert!(inserts.iter().any(|found| found.params.iter().any(|text| text.contains(UNKNOWN_MAC))));
    Ok(())
}


#[tokio::test]
async fn a_failed_store_keeps_the_leases_pending_and_the_next_round_retries_them() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    fs::write(&path, lines(&[HEADER, KNOWN_ROW, UNKNOWN_ROW]))?;
    let scope = tenant_scope("acme")?;
    let known = known_of(&[]);
    let limits = Limits::default();
    let mut follower = Follower::default();
    let failing = recorder(true);
    let failed = run_round(&executor(&failing), &scope, &known, &mut follower, (&path, &limits, NOW)).await;
    assert!(matches!(failed, Err(RoundError::History(_))));
    log_round(&failed);
    assert_eq!(follower.pending.len(), TWO);
    let working = recorder(false);
    let retried = run_round(&executor(&working), &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    log_round(&Ok(retried));
    assert_eq!((retried.leases, retried.alerts), (TWO, TWO));
    assert!(follower.pending.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_alert_insert_is_an_alerts_error_and_keeps_the_leases_pending() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    fs::write(&path, lines(&[HEADER, UNKNOWN_ROW]))?;
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let mut follower = Follower::default();
    let store = recorder(false);
    let inner = executor(&store);
    let exec = move |scope_arg: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        if sql == INSERT_SQL {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            inner(scope_arg, sql, params)
        }
    };
    let failed = run_round(&exec, &scope, &known_of(&[]), &mut follower, (&path, &limits, NOW)).await;
    assert!(matches!(failed, Err(RoundError::Alerts(StoreError::Pg(_)))), "{failed:?}");
    assert_eq!(follower.pending.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_bad_header_is_a_round_error_and_a_non_regular_lease_path_is_refused_and_counted() -> TestResult {
    let dir = tempdir()?;
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let store = recorder(false);
    let exec = executor(&store);
    let bad = dir.path().join("bad.csv");
    fs::write(&bad, "nothing,useful\n1,2\n")?;
    let mut follower = Follower::default();
    let failed = run_round(&exec, &scope, &known_of(&[]), &mut follower, (&bad, &limits, NOW)).await;
    assert!(matches!(failed, Err(RoundError::Follow(KeaError::Header(_)))));
    let fifo = dir.path().join("fifo.csv");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let link = dir.path().join("link.csv");
    fs::write(dir.path().join("real.csv"), lines(&[HEADER, UNKNOWN_ROW]))?;
    symlink(dir.path().join("real.csv"), &link)?;
    let missing = dir.path().join("missing.csv");
    [fifo, link, missing].iter().try_for_each(|path| {
        let mut other = Follower::default();
        collect(path, &mut other, &limits)?;
        assert!(other.pending.is_empty());
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let mut counted = Follower::default();
    collect(&dir.path().join("fifo.csv"), &mut counted, &limits)?;
    assert_eq!(counted.counts.refused, 1);
    assert!(seen_sql(&store)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_hostile_hostname_and_an_oversized_line_never_reach_the_store_as_text() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    let huge = format!("10.0.0.5,aa:bb:cc:dd:ee:05,01,3600,1700003600,1,0,0,{},0,", "a".repeat(HUGE_LINE));
    fs::write(&path, lines(&[HEADER, HOSTILE_ROW, &huge, UNKNOWN_ROW]))?;
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let mut follower = Follower::default();
    let store = recorder(false);
    let exec = executor(&store);
    let report = run_round(&exec, &scope, &known_of(&[]), &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!(report.leases, TWO);
    assert_eq!(follower.counts.malformed.get("line-too-long"), Some(&1));
    let statements = seen_sql(&store)?;
    assert!(statements
        .iter()
        .all(|found| found.params.iter().all(|text| !text.contains('\u{1b}') && text.len() < HUGE_LINE)));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_production_pause_waits_the_given_duration_on_the_paused_clock() -> TestResult {
    let before = tokio::time::Instant::now();
    pause(Duration::from_secs(MIN_INTERVAL)).await;
    assert_eq!(before.elapsed(), Duration::from_secs(MIN_INTERVAL));
    Ok(())
}


fn failing_lookup_executor<'store>(
    store: &'store Recorder,
    failing: &'store AtomicBool,
) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'store> + 'store {
    let inner = executor(store);
    move |scope, sql, params| -> RowFuture<'store> {
        if sql == ALERTED_SQL && failing.load(Ordering::SeqCst) {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            inner(scope, sql, params)
        }
    }
}


#[tokio::test]
async fn a_failed_already_alerted_lookup_keeps_the_batch_pending_and_the_next_round_alerts() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    fs::write(&path, lines(&[HEADER, KNOWN_ROW, UNKNOWN_ROW]))?;
    let scope = tenant_scope("acme")?;
    let known = known_of(&[]);
    let limits = Limits::default();
    let mut follower = Follower::default();
    let store = recorder(false);
    let failing = AtomicBool::new(true);
    let exec = failing_lookup_executor(&store, &failing);
    let failed = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await;
    assert!(matches!(failed, Err(RoundError::LookupFailed)), "{failed:?}");
    assert!(failed
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("already-alerted lookup failed")));
    assert_eq!(follower.pending.len(), TWO);
    assert!(seen_sql(&store)?.iter().all(|found| found.sql != INSERT_SQL));
    failing.store(false, Ordering::SeqCst);
    let retried = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!((retried.leases, retried.alerts, retried.inserted), (TWO, TWO, 1));
    assert!(follower.pending.is_empty());
    assert!(seen_sql(&store)?.iter().any(|found| found.sql == INSERT_SQL));
    Ok(())
}


fn gated(entered: Sender<()>, release: Receiver<()>) -> Handler {
    let held = Mutex::new(release);
    let first = AtomicBool::new(true);
    let inner = answering();
    Arc::new(move |sql| {
        if sql.contains("FROM dhcp_history_store(") && first.swap(false, Ordering::SeqCst) {
            if entered.send(()).is_err() {
                tracing::warn!("nobody waits for the round to start");
            }
            if let Ok(receiver) = held.lock() {
                if let Err(error) = receiver.recv_timeout(HANG_GUARD) {
                    tracing::warn!(%error, "the round was not released");
                }
            }
        }
        inner(sql)
    })
}


fn forever(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(pending())
}


fn interrupt_when_entered(entered: Receiver<()>, seen: Arc<AtomicBool>) -> InterruptWait {
    Box::pin(async move {
        let started = tokio::task::spawn_blocking(move || entered.recv_timeout(HANG_GUARD)).await?;
        started.map_err(io::Error::other)?;
        seen.store(true, Ordering::SeqCst);
        Ok(())
    })
}


fn statements_so_far(fake: &mut Fake) -> Vec<String> {
    std::iter::from_fn(|| fake.statements.try_recv().ok()).collect()
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_during_a_round_lets_it_finish_before_serve_returns() -> TestResult {
    let dir = tempdir()?;
    let (entered_sender, entered_receiver) = channel();
    let (release_sender, release_receiver) = channel();
    let (mut fake, ca_pem) = fake_with(gated(entered_sender, release_receiver)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let seen = Arc::new(AtomicBool::new(false));
    let interrupt = interrupt_when_entered(entered_receiver, Arc::clone(&seen));
    let driver = async {
        let polled = futures_poll_until(&seen).await;
        release_sender.send(())?;
        Ok::<bool, Box<dyn std::error::Error>>(polled)
    };
    let (served, released) = tokio::join!(start_with(&settings_file, usize::MAX, interrupt, forever), driver);
    served?;
    assert!(released?, "the interrupt was never consumed");
    let statements = statements_so_far(&mut fake);
    assert!(
        statements.iter().any(|sql| sql.contains("INSERT INTO alerts")),
        "the round in flight was dropped: {statements:?}"
    );
    Ok(())
}


async fn futures_poll_until(flag: &AtomicBool) -> bool {
    let mut attempts = 0;
    while !flag.load(Ordering::SeqCst) && attempts < MAX_POLLS {
        tokio::time::sleep(POLL_STEP).await;
        attempts += 1;
    }
    flag.load(Ordering::SeqCst)
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_still_held_at_the_shutdown_grace_is_cut_and_serve_returns() -> TestResult {
    let dir = tempdir()?;
    let (entered_sender, entered_receiver) = channel();
    let (release_sender, release_receiver) = channel();
    let (mut fake, ca_pem) = fake_with(gated(entered_sender, release_receiver)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let interrupt = interrupt_when_entered(entered_receiver, Arc::new(AtomicBool::new(false)));
    start_with(&settings_file, usize::MAX, interrupt, no_wait).await?;
    drop(release_sender);
    let statements = statements_so_far(&mut fake);
    assert!(statements.iter().all(|sql| !sql.contains("INSERT INTO alerts")), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn between_two_rounds_the_interrupt_wins_over_the_interval_and_the_interval_over_no_interrupt() -> TestResult {
    let mut signalled: InterruptWait = Box::pin(ready(Ok(())));
    let stopped = pause_or_stop(&mut signalled, forever, Duration::from_secs(MIN_INTERVAL)).await;
    assert!(matches!(stopped, Some(Ok(()))));
    let mut silent = never();
    assert!(pause_or_stop(&mut silent, no_wait, Duration::from_secs(MIN_INTERVAL)).await.is_none());
    Ok(())
}


const ALERTED_FIRST: usize = 4_800;


const FRESH_IN_CHUNK: usize = 200;


const OCTET_RANGE: usize = 256;


fn mac_at(index: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", index / OCTET_RANGE, index % OCTET_RANGE)
}


fn ecs_mac_at(index: usize) -> String {
    mac_at(index).to_ascii_uppercase().replace(':', "-")
}


fn row_at(index: usize) -> String {
    format!("10.0.0.1,{},01,3600,1700003600,1,0,0,,0,", mac_at(index))
}


fn alerted_executor<'a>(store: &'a Recorder, alerted: &'a BTreeSet<String>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        if sql == ALERTED_SQL {
            let parsed: Result<Vec<String>, serde_json::Error> = serde_json::from_str(params.first().map_or("[]", String::as_str));
            match parsed {
                Ok(ids) => Box::pin(ready(Ok(ids.into_iter().filter(|id| alerted.contains(id)).map(|id| vec![id]).collect()))),
                Err(_refused) => Box::pin(ready(Err(PgError::InvalidTenant))),
            }
        } else if sql == CURSOR_READ_SQL {
            Box::pin(ready(Ok(vec![vec!["0".to_owned()]])))
        } else {
            executor(store)(scope, sql, params)
        }
    }
}


#[tokio::test]
async fn macs_of_an_unscanned_chunk_wait_and_are_alerted_on_the_next_round() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("leases.csv");
    let total = ALERTED_FIRST + FRESH_IN_CHUNK + 1;
    let mut text = lines(&[HEADER]);
    text.push_str(&(0..total).map(|index| format!("{}\n", row_at(index))).collect::<String>());
    fs::write(&path, text)?;
    let scope = tenant_scope("acme")?;
    let alerted: BTreeSet<String> = (0..ALERTED_FIRST)
        .map(|index| alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{}", ecs_mac_at(index))]))
        .collect();
    let store = recorder(false);
    let exec = alerted_executor(&store, &alerted);
    let known = known_of(&[]);
    let limits = Limits::default();
    let mut follower = Follower::default();
    let first = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!((first.leases, first.alerts), (total, FRESH_IN_CHUNK + 1));
    assert_eq!(follower.waiting.len(), 1);
    assert!(follower.pending.is_empty());
    let second = run_round(&exec, &scope, &known, &mut follower, (&path, &limits, NOW)).await?;
    assert_eq!((second.leases, second.alerts), (0, 1));
    assert!(follower.waiting.is_empty());
    let victim = ecs_mac_at(total - 1);
    let inserts: Vec<Statement> = seen_sql(&store)?.into_iter().filter(|found| found.sql == INSERT_SQL).collect();
    assert!(inserts
        .last()
        .is_some_and(|found| found.params.iter().any(|param| param.contains(&victim))));
    Ok(())
}

#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use cert_inventory::error::{InventoryStoreError, RoundError};
use cert_inventory::model::{CertRecord, FoundCert, KeyType, ScanOutcome, SkipCounts, StoreCounts};
use cert_inventory::serve::{
    block_on_with_grace, boxed_reload_audit, by_path, encoded, failure_class, gap_text, gaps_of, is_host, listen_for_signals, load_settings,
    one_round, open_cert_settings_from, pause, pg_digest, progress_of, report, serve_then_quiesce, start, start_only_changed, start_only_field,
    sum_counts, ReloadThread, RoundGaps, RoundReport, MAX_DEADLINE_SECONDS, MAX_HOST_BYTES, MAX_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS,
    UNKNOWN_CLASS,
};
use cert_inventory::types::{InterruptFn, InterruptWait, StopWatchFn, WaitFn};
use core_audit::log::open_file_log;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::{CertificateParams, KeyPair, SanType};
use std::collections::BTreeMap;
use std::fs;
use std::future::{pending, ready, Future};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::runtime::Handle;
use tokio::sync::{Notify, Semaphore};
use tracing::dispatcher::{with_default, Dispatch};
use tracing::instrument::WithSubscriber;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-certs");


const OWNER_ONLY: u32 = 0o600;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const STORE_MARKER: &str = "jsonb_to_recordset";


const TWO_ROUNDS: u64 = 2;


const LISTING_CUT_COUNT: usize = 3;


const PATHS_OMITTED_COUNT: usize = 4;


const ONE_ROUND: u64 = 1;


const LIVE_INTERVAL: &str = "7200";


const MAX_POLLS: usize = 2_000;


const POLL_PAUSE: Duration = Duration::from_millis(10);


const MAX_DRAIN: usize = 10_000;


const INSERTED: usize = 2;


const SEEN_AGAIN: usize = 3;


const REFUSED_FULL: usize = 5;


const REFUSED_SOURCE: usize = 7;


const REFUSED_RECORD: usize = 11;


const DUPLICATES: usize = 13;


const MAX_LINES: usize = 1_000;


const OVER_HOST: usize = 254;


const ALL_FILES: usize = 1_000;


const NOT_REGULAR_COUNT: usize = 3;


const TOO_LARGE_COUNT: usize = 4;


const SWAPPED_COUNT: usize = 5;


const VANISHED_COUNT: usize = 6;


const UNREADABLE_COUNT: usize = 7;


const KEYS_COUNT: usize = 8;


const UNREACHED_COUNT: usize = 9;


const OVER_COUNT: usize = 10;


const REFUSED_ROOTS_COUNT: usize = 12;


const MALFORMED_COUNT: usize = 11;


const OVERRUN: usize = 500;


const OVERRUN_TEXT: &str = "500";


const HANG_GUARD: Duration = Duration::from_secs(60);


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn certificate_pem() -> Result<String, Box<dyn std::error::Error>> {
    let key = KeyPair::generate()?;
    Ok(CertificateParams::new(vec!["scan.example.test".to_owned()])?.self_signed(&key)?.pem())
}


fn settings_text(dir: &Path, overrides: &[(&str, String)]) -> String {
    let mut fields: BTreeMap<&str, String> = BTreeMap::from([
        ("tenant", "acme".to_owned()),
        ("pg_settings", dir.join("pg.yaml").display().to_string()),
        ("audit_file", dir.join("audit.log").display().to_string()),
        ("roots", format!("[{}]", dir.join("certs").display())),
        ("host", "scanner-1.lab".to_owned()),
        ("interval_seconds", MIN_INTERVAL_SECONDS.to_string()),
        ("max_depth", "4".to_owned()),
        ("deadline_seconds", "5".to_owned()),
        ("max_certs", "1000".to_owned()),
    ]);
    overrides.iter().for_each(|(key, value)| {
        fields.insert(key, value.clone());
    });
    fields.iter().map(|(key, value)| format!("{key}: {value}\n")).collect()
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
    fs::create_dir_all(dir.join("certs"))?;
    fs::write(dir.join("certs/one.pem"), certificate_pem()?)?;
    fs::write(
        dir.join("certs/broken.pem"),
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )?;
    let settings_file = dir.join("certs.yaml");
    fs::write(&settings_file, settings_text(dir, &[]))?;
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


fn storing() -> Handler {
    Arc::new(|sql| {
        if sql.contains(STORE_MARKER) {
            Reply::Rows(vec![["1", "0", "0"].map(str::to_owned).to_vec()])
        } else {
            Reply::Done
        }
    })
}


fn wait_for(reader: &mut BufReader<ChildStderr>, marker: &str) -> TestResult {
    reader
        .by_ref()
        .lines()
        .take(MAX_LINES)
        .find_map(|line| line.map(|text| text.contains(marker).then_some(())).transpose())
        .ok_or("the child ended before the marker")??;
    Ok(())
}


fn wait_for_audit(path: &Path, marker: &str) -> TestResult {
    (0..MAX_POLLS)
        .find_map(|_attempt| {
            std::thread::sleep(POLL_PAUSE);
            fs::read_to_string(path).is_ok_and(|text| text.contains(marker)).then_some(())
        })
        .ok_or("the audit record never arrived")?;
    Ok(())
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn spawn_service(settings_file: &Path) -> Result<(Child, BufReader<ChildStderr>), Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    Ok((child, reader))
}


fn finish(mut child: Child, mut reader: BufReader<ChildStderr>) -> TestResult {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(())
}


fn never() -> io::Result<InterruptWait> {
    Ok(Box::pin(pending()))
}


fn at_once() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Ok(()))))
}


fn failing_wait() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Err(io::Error::other("no signal")))))
}


fn cannot_listen() -> io::Result<InterruptWait> {
    Err(io::Error::other("no handler"))
}


fn instant(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(ready(()))
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-certs <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-certs")
}


#[test]
fn an_unreadable_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")
}


#[test]
fn an_invalid_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("certs.yaml");
    fs::write(&settings_file, "tenant: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "certs.yaml")
}


#[test]
fn a_settings_file_with_no_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("certs.yaml");
    fs::write(
        &settings_file,
        settings_text(dir.path(), &[])
            .lines()
            .filter(|line| !line.starts_with("audit_file"))
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")
}


#[test]
fn a_missing_pg_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
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
    assert!(!output.stderr.is_empty());
    Ok(())
}


async fn serve_until_round(signal_name: &str) -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (child, mut reader) = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for(&mut reader, "scan round stored"))?;
    signal(&child, signal_name)?;
    tokio::task::block_in_place(|| finish(child, reader))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_stores_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_until_round("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_until_round("-TERM").await
}


#[tokio::test(flavor = "multi_thread")]
async fn a_sighup_after_an_interval_edit_is_audited_under_the_reserved_tenant() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (child, mut reader) = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for(&mut reader, "serving"))?;
    fs::write(
        &settings_file,
        settings_text(dir.path(), &[("interval_seconds", LIVE_INTERVAL.to_owned())]),
    )?;
    signal(&child, "-HUP")?;
    tokio::task::block_in_place(|| wait_for(&mut reader, "configuration reloaded"))?;
    wait_for_audit(&dir.path().join("audit.log"), "config.reload")?;
    signal(&child, "-INT")?;
    tokio::task::block_in_place(|| finish(child, reader))?;
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("config.reload"), "{audit}");
    assert!(
        audit.lines().all(|line| line.contains("\"tenant\":\"all\"") && !line.contains("acme\"")),
        "{audit}"
    );
    assert!(audit.contains(LIVE_INTERVAL), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_sighup_changing_a_start_only_setting_is_refused_and_audited() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (child, mut reader) = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for(&mut reader, "serving"))?;
    fs::write(&settings_file, settings_text(dir.path(), &[("tenant", "other".to_owned())]))?;
    signal(&child, "-HUP")?;
    tokio::task::block_in_place(|| wait_for(&mut reader, "reload refused"))?;
    wait_for_audit(&dir.path().join("audit.log"), "denied")?;
    signal(&child, "-INT")?;
    tokio::task::block_in_place(|| finish(child, reader))?;
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("denied"), "{audit}");
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    Ok(())
}


async fn statements_after(mut fake: Fake) -> usize {
    let mut stores = 0;
    let mut drained = 0;
    let mut empty = false;
    while !empty && drained < MAX_DRAIN {
        match fake.statements.try_recv() {
            Ok(sql) => stores += usize::from(sql.contains(STORE_MARKER)),
            Err(_closed_or_empty) => empty = true,
        }
        drained += 1;
    }
    stores
}


#[tokio::test(flavor = "multi_thread")]
async fn two_rounds_store_the_certificate_twice_and_start_returns() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, TWO_ROUNDS, never, instant).await?;
    assert_eq!(statements_after(fake).await, TWO_ROUNDS as usize);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_store_is_logged_and_the_next_round_still_runs() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains(STORE_MARKER) {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, TWO_ROUNDS, never, instant).await?;
    assert_eq!(statements_after(fake).await, TWO_ROUNDS as usize);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_production_wait_returns_after_its_duration() -> TestResult {
    pause(Duration::ZERO).await;
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, ONE_ROUND, never, pause_zero).await?;
    Ok(())
}


fn pause_zero(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    pause(Duration::ZERO)
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_when_the_interrupt_arrives() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, u64::MAX, at_once, instant).await?;
    drop(fake);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let error = start(&settings_file, u64::MAX, failing_wait, instant)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    drop(fake);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_signal_handler_that_cannot_be_installed_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let error = start(&settings_file, ONE_ROUND, cannot_listen, instant)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no handler"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_signal_future_stays_pending_until_a_signal_arrives() -> TestResult {
    let waiting = listen_for_signals()?;
    let outcome = tokio::time::timeout(Duration::ZERO, waiting).await;
    assert!(outcome.is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_against_a_missing_root_reports_the_scan_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(
        &settings_file,
        settings_text(dir.path(), &[("roots", format!("[{}]", dir.path().join("absent").display()))]),
    )?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let outcome = one_round(&pg, &tenant_scope("acme")?, &live).await?;
    assert_eq!(outcome.records, 0);
    assert_eq!(outcome.scan_errors, 1);
    report(&Ok(outcome));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_against_a_closed_port_is_a_database_error() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let failure = one_round(&pg, &tenant_scope("acme")?, &live).await.err().ok_or("expected an error")?;
    assert!(matches!(failure, RoundError::Pg(_)));
    report(&Err(failure));
    Ok(())
}


fn bad_value(dir: &Path, field: &str, value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let file = dir.join("bad.yaml");
    fs::write(&file, settings_text(dir, &[(field, value.to_owned())]))?;
    Ok(load_settings(&file).err().ok_or("expected a refusal")?.to_string())
}


#[test]
fn every_out_of_bound_setting_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let relative = "[certs]";
    let cases: Vec<(&str, String)> = vec![
        ("tenant", "all".to_owned()),
        ("tenant", "-x".to_owned()),
        ("roots", "[]".to_owned()),
        ("roots", relative.to_owned()),
        ("audit_file", "audit.log".to_owned()),
        ("host", "''".to_owned()),
        ("host", "-a".to_owned()),
        ("host", "a/b".to_owned()),
        ("host", "a".repeat(OVER_HOST)),
        ("interval_seconds", (MIN_INTERVAL_SECONDS - 1).to_string()),
        ("interval_seconds", (MAX_INTERVAL_SECONDS + 1).to_string()),
        ("max_depth", "0".to_owned()),
        ("max_depth", "17".to_owned()),
        ("deadline_seconds", (MAX_DEADLINE_SECONDS + 1).to_string()),
        ("max_certs", "0".to_owned()),
        ("max_certs", "200001".to_owned()),
    ];
    cases.iter().try_for_each(|(field, value)| {
        let text = bad_value(dir.path(), field, value)?;
        assert!(text.contains(&format!("settings.{field}")), "{field} {value}: {text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_host_grammar_accepts_names_and_refuses_the_rest() -> TestResult {
    assert!(is_host("a.b-c9"));
    assert!(is_host(&"a".repeat(MAX_HOST_BYTES)));
    assert!(!is_host(""));
    assert!(!is_host(&"a".repeat(MAX_HOST_BYTES + 1)));
    assert!(!is_host("a b"));
    assert!(!is_host(".a"));
    assert!(!is_host("-a"));
    Ok(())
}


#[test]
fn only_the_live_values_may_change_on_a_reload() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("a.yaml");
    fs::write(&file, settings_text(dir.path(), &[]))?;
    let baseline = load_settings(&file)?;
    let live = [
        ("host", "other.lab"),
        ("interval_seconds", LIVE_INTERVAL),
        ("max_depth", "5"),
        ("deadline_seconds", "6"),
        ("max_certs", "2000"),
    ];
    live.iter().try_for_each(|(field, value)| {
        fs::write(&file, settings_text(dir.path(), &[(field, (*value).to_owned())]))?;
        assert!(!start_only_changed(&baseline, &load_settings(&file)?), "{field}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let fixed = [
        ("tenant", "other".to_owned()),
        ("pg_settings", dir.path().join("x.yaml").display().to_string()),
        ("audit_file", dir.path().join("x.log").display().to_string()),
        ("roots", "[/srv/other]".to_owned()),
    ];
    fixed.iter().try_for_each(|(field, value)| {
        fs::write(&file, settings_text(dir.path(), &[(field, value.clone())]))?;
        assert!(start_only_changed(&baseline, &load_settings(&file)?), "{field}");
        assert_eq!(start_only_field(&baseline, &load_settings(&file)?), Some(*field));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_scan_path_is_percent_encoded_outside_the_source_allowlist() -> TestResult {
    assert_eq!(encoded("/etc/ssl/a b%é.pem"), "/etc/ssl/a%20b%25%C3%A9.pem");
    Ok(())
}


fn record(fingerprint: &str) -> CertRecord {
    CertRecord {
        fingerprint_sha256: fingerprint.to_owned(),
        subject: "CN=a".to_owned(),
        issuer: "CN=a".to_owned(),
        dns_names: Vec::new(),
        not_before: 0,
        not_after: 1,
        key_type: KeyType::Other,
        key_bits: None,
        self_signed: true,
    }
}


#[test]
fn certificates_are_grouped_by_path_and_counts_add_up() -> TestResult {
    let outcome = ScanOutcome {
        records: vec![
            FoundCert {
                record: record("a"),
                paths: vec!["/x".to_owned(), "/y".to_owned()],
                paths_omitted: 0,
            },
            FoundCert {
                record: record("b"),
                paths: vec!["/x".to_owned()],
                paths_omitted: 0,
            },
        ],
        examined: 0,
        skipped: SkipCounts::default(),
        malformed: BTreeMap::new(),
        max_open_dirs: 0,
        private_keys_refused: 0,
        roots_unreached: 0,
        roots_refused: 0,
        listing_cut: 0,
        errors: Vec::new(),
        errors_omitted: 0,
    };
    let grouped = by_path(&outcome);
    assert_eq!(grouped.get("/x").map(Vec::len), Some(INSERTED));
    assert_eq!(grouped.get("/y").map(Vec::len), Some(1));
    let one = StoreCounts {
        inserted: INSERTED,
        seen_again: SEEN_AGAIN,
        refused_full: REFUSED_FULL,
        refused_source: REFUSED_SOURCE,
        refused_record: REFUSED_RECORD,
        duplicate_in_batch: DUPLICATES,
    };
    let expected = StoreCounts {
        inserted: INSERTED + INSERTED,
        seen_again: SEEN_AGAIN + SEEN_AGAIN,
        refused_full: REFUSED_FULL + REFUSED_FULL,
        refused_source: REFUSED_SOURCE + REFUSED_SOURCE,
        refused_record: REFUSED_RECORD + REFUSED_RECORD,
        duplicate_in_batch: DUPLICATES + DUPLICATES,
    };
    assert_eq!(sum_counts(one, one), expected);
    Ok(())
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_poisoned| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn captured(action: impl FnOnce()) -> Result<String, Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Capture(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    with_default(&Dispatch::new(subscriber), action);
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok(String::from_utf8(bytes)?)
}


fn no_gaps() -> RoundGaps {
    RoundGaps {
        max_files: ALL_FILES,
        over_count: 0,
        not_regular: 0,
        too_large: 0,
        swapped: 0,
        vanished: 0,
        unreadable: 0,
        private_keys_refused: 0,
        roots_unreached: 0,
        roots_refused: 0,
        listing_cut: 0,
        paths_omitted: 0,
        malformed: Vec::new(),
    }
}


fn round_with(gaps: RoundGaps) -> RoundReport {
    RoundReport {
        records: 0,
        examined: 0,
        scan_errors: 0,
        counts: StoreCounts::default(),
        gaps,
    }
}


#[test]
fn a_round_that_lost_nothing_logs_no_gap_line() -> TestResult {
    let text = captured(|| report(&Ok(round_with(no_gaps()))))?;
    assert!(text.contains("scan round stored"), "{text}");
    assert!(!text.contains("scan gaps") && !text.contains("budget overrun"), "{text}");
    assert_eq!(gap_text(&no_gaps()), "");
    Ok(())
}


#[test]
fn every_gap_count_is_a_named_field_of_the_warn_line() -> TestResult {
    let cases: Vec<(String, RoundGaps)> = vec![
        (
            format!("not_regular={NOT_REGULAR_COUNT}"),
            RoundGaps {
                not_regular: NOT_REGULAR_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("too_large={TOO_LARGE_COUNT}"),
            RoundGaps {
                too_large: TOO_LARGE_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("swapped={SWAPPED_COUNT}"),
            RoundGaps {
                swapped: SWAPPED_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("vanished={VANISHED_COUNT}"),
            RoundGaps {
                vanished: VANISHED_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("unreadable={UNREADABLE_COUNT}"),
            RoundGaps {
                unreadable: UNREADABLE_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("private_keys_refused={KEYS_COUNT}"),
            RoundGaps {
                private_keys_refused: KEYS_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("roots_unreached={UNREACHED_COUNT}"),
            RoundGaps {
                roots_unreached: UNREACHED_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("roots_refused={REFUSED_ROOTS_COUNT}"),
            RoundGaps {
                roots_refused: REFUSED_ROOTS_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("listing_cut={LISTING_CUT_COUNT}"),
            RoundGaps {
                listing_cut: LISTING_CUT_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("paths_omitted={PATHS_OMITTED_COUNT}"),
            RoundGaps {
                paths_omitted: PATHS_OMITTED_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("over_count={OVER_COUNT}"),
            RoundGaps {
                over_count: OVER_COUNT,
                ..no_gaps()
            },
        ),
        (
            format!("malformed_pem={MALFORMED_COUNT}"),
            RoundGaps {
                malformed: vec![("pem", MALFORMED_COUNT)],
                ..no_gaps()
            },
        ),
    ];
    cases.into_iter().try_for_each(|(expected, gaps)| {
        let text = captured(|| report(&Ok(round_with(gaps))))?;
        assert!(text.contains("scan gaps") && text.contains(&expected), "{expected}: {text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_max_files_hit_is_a_named_budget_overrun_with_the_unreached_roots() -> TestResult {
    let gaps = RoundGaps {
        over_count: OVERRUN,
        roots_unreached: 1,
        ..no_gaps()
    };
    let text = captured(|| report(&Ok(round_with(gaps))))?;
    assert!(text.contains("scan budget overrun"), "{text}");
    assert!(
        text.contains("max_files=1000") && text.contains(&format!("over_count={OVERRUN_TEXT}")) && text.contains("roots_unreached=1"),
        "{text}"
    );
    let unreached_only = captured(|| {
        report(&Ok(round_with(RoundGaps {
            roots_unreached: 1,
            ..no_gaps()
        })))
    })?;
    assert!(!unreached_only.contains("budget overrun"), "{unreached_only}");
    Ok(())
}


fn found_omitting(name: &str) -> FoundCert {
    FoundCert {
        record: record(name),
        paths: vec!["/x".to_owned()],
        paths_omitted: PATHS_OMITTED_COUNT,
    }
}


#[test]
fn a_listing_cut_or_omitted_paths_alone_is_a_named_budget_overrun() -> TestResult {
    let cut = captured(|| report(&Ok(round_with(RoundGaps { listing_cut: 1, ..no_gaps() }))))?;
    let omitted = captured(|| {
        report(&Ok(round_with(RoundGaps {
            paths_omitted: PATHS_OMITTED_COUNT,
            ..no_gaps()
        })))
    })?;
    assert!(cut.contains("scan budget overrun") && cut.contains("listing_cut=1"), "{cut}");
    assert!(
        omitted.contains("scan budget overrun") && omitted.contains(&format!("paths_omitted={PATHS_OMITTED_COUNT}")),
        "{omitted}"
    );
    Ok(())
}


#[test]
fn the_gaps_of_an_outcome_carry_every_count() -> TestResult {
    let outcome = ScanOutcome {
        skipped: SkipCounts {
            over_count: OVER_COUNT,
            not_regular: NOT_REGULAR_COUNT,
            too_large: TOO_LARGE_COUNT,
            swapped: SWAPPED_COUNT,
            unreadable: UNREADABLE_COUNT,
            vanished: VANISHED_COUNT,
        },
        malformed: BTreeMap::from([("pem", MALFORMED_COUNT)]),
        private_keys_refused: KEYS_COUNT,
        roots_unreached: UNREACHED_COUNT,
        roots_refused: REFUSED_ROOTS_COUNT,
        listing_cut: LISTING_CUT_COUNT,
        records: vec![found_omitting("a"), found_omitting("b")],
        ..ScanOutcome::default()
    };
    let expected = RoundGaps {
        max_files: ALL_FILES,
        over_count: OVER_COUNT,
        not_regular: NOT_REGULAR_COUNT,
        too_large: TOO_LARGE_COUNT,
        swapped: SWAPPED_COUNT,
        vanished: VANISHED_COUNT,
        unreadable: UNREADABLE_COUNT,
        private_keys_refused: KEYS_COUNT,
        roots_unreached: UNREACHED_COUNT,
        roots_refused: REFUSED_ROOTS_COUNT,
        listing_cut: LISTING_CUT_COUNT,
        paths_omitted: PATHS_OMITTED_COUNT + PATHS_OMITTED_COUNT,
        malformed: vec![("pem", MALFORMED_COUNT)],
    };
    assert_eq!(gaps_of(&outcome, ALL_FILES), expected);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_flood_root_ahead_of_the_real_one_is_reported_through_a_round() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let flood = dir.path().join("flood");
    fs::create_dir_all(&flood)?;
    (0..=ALL_FILES).try_for_each(|index| fs::write(flood.join(format!("{index}.pem")), b""))?;
    let roots = format!("[{}, {}]", flood.display(), dir.path().join("certs").display());
    fs::write(&settings_file, settings_text(dir.path(), &[("roots", roots)]))?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let round = one_round(&pg, &tenant_scope("acme")?, &live).await?;
    assert_eq!(round.gaps.roots_unreached, 1);
    assert!(round.gaps.over_count > 0);
    assert_eq!(round.gaps.max_files, ALL_FILES);
    Ok(())
}


#[test]
fn a_blocking_task_that_never_ends_does_not_hold_the_runtime_past_the_grace() -> TestResult {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = block_on_with_grace(
            Box::pin(async move {
                let blocking = tokio::task::spawn_blocking(move || {
                    assert!(started_tx.send(()).is_ok());
                    match held.recv() {
                        Ok(()) | Err(_) => (),
                    }
                });
                started_rx.recv_timeout(HANG_GUARD)?;
                drop(blocking);
                Ok(())
            }),
            Duration::ZERO,
        );
        assert!(done_tx.send(result.is_ok()).is_ok());
    });
    let finished = done_rx.recv_timeout(HANG_GUARD);
    release.send(())?;
    worker.join().map_err(|_panic| "worker panicked")?;
    assert!(finished?);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn sigterm_during_the_migration_exits_zero() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, ca_pem) = fake_with(Arc::new(|_sql| Reply::Hang)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (child, reader) = spawn_service(&settings_file)?;
    let first = tokio::time::timeout(HANG_GUARD, fake.statements.recv()).await?;
    assert!(first.is_some());
    signal(&child, "-TERM")?;
    tokio::task::block_in_place(|| finish(child, reader))
}


static FINISH_SEEN: LazyLock<Notify> = LazyLock::new(Notify::new);


static FINISH_ACK: LazyLock<Notify> = LazyLock::new(Notify::new);


static SECOND_SEEN: LazyLock<Notify> = LazyLock::new(Notify::new);


static SECOND_CALLS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));


static SECOND_ACK: LazyLock<Notify> = LazyLock::new(Notify::new);


static NO_SECOND_SEEN: LazyLock<Notify> = LazyLock::new(Notify::new);


static NO_SECOND_ACK: LazyLock<Notify> = LazyLock::new(Notify::new);


static NO_SECOND_CALLS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));


static ERR_SEEN: LazyLock<Notify> = LazyLock::new(Notify::new);


static ERR_ACK: LazyLock<Notify> = LazyLock::new(Notify::new);


static WAIT_ERR: LazyLock<Notify> = LazyLock::new(Notify::new);


static WAIT_OK: LazyLock<Notify> = LazyLock::new(Notify::new);


async fn captured_async<Work: Future>(future: Work) -> Result<(Work::Output, String), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Capture(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    let output = future.with_subscriber(Dispatch::new(subscriber)).await;
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok((output, String::from_utf8(bytes)?))
}


fn blocking_store(seen: &'static LazyLock<Notify>, ack: &'static LazyLock<Notify>) -> Handler {
    Arc::new(move |sql| {
        if sql.contains(STORE_MARKER) {
            seen.notify_one();
            let acked = tokio::task::block_in_place(|| Handle::current().block_on(tokio::time::timeout(HANG_GUARD, ack.notified()))).is_ok();
            if acked {
                Reply::Rows(vec![["1", "0", "0"].map(str::to_owned).to_vec()])
            } else {
                Reply::Error("XX000")
            }
        } else {
            Reply::Done
        }
    })
}


fn forever(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(pending())
}


fn after_finish_store() -> io::Result<InterruptWait> {
    Ok(Box::pin(async {
        FINISH_SEEN.notified().await;
        FINISH_ACK.notify_one();
        Ok(())
    }))
}


fn second_comes_at_once() -> io::Result<InterruptWait> {
    if SECOND_CALLS.try_acquire().map(|permit| permit.forget()).is_ok() {
        Ok(Box::pin(async {
            SECOND_SEEN.notified().await;
            Ok(())
        }))
    } else {
        Ok(Box::pin(async {
            SECOND_ACK.notify_one();
            Ok(())
        }))
    }
}


fn second_cannot_be_armed() -> io::Result<InterruptWait> {
    if NO_SECOND_CALLS.try_acquire().map(|permit| permit.forget()).is_ok() {
        Ok(Box::pin(async {
            NO_SECOND_SEEN.notified().await;
            NO_SECOND_ACK.notify_one();
            Ok(())
        }))
    } else {
        cannot_listen()
    }
}


fn failing_in_the_round() -> io::Result<InterruptWait> {
    Ok(Box::pin(async {
        ERR_SEEN.notified().await;
        ERR_ACK.notify_one();
        Err(io::Error::other("no signal"))
    }))
}


fn failing_in_the_wait() -> io::Result<InterruptWait> {
    Ok(Box::pin(async {
        WAIT_ERR.notified().await;
        Err(io::Error::other("no signal"))
    }))
}


fn ending_in_the_wait() -> io::Result<InterruptWait> {
    Ok(Box::pin(async {
        WAIT_OK.notified().await;
        Ok(())
    }))
}


fn release_wait_error(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {
        WAIT_ERR.notify_one();
        pending::<()>().await;
    })
}


fn release_wait_end(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {
        WAIT_OK.notify_one();
        pending::<()>().await;
    })
}


async fn run_start(handler: Handler, interrupt: InterruptFn, wait: WaitFn) -> Result<(Fake, String, String), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(handler).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (outcome, log) = captured_async(start(&settings_file, u64::MAX, interrupt, wait)).await?;
    let failure = outcome.err().map(|error| error.to_string()).unwrap_or_else(|| "none".to_owned());
    Ok((fake, log, failure))
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_during_a_round_lets_it_store_and_log_its_line_before_return() -> TestResult {
    let (fake, log, failure) = run_start(blocking_store(&FINISH_SEEN, &FINISH_ACK), after_finish_store, forever).await?;
    assert_eq!(failure, "none");
    assert!(
        log.contains("finishing the round in flight") && log.contains("scan round stored"),
        "{log}"
    );
    assert!(!log.contains("round cut"), "{log}");
    assert_eq!(statements_after(fake).await, 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_second_interrupt_is_logged_and_the_round_still_finishes() -> TestResult {
    let (fake, log, failure) = run_start(blocking_store(&SECOND_SEEN, &SECOND_ACK), second_comes_at_once, forever).await?;
    assert_eq!(failure, "none");
    assert!(
        log.contains("stop already in progress") && log.contains("scan round stored") && !log.contains("round cut"),
        "{log}"
    );
    assert_eq!(statements_after(fake).await, 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_second_interrupt_that_cannot_be_armed_leaves_the_round_to_finish() -> TestResult {
    let (fake, log, failure) = run_start(blocking_store(&NO_SECOND_SEEN, &NO_SECOND_ACK), second_cannot_be_armed, forever).await?;
    assert_eq!(failure, "none");
    assert!(
        log.contains("no second interrupt can be armed") && log.contains("scan round stored"),
        "{log}"
    );
    assert!(!log.contains("round cut"), "{log}");
    assert_eq!(statements_after(fake).await, 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_during_a_round_is_an_error() -> TestResult {
    let (fake, log, failure) = run_start(blocking_store(&ERR_SEEN, &ERR_ACK), failing_in_the_round, forever).await?;
    assert!(failure.contains("no signal"), "{failure}");
    assert!(log.contains("scan round stored"), "the round was dropped: {log}");
    assert_eq!(statements_after(fake).await, 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_between_rounds_is_an_error() -> TestResult {
    let (fake, log, failure) = run_start(storing(), failing_in_the_wait, release_wait_error).await?;
    assert!(failure.contains("no signal") && log.contains("scan round stored"), "{failure} {log}");
    drop(fake);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_between_rounds_ends_the_service() -> TestResult {
    let (fake, log, failure) = run_start(storing(), ending_in_the_wait, release_wait_end).await?;
    assert_eq!(failure, "none");
    assert!(log.contains("scan round stored"), "{log}");
    assert_eq!(statements_after(fake).await, 1);
    Ok(())
}


fn reload_guard(worker: Option<std::thread::JoinHandle<()>>) -> Result<ReloadThread, Box<dyn std::error::Error>> {
    let stream = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])?;
    Ok(ReloadThread {
        handle: stream.handle(),
        worker,
    })
}


#[test]
fn a_reload_thread_that_panicked_is_logged_when_the_guard_drops() -> TestResult {
    let worker = std::thread::spawn(|| std::panic::resume_unwind(Box::new("reload thread")));
    let guard = reload_guard(Some(worker))?;
    let text = captured(move || drop(guard))?;
    assert!(text.contains("the reload thread panicked"), "{text}");
    Ok(())
}


#[test]
fn a_clean_or_absent_reload_thread_logs_nothing_when_the_guard_drops() -> TestResult {
    let clean = reload_guard(Some(std::thread::spawn(|| ())))?;
    let absent = reload_guard(None)?;
    let text = captured(move || {
        drop(clean);
        drop(absent);
    })?;
    assert!(!text.contains("panicked"), "{text}");
    Ok(())
}


const WATCH_DROP_PATIENCE: Duration = Duration::from_millis(500);


fn stop_signal(sender: std::sync::mpsc::Sender<()>) -> StopWatchFn {
    Box::new(move || {
        if sender.send(()).is_err() {
            tracing::error!("nobody listens for the watch stop");
        }
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn the_service_waits_for_a_reload_in_flight_before_it_returns() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let baseline = load_settings(&settings_file)?;
    let pg_text = fs::read_to_string(&baseline.pg_settings)?;
    let pg = load_pg_settings(&baseline.pg_settings)?;
    let audit = boxed_reload_audit(open_file_log(&baseline.audit_file)?);
    let engine = Arc::new(open_cert_settings_from(&settings_file, baseline, pg_digest(&pg_text), audit)?);
    let (locked_sender, locked_receiver) = std::sync::mpsc::channel::<()>();
    let (release_sender, release_receiver) = std::sync::mpsc::channel::<()>();
    let (dropped_sender, dropped_receiver) = std::sync::mpsc::channel::<()>();
    let held = Arc::clone(&engine);
    let holder = tokio::task::spawn_blocking(move || {
        let _in_flight = held.gate.lock().map_err(|_poisoned| "poisoned")?;
        locked_sender.send(())?;
        release_receiver.recv()?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    tokio::task::block_in_place(|| locked_receiver.recv())?;
    let service_engine = Arc::clone(&engine);
    let (done_sender, done_receiver) = std::sync::mpsc::channel::<Result<(), String>>();
    let service = std::thread::spawn(move || {
        let outcome = at_once().map_err(|error| error.to_string()).and_then(|mut interrupted| {
            block_on_with_grace(
                Box::pin(serve_then_quiesce(
                    stop_signal(dropped_sender),
                    1,
                    &service_engine,
                    &pg,
                    instant,
                    at_once,
                    &mut interrupted,
                )),
                Duration::ZERO,
            )
            .map_err(|error| error.to_string())
        });
        done_sender.send(outcome)
    });
    tokio::task::block_in_place(|| dropped_receiver.recv())?;
    let early = tokio::task::block_in_place(|| done_receiver.recv_timeout(WATCH_DROP_PATIENCE));
    assert_eq!(
        early,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "the service returned while a reload held the gate"
    );
    release_sender.send(())?;
    holder.await?.map_err(|error| error.to_string())?;
    tokio::task::block_in_place(|| done_receiver.recv_timeout(HANG_GUARD))??;
    service.join().map_err(|_panicked| "service thread panicked")??;
    drop(fake);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_changed_pg_settings_file_makes_a_reload_refused_and_audited() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let baseline = load_settings(&settings_file)?;
    let pg_file = baseline.pg_settings.clone();
    let pg_text = fs::read_to_string(&pg_file)?;
    let audit_file = baseline.audit_file.clone();
    let audit = boxed_reload_audit(open_file_log(&audit_file)?);
    let engine = open_cert_settings_from(&settings_file, baseline, pg_digest(&pg_text), audit)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    fs::write(&pg_file, format!("{pg_text}connect_timeout_secs: 7\n"))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("pg_settings")),
        "{outcome:?}"
    );
    assert!(fs::read_to_string(&audit_file)?.contains("denied"));
    drop(fake);
    Ok(())
}


fn store_failure(path_index: usize, source: PgError) -> RoundError {
    RoundError::Store {
        path_index,
        counts: StoreCounts {
            inserted: INSERTED,
            ..StoreCounts::default()
        },
        source: Box::new(InventoryStoreError::Pg(source)),
    }
}


#[tokio::test]
async fn every_failure_has_a_fixed_class_and_its_progress() -> TestResult {
    let task = tokio::spawn(pending::<()>());
    task.abort();
    let join = RoundError::Scan(task.await.err().ok_or("expected a join error")?);
    let connect = RoundError::Pg(PgError::InvalidTenant);
    let unknown = store_failure(1, PgError::ClientDeadline { seconds: 1 });
    let refused = store_failure(1, PgError::InvalidTenant);
    assert_eq!(failure_class(&join), "scan_task");
    assert_eq!(failure_class(&connect), "connect");
    assert_eq!(failure_class(&unknown), UNKNOWN_CLASS);
    assert_eq!(failure_class(&refused), "store");
    assert_eq!(progress_of(&join), (0, StoreCounts::default()));
    assert_eq!(progress_of(&connect), (0, StoreCounts::default()));
    assert_eq!(progress_of(&unknown).0, 1);
    assert_eq!(progress_of(&unknown).1.inserted, INSERTED);
    Ok(())
}


#[test]
fn an_unknown_outcome_is_logged_as_unknown_and_a_refusal_as_failed() -> TestResult {
    let unknown = captured(|| report(&Err(store_failure(1, PgError::ClientDeadline { seconds: 1 }))))?;
    let refused = captured(|| report(&Err(store_failure(1, PgError::InvalidTenant))))?;
    assert!(
        unknown.contains("outcome unknown") && unknown.contains("may have committed") && unknown.contains("path_index=1"),
        "{unknown}"
    );
    assert!(unknown.contains("store_unknown") && unknown.contains("inserted: 2"), "{unknown}");
    assert!(refused.contains("scan round failed") && !refused.contains("outcome unknown"), "{refused}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_connection_lost_in_the_second_store_keeps_the_first_counts_and_is_unknown() -> TestResult {
    let dir = tempdir()?;
    let stores = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&stores);
    let handler: Handler = Arc::new(move |sql| {
        if sql.contains(STORE_MARKER) {
            counter.fetch_add(1, Ordering::SeqCst);
            Reply::Rows(vec![["1", "0", "0"].map(str::to_owned).to_vec()])
        } else if counter.load(Ordering::SeqCst) > 0 {
            Reply::Drop
        } else {
            Reply::Done
        }
    });
    let (fake, ca_pem) = fake_with(handler).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::copy(dir.path().join("certs/one.pem"), dir.path().join("certs/two.pem"))?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let failure = one_round(&pg, &tenant_scope("acme")?, &live).await.err().ok_or("expected an error")?;
    let (path_index, counts) = progress_of(&failure);
    assert_eq!(path_index, 1);
    assert_eq!(counts.inserted, 1);
    assert_eq!(failure_class(&failure), UNKNOWN_CLASS, "{failure:?}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_connect_failure_never_prints_the_file_it_names() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let pg_text = fs::read_to_string(dir.path().join("pg.yaml"))?;
    fs::write(dir.path().join("pg.yaml"), pg_text.replace("ca.pem", "marker-ca-file.pem"))?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let failure = one_round(&pg, &tenant_scope("acme")?, &live).await.err().ok_or("expected an error")?;
    assert!(failure.to_string().contains("marker-ca-file"), "{failure}");
    let text = captured(|| report(&Err(failure)))?;
    assert!(text.contains("class=\"connect\"") && !text.contains("marker-ca-file"), "{text}");
    Ok(())
}

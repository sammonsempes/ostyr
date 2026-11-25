#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use cert_inventory::error::RoundError;
use cert_inventory::model::{CertRecord, FoundCert, KeyType, ScanOutcome, SkipCounts, StoreCounts};
use cert_inventory::serve::{
    by_path, encoded, is_host, listen_for_signals, load_settings, one_round, pause, report, start, start_only_changed, sum_counts,
    MAX_DEADLINE_SECONDS, MAX_HOST_BYTES, MAX_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS,
};
use cert_inventory::types::InterruptWait;
use core_pg::scope::tenant_scope;
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::{CertificateParams, KeyPair, SanType};
use std::collections::BTreeMap;
use std::fs;
use std::future::{pending, ready, Future};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-certs");


const OWNER_ONLY: u32 = 0o600;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const STORE_MARKER: &str = "jsonb_to_recordset";


const TWO_ROUNDS: u64 = 2;


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

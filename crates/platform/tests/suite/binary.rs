use crate::fixture::{PAGE_TEXT, WEIGHTS_TEXT};
use crate::types::{TestError, TestResult};
use axum::Router;
use core_api::server::{listening_address, new_listener, run_loaded};
use core_api::types::AccessTable;
use core_config::load::load_module;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use platform::serve::{announce, stop_on};
use rcgen::SanType;
use serde_json::Value;
use std::fs;
use std::future::ready;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::Arc;
use tempfile::tempdir;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-platform");


const OWNER_ONLY: u32 = 0o600;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 5;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const SERVING_MARKER: &str = "\"serving\"";


const READ_REQUEST: &str = "GET /alerts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";


const START_ONLY: [&str; 1] = ["modules"];


const MIGRATION_TABLE: &str = "CREATE TABLE IF NOT EXISTS public.schema_migrations";


fn private_file(path: &Path, bytes: &[u8]) -> Result<(), TestError> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn write_site(dir: &Path, port: u16, ca_pem: &str, modules: &str, extra: &str) -> Result<PathBuf, TestError> {
    private_file(&dir.join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("compromised.txt"), "passwordpassword\n")?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(dir.join("weights.yaml"), WEIGHTS_TEXT)?;
    fs::write(dir.join("page.yaml"), PAGE_TEXT)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    let module_file = dir.join("platform.yaml");
    fs::write(
        &module_file,
        format!(
            "name: platform\nversion: \"1\"\ntenant: acme\nlisten: \"127.0.0.1:0\"\nsettings:\n  modules: \"{modules}\"\n  pg_settings: {}\n  accounts_store: {}\n  \
             audit_log: {}\n  key_file: {}\n  compromised_list: {}\n{extra}",
            dir.join("pg.yaml").display(),
            dir.join("accounts.json").display(),
            dir.join("audit.log").display(),
            dir.join("store.key").display(),
            dir.join("compromised.txt").display(),
        ),
    )?;
    Ok(module_file)
}


fn weights_line(dir: &Path) -> String {
    format!("  risk.weights_file: {}\n", dir.join("weights.yaml").display())
}


fn page_line(dir: &Path) -> String {
    format!("  status.page_file: {}\n", dir.join("page.yaml").display())
}


const SECOND_LINE: usize = 1;


const THIRD_LINE: usize = 2;


const DIGEST: &str = "abababababababababababababababababababababababababababababababab";


fn traces_lines(dir: &Path, with_tls: bool) -> Result<String, TestError> {
    fs::write(
        dir.join("traces.yaml"),
        format!(
            "url: http://127.0.0.1:1\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\n",
            dir.join("pg.pass").display()
        ),
    )?;
    fs::write(dir.join("sampling.yaml"), "default_ratio: 1.0\n")?;
    fs::write(
        dir.join("senders.yaml"),
        format!("senders:\n  - name: collector\n    token_sha256: {DIGEST}\n"),
    )?;
    let tls = if with_tls {
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        fs::write(dir.join("server.pem"), pair.cert.pem())?;
        private_file(&dir.join("server.key"), pair.signing_key.serialize_pem().as_bytes())?;
        format!(
            "  tls_certificate: {}\n  tls_key: {}\n",
            dir.join("server.pem").display(),
            dir.join("server.key").display()
        )
    } else {
        String::new()
    };
    Ok(format!(
        "  traces.settings_file: {}\n  traces.sampling_file: {}\n  otlp.senders_file: {}\n{tls}",
        dir.join("traces.yaml").display(),
        dir.join("sampling.yaml").display(),
        dir.join("senders.yaml").display()
    ))
}


fn serve_tls_then_interrupt(module_file: &Path) -> TestResult {
    let mut child = Command::new(PROGRAM)
        .arg(module_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let address = address_of(&mut reader)?;
    assert!(TcpStream::connect(address).is_ok());
    interrupt(&child)?;
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    assert!(child.wait()?.success(), "{rest}");
    Ok(())
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, TestError> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> Result<(), TestError> {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn serving_address(line: &str) -> Result<Option<SocketAddr>, TestError> {
    if line.contains(SERVING_MARKER) {
        let json: Value = serde_json::from_str(line)?;
        Ok(Some(json.get("address").and_then(Value::as_str).ok_or("no address")?.parse()?))
    } else {
        Ok(None)
    }
}


fn address_of(reader: &mut BufReader<ChildStdout>) -> Result<SocketAddr, TestError> {
    reader
        .by_ref()
        .lines()
        .map(|line| serving_address(&line?))
        .find_map(Result::transpose)
        .ok_or("the child ended before it served")?
}


fn status_line(address: SocketAddr) -> Result<String, TestError> {
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(READ_REQUEST.as_bytes())?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply.lines().next().ok_or("empty reply")?.to_owned())
}


fn interrupt(child: &Child) -> TestResult {
    let status = Command::new("kill").arg("-INT").arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn serve_then_interrupt(module_file: &Path) -> TestResult {
    let mut child = Command::new(PROGRAM)
        .arg(module_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let address = address_of(&mut reader)?;
    let status = status_line(address)?;
    assert!(status.contains("401"), "{status}");
    interrupt(&child)?;
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(())
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), TestError> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn accepting() -> Handler {
    Arc::new(|_| Reply::Done)
}


#[test]
fn a_missing_argument_prints_the_usage_and_fails() -> TestResult {
    let output = run_to_end(&[])?;
    refused_with(&output, "usage: ostyr-platform <module.yaml>")
}


#[test]
fn an_unreadable_module_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    let output = run_to_end(&[&missing])?;
    refused_with(&output, "absent.yaml")
}


#[test]
fn an_invalid_module_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, "name: [\n")?;
    refused_with(&run_to_end(&[&module_file])?, "platform.yaml")
}


#[test]
fn an_unknown_module_is_refused_before_any_connection() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,bogus", "")?;
    refused_with(&run_to_end(&[&module_file])?, "module")
}


#[test]
fn risk_without_a_weights_file_names_the_key() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,risk", "")?;
    refused_with(&run_to_end(&[&module_file])?, "risk.weights_file")
}


#[test]
fn status_without_a_page_file_names_the_key() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,status", "")?;
    refused_with(&run_to_end(&[&module_file])?, "page_file")
}


#[test]
fn a_page_of_another_tenant_is_refused() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,status", &page_line(dir.path()))?;
    fs::write(dir.path().join("page.yaml"), PAGE_TEXT.replace("tenant: acme", "tenant: other"))?;
    refused_with(&run_to_end(&[&module_file])?, "tenant")
}


#[test]
fn a_missing_pg_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts", "")?;
    fs::remove_file(dir.path().join("pg.yaml"))?;
    refused_with(&run_to_end(&[&module_file])?, "pg.yaml")
}


#[test]
fn an_invalid_weights_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,risk", &weights_line(dir.path()))?;
    fs::write(dir.path().join("weights.yaml"), "severity_points: nope\n")?;
    refused_with(&run_to_end(&[&module_file])?, "weights.yaml")
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts", "")?;
    let output = run_to_end(&[&module_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains(MIGRATION_TABLE) {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "alerts", "")?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&module_file]))?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_key_file_that_is_missing_fails_after_the_migrations() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "alerts", "")?;
    fs::remove_file(dir.path().join("store.key"))?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&module_file]))?;
    refused_with(&output, "key file rejected")
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_request_and_exits_cleanly_on_the_interrupt() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "alerts,cases", "")?;
    tokio::task::block_in_place(|| serve_then_interrupt(&module_file))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_risk_and_status_with_their_files() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let extra = format!("{}{}", weights_line(dir.path()), page_line(dir.path()));
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "alerts,risk,status", &extra)?;
    tokio::task::block_in_place(|| serve_then_interrupt(&module_file))
}


#[tokio::test]
async fn announce_waits_for_the_server_and_stop_on_stops_it_only_on_a_signal() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts", "")?;
    let loaded = load_module(&module_file)?;
    let listener = new_listener();
    let running = listener.clone();
    let file = module_file.clone();
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None, Vec::new()).await });
    announce(listener.clone()).await;
    stop_on(listener.clone(), Box::pin(ready(Err(io::Error::other("no signal"))))).await;
    assert!(listening_address(&listener).await.is_some());
    stop_on(listener.clone(), Box::pin(ready(Ok(())))).await;
    assert!(task.await?.is_ok());
    Ok(())
}


#[test]
fn an_unreadable_page_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "alerts,status", &page_line(dir.path()))?;
    fs::remove_file(dir.path().join("page.yaml"))?;
    refused_with(&run_to_end(&[&module_file])?, "cannot be read")
}


#[tokio::test(flavor = "multi_thread")]
async fn a_module_file_without_a_tenant_serves_the_default_tenant() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "alerts,risk", &weights_line(dir.path()))?;
    let text = fs::read_to_string(&module_file)?;
    fs::write(&module_file, text.replace("tenant: acme\n", ""))?;
    tokio::task::block_in_place(|| serve_then_interrupt(&module_file))
}


#[test]
fn traces_without_each_of_its_keys_names_the_key() -> TestResult {
    let dir = tempdir()?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "traces", "")?;
    refused_with(&run_to_end(&[&module_file])?, "traces.settings_file")?;
    let full = traces_lines(dir.path(), true)?;
    let lines: Vec<&str> = full.lines().collect();
    for (kept, missing) in [(SECOND_LINE, "traces.sampling_file"), (THIRD_LINE, "otlp.senders_file")] {
        let extra: String = lines.iter().take(kept).map(|line| format!("{line}\n")).collect();
        let partial = write_site(dir.path(), CLOSED_PORT, "", "traces", &extra)?;
        refused_with(&run_to_end(&[&partial])?, missing)?;
    }
    Ok(())
}


#[test]
fn traces_without_tls_is_refused_even_on_loopback() -> TestResult {
    let dir = tempdir()?;
    let extra = traces_lines(dir.path(), false)?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "traces", &extra)?;
    refused_with(&run_to_end(&[&module_file])?, "tls_certificate")
}


#[test]
fn an_invalid_senders_file_fails_the_start_without_naming_a_digest() -> TestResult {
    let dir = tempdir()?;
    let extra = traces_lines(dir.path(), true)?;
    let module_file = write_site(dir.path(), CLOSED_PORT, "", "traces", &extra)?;
    fs::write(
        dir.path().join("senders.yaml"),
        format!("senders:\n  - name: collector\n    token_sha256: {}\n", DIGEST.to_uppercase()),
    )?;
    let output = run_to_end(&[&module_file])?;
    refused_with(&output, "senders[0].token_sha256")?;
    assert!(!String::from_utf8(output.stderr)?.contains(&DIGEST.to_uppercase()));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_traces_over_tls_and_exits_cleanly_on_the_interrupt() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let extra = traces_lines(dir.path(), true)?;
    let module_file = write_site(dir.path(), fake.port, &ca_pem, "traces", &extra)?;
    tokio::task::block_in_place(|| serve_tls_then_interrupt(&module_file))
}

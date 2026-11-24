#![cfg(unix)]


#[path = "binary_support/types.rs"]
mod binary_types;
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;


use agent_channel::client::{connect_channel, push_events};
use agent_channel::model::ClientTlsPaths;
use agent_channel::proto::EventBatch;
use agent_channel::tls::client_config;
use binary_types::{Failure, TestResult};
use nats_stub::{kill_connections, lock, start_stub, wait_until};
use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use tempfile::tempdir;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-event-gateway");


const SERVER_NAME: &str = "localhost";


const AGENT_URI: &str = "urn:ostyr:agent:acme:agent-1";


const PRIVATE_MODE: u32 = 0o600;


struct Leaf {
    certificate: PathBuf,
    key: PathBuf,
}


fn write_leaf(dir: &Path, name: &str, issuer: &Issuer<'static, KeyPair>, params: CertificateParams) -> Result<Leaf, Failure> {
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, issuer)?;
    let leaf = Leaf {
        certificate: dir.join(format!("{name}.crt")),
        key: dir.join(format!("{name}.key")),
    };
    fs::write(&leaf.certificate, certificate.pem())?;
    fs::write(&leaf.key, key.serialize_pem())?;
    fs::set_permissions(&leaf.key, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(leaf)
}


const SERVING_MARKER: &str = "serving";


const ADDRESS_FIELD: &str = "address=";


struct Running {
    child: Child,
    reader: BufReader<ChildStderr>,
    address: SocketAddr,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::warn!(%error, "the gateway child was already gone");
        }
    }
}


struct Site {
    server_file: PathBuf,
    gateway_file: PathBuf,
    client: ClientTlsPaths,
}


fn write_site(dir: &Path, nats_port: u16) -> Result<Site, Failure> {
    let authority_key = KeyPair::generate()?;
    let mut authority_params = CertificateParams::new(Vec::<String>::new())?;
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let authority = authority_params.self_signed(&authority_key)?;
    let ca = dir.join("ca.pem");
    fs::write(&ca, authority.pem())?;
    let issuer = Issuer::new(authority_params, authority_key);
    let mut server_params = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = write_leaf(dir, "server", &issuer, server_params)?;
    let mut agent_params = CertificateParams::new(Vec::<String>::new())?;
    agent_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    agent_params.subject_alt_names.push(SanType::URI(Ia5String::try_from(AGENT_URI)?));
    let agent = write_leaf(dir, "agent", &issuer, agent_params)?;
    fs::write(dir.join("revoked.yaml"), "revoked_serials: []\n")?;
    fs::write(dir.join("channel.yaml"), "{}\n")?;
    fs::write(dir.join("gateway.yaml"), format!("nats_url: \"nats://127.0.0.1:{nats_port}\"\n"))?;
    let server_file = dir.join("server.yaml");
    fs::write(
        &server_file,
        format!(
            "listen: \"127.0.0.1:0\"\ncertificate: {}\nkey: {}\nagent_ca: {}\nrevocation_file: {}\nsettings_file: {}\naudit_file: {}\n\
             events_file: {}\ncommands_dir: {}\n",
            server.certificate.display(),
            server.key.display(),
            ca.display(),
            dir.join("revoked.yaml").display(),
            dir.join("channel.yaml").display(),
            dir.join("server-audit.log").display(),
            dir.join("unused-events.log").display(),
            dir.join("commands").display(),
        ),
    )?;
    let gateway_file = dir.join("gateway-file.yaml");
    fs::write(
        &gateway_file,
        format!(
            "settings_file: {}\naudit_file: {}\n",
            dir.join("gateway.yaml").display(),
            dir.join("gateway-audit.log").display()
        ),
    )?;
    Ok(Site {
        server_file,
        gateway_file,
        client: ClientTlsPaths {
            certificate: agent.certificate,
            key: agent.key,
            platform_ca: ca,
        },
    })
}


fn address_of(line: &str) -> Option<SocketAddr> {
    line.split_once(ADDRESS_FIELD)?.1.split_whitespace().next()?.parse().ok()
}


fn start(site: &Site) -> Result<Running, Failure> {
    let mut child = Command::new(PROGRAM)
        .arg(&site.server_file)
        .arg(&site.gateway_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let mut reader = BufReader::new(stderr);
    let line = reader
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(SERVING_MARKER).then_some(text)).transpose())
        .ok_or("the child ended before it served")??;
    let address = address_of(&line).ok_or("no address in the serving line")?;
    Ok(Running { child, reader, address })
}


fn send(running: &Running, signal: &str) -> TestResult {
    let status = Command::new("kill").arg(signal).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn stop_with(mut running: Running, signal: &str) -> TestResult {
    send(&running, signal)?;
    let mut rest = String::new();
    running.reader.read_to_string(&mut rest)?;
    let status = running.child.wait()?;
    assert!(status.success(), "{status}: {rest}");
    Ok(())
}


fn run_to_end(arguments: &[&Path], directives: Option<&str>) -> Result<Output, Failure> {
    let mut command = Command::new(PROGRAM);
    command.args(arguments).stdin(Stdio::null());
    if let Some(text) = directives {
        command.env("RUST_LOG", text);
    }
    Ok(command.output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_batch_is_published_and_sigint_stops_the_gateway_cleanly() -> TestResult {
    let dir = tempdir()?;
    let stub = start_stub(None, |_| {})?;
    let site = write_site(dir.path(), stub.port)?;
    let running = start(&site)?;
    let config = client_config(&site.client)?;
    let channel = connect_channel(running.address, config, SERVER_NAME).await?;
    let batch = EventBatch {
        sequence: 1,
        ecs_json: b"{\"message\":\"hello\"}".to_vec(),
        tenant: String::new(),
        agent_id: String::new(),
    };
    let acknowledged = push_events(channel, vec![batch]).await?;
    assert_eq!(acknowledged, vec![1]);
    wait_until(&stub, |state| !state.published.is_empty()).map_err(|error| error.to_string())?;
    assert_eq!(
        lock(&stub.hub).published.first().map(|message| message.subject.clone()),
        Some("events.acme".to_owned())
    );
    let first = lock(&stub.hub)
        .published
        .first()
        .map(|message| (message.headers.clone(), message.payload.clone()));
    let (headers, payload) = first.ok_or("nothing published")?;
    assert!(headers.contains("acme:agent-1:1:0"), "{headers}");
    assert!(String::from_utf8(payload)?.contains("\"tenant\":\"acme\""));
    kill_connections(&stub);
    assert!(dir.path().join("gateway-audit.log").exists());
    stop_with(running, "-INT")
}


#[test]
fn sigterm_stops_the_gateway_cleanly() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1)?;
    stop_with(start(&site)?, "-TERM")
}


#[test]
fn a_wrong_argument_count_is_a_usage_error() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1)?;
    refused_with(&run_to_end(&[], None)?, "usage")?;
    refused_with(&run_to_end(&[&site.server_file], None)?, "usage")?;
    refused_with(&run_to_end(&[&site.server_file, &site.gateway_file, &site.gateway_file], None)?, "usage")
}


#[test]
fn a_missing_or_invalid_file_names_the_file() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1)?;
    let missing = dir.path().join("missing.yaml");
    refused_with(&run_to_end(&[&missing, &site.gateway_file], None)?, "missing.yaml")?;
    refused_with(&run_to_end(&[&site.server_file, &missing], None)?, "missing.yaml")?;
    let no_audit = dir.path().join("no-audit.yaml");
    fs::write(&no_audit, format!("settings_file: {}\n", dir.path().join("gateway.yaml").display()))?;
    refused_with(&run_to_end(&[&site.server_file, &no_audit], None)?, "no-audit.yaml")
}


#[test]
fn an_unwritable_audit_path_or_a_busy_port_or_bad_log_directives_refuse_the_start() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1)?;
    let unwritable = dir.path().join("unwritable.yaml");
    fs::write(
        &unwritable,
        format!(
            "settings_file: {}\naudit_file: {}\n",
            dir.path().join("gateway.yaml").display(),
            dir.path().join("none").join("audit.log").display()
        ),
    )?;
    let output = run_to_end(&[&site.server_file, &unwritable], None)?;
    assert!(!output.status.success());
    let held = TcpListener::bind("127.0.0.1:0")?;
    let busy = dir.path().join("busy.yaml");
    let server_text = fs::read_to_string(&site.server_file)?.replace("127.0.0.1:0", &held.local_addr()?.to_string());
    fs::write(&busy, server_text)?;
    let busy_output = run_to_end(&[&busy, &site.gateway_file], None)?;
    assert!(!busy_output.status.success());
    let log_output = run_to_end(&[&site.server_file, &site.gateway_file], Some("info=notalevel"))?;
    assert!(!log_output.status.success());
    Ok(())
}

mod common;


use agent_channel::server_app::ServerFile;
use common::types::TestResult;
use event_gateway::error::GatewayError;
use event_gateway::model::GatewayFile;
use event_gateway::run::{load_gateway_file, run_gateway};
use rcgen::generate_simple_self_signed;
use std::error::Error;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use tokio::net::TcpListener;


#[cfg(unix)]
fn set_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    const PRIVATE_MODE: u32 = 0o600;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_MODE))
}


#[cfg(not(unix))]
fn set_private(_path: &Path) -> std::io::Result<()> {
    Ok(())
}


fn server_file(dir: &Path) -> Result<ServerFile, Box<dyn Error + Send + Sync>> {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = dir.join("server.crt");
    let key = dir.join("server.key");
    fs::write(&certificate, certified.cert.pem())?;
    fs::write(&key, certified.signing_key.serialize_pem())?;
    set_private(&key)?;
    let revocation_file = dir.join("revoked.yaml");
    fs::write(&revocation_file, "revoked_serials: []\n")?;
    let settings_file = dir.join("channel.yaml");
    fs::write(&settings_file, "{}\n")?;
    Ok(ServerFile {
        listen: "127.0.0.1:0".to_owned(),
        agent_ca: certificate.clone(),
        certificate,
        key,
        revocation_file,
        settings_file,
        audit_file: dir.join("server-audit.log"),
        events_file: dir.join("unused-events.log"),
        commands_dir: dir.join("commands"),
    })
}


fn gateway_file(dir: &Path, settings: &str) -> Result<GatewayFile, Box<dyn Error + Send + Sync>> {
    let settings_file = dir.join("gateway.yaml");
    fs::write(&settings_file, settings)?;
    Ok(GatewayFile {
        settings_file,
        audit_file: dir.join("gateway-audit.log"),
    })
}


#[tokio::test]
async fn the_gateway_serves_and_stops_on_shutdown() -> TestResult {
    let dir = tempdir()?;
    let server = server_file(dir.path())?;
    let gateway = gateway_file(dir.path(), "nats_url: \"nats://127.0.0.1:1\"\n")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    run_gateway(server, gateway, listener, Box::pin(async {})).await?;
    assert!(dir.path().join("gateway-audit.log").exists());
    assert!(!dir.path().join("unused-events.log").exists());
    Ok(())
}


#[tokio::test]
async fn invalid_gateway_settings_stop_the_start() -> TestResult {
    let dir = tempdir()?;
    let server = server_file(dir.path())?;
    let gateway = gateway_file(dir.path(), "max_in_flight_batches: 0\n")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let outcome = run_gateway(server, gateway, listener, Box::pin(async {})).await;
    assert!(matches!(outcome, Err(GatewayError::Settings(_))));
    Ok(())
}


#[tokio::test]
async fn an_unreadable_audit_log_stops_the_start() -> TestResult {
    let dir = tempdir()?;
    let server = server_file(dir.path())?;
    let gateway = GatewayFile {
        audit_file: dir.path().join("missing").join("audit.log"),
        ..gateway_file(dir.path(), "{}\n")?
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let outcome = run_gateway(server, gateway, listener, Box::pin(async {})).await;
    assert!(matches!(outcome, Err(GatewayError::Audit(_))));
    Ok(())
}


#[tokio::test]
async fn a_server_that_cannot_start_is_reported() -> TestResult {
    let dir = tempdir()?;
    let server = ServerFile {
        certificate: dir.path().join("missing.crt"),
        ..server_file(dir.path())?
    };
    let gateway = gateway_file(dir.path(), "{}\n")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let outcome = run_gateway(server, gateway, listener, Box::pin(async {})).await;
    assert!(matches!(outcome, Err(GatewayError::App(_))));
    Ok(())
}


#[test]
fn the_gateway_file_loads_and_refuses_unknown_keys() -> TestResult {
    let dir = tempdir()?;
    let good = dir.path().join("good.yaml");
    fs::write(
        &good,
        "settings_file: /etc/ostyr/gateway.yaml\naudit_file: /var/log/ostyr/gateway-audit.log\n",
    )?;
    assert_eq!(load_gateway_file(&good)?.settings_file, Path::new("/etc/ostyr/gateway.yaml"));
    let bad = dir.path().join("bad.yaml");
    fs::write(&bad, "settings_file: /a\naudit_file: /b\nextra: 1\n")?;
    assert!(matches!(load_gateway_file(&bad), Err(GatewayError::Config(_))));
    Ok(())
}

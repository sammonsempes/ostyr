use crate::certs::{loopback, make_pki};
use crate::fake::{always, start, Mode, Reply};
use crate::settings_for;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{reload, ReloadContext, ReloadOutcome};
use core_pg::connect::{connect, connect_current, connect_with_driver};
use core_pg::error::PgError;
use core_pg::query::execute_script;
use core_pg::settings::open_settings;
use rcgen::SanType;
use std::error::Error;
use std::fs;
use std::io;
use std::time::Duration;
use tempfile::tempdir;


const DEADLINE: Duration = Duration::from_secs(30);


const SHORT_CONNECT_SECS: u64 = 5;


#[tokio::test]
async fn connects_over_verified_tls_and_sends_the_password_read_from_the_file() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let mut fake = start(Mode::Tls(pki.server), "s3cret", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "s3cret\n", DEADLINE.as_secs())?;
    let client = connect(&settings).await?;
    execute_script(&client, "SELECT 1", DEADLINE).await?;
    assert_eq!(fake.passwords.recv().await.ok_or("no password")?, b"s3cret");
    assert!(fake
        .statements
        .recv()
        .await
        .ok_or("no statement")?
        .starts_with("SET statement_timeout = 30000; SELECT 1"));
    Ok(())
}


#[tokio::test]
async fn a_wrong_password_is_reduced_to_its_sqlstate() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Tls(pki.server), "right", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "wrong-password", DEADLINE.as_secs())?;
    let error = connect(&settings).await.err().ok_or("connected")?;
    assert!(matches!(&error, PgError::Server { code, .. } if code == "28P01"), "{error}");
    assert!(!format!("{error} {error:?}").contains("wrong-password"));
    Ok(())
}


#[tokio::test]
async fn an_unknown_ca_is_refused() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let other = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Tls(pki.server), "p", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &other.ca_pem, "p", DEADLINE.as_secs())?;
    assert!(matches!(connect(&settings).await, Err(PgError::Client(_))));
    Ok(())
}


#[tokio::test]
async fn a_certificate_for_another_host_is_refused() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::DnsName("other.example".try_into()?))?;
    let fake = start(Mode::Tls(pki.server), "p", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    assert!(matches!(connect(&settings).await, Err(PgError::Client(_))));
    Ok(())
}


#[tokio::test]
async fn a_server_without_tls_is_refused() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Plain, "p", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    assert!(matches!(connect(&settings).await, Err(PgError::Client(_))));
    Ok(())
}


#[tokio::test]
async fn missing_password_or_ca_file_fails_before_any_connection() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), 1, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    fs::remove_file(dir.path().join("ca.pem"))?;
    assert!(matches!(connect(&settings).await, Err(PgError::Io { .. })));
    fs::remove_file(dir.path().join("pg.pass"))?;
    assert!(matches!(connect(&settings).await, Err(PgError::Io { .. })));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_silent_server_hits_the_connect_deadline() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Silent, "p", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", SHORT_CONNECT_SECS)?;
    let error = connect(&settings).await.err().ok_or("connected")?;
    assert!(
        matches!(error, PgError::ConnectTimeout { seconds } if seconds == SHORT_CONNECT_SECS),
        "{error}"
    );
    Ok(())
}


#[tokio::test]
async fn dropping_the_client_ends_the_driver_quietly() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Tls(pki.server), "p", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    let (client, driver) = connect_with_driver(&settings).await?;
    drop(client);
    driver.await?;
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_ends_the_driver_and_fails_the_next_call() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_writer(io::sink)
        .try_init()
        .map_err(|error| error.to_string())?;
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = start(Mode::Tls(pki.server), "p", always(Reply::Drop)).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    let client = connect(&settings).await?;
    assert!(matches!(execute_script(&client, "SELECT 1", DEADLINE).await, Err(PgError::Client(_))));
    Ok(())
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "core-pg".to_owned(),
        tenant: "example".to_owned(),
        module: "pg".to_owned(),
        target: "pg.yaml".to_owned(),
        request_id: "reload".to_owned(),
    }
}


#[tokio::test]
async fn a_reload_changes_new_connections_and_leaves_open_ones() -> Result<(), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let mut first = start(Mode::Tls(pki.server.clone()), "one", always(Reply::Done)).await?;
    let mut second = start(Mode::Tls(pki.server), "two", always(Reply::Done)).await?;
    let dir = tempdir()?;
    let path = dir.path().join("pg.yaml");
    let settings = settings_for(dir.path(), first.port, &pki.ca_pem, "one", DEADLINE.as_secs())?;
    let text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        settings.port, settings.password_file, settings.ca_file
    );
    fs::write(&path, &text)?;
    let log = genesis_log(io::sink());
    let engine = open_settings(path.clone(), Box::new(move |entry: NewEntry| append(&log, entry)), context())?;
    let held = connect_current(&engine).await?;
    assert_eq!(first.passwords.recv().await.ok_or("no password")?, b"one");
    fs::write(&settings.password_file, "two")?;
    fs::write(&path, text.replace(&format!("port: {}", first.port), &format!("port: {}", second.port)))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let fresh = connect_current(&engine).await?;
    assert_eq!(second.passwords.recv().await.ok_or("no password")?, b"two");
    execute_script(&held, "SELECT 1", DEADLINE).await?;
    execute_script(&fresh, "SELECT 1", DEADLINE).await?;
    assert!(first.statements.recv().await.is_some() && second.statements.recv().await.is_some());
    Ok(())
}

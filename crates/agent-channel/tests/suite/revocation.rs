use crate::harness::{
    attempt, bounded, client_paths, finish, make_platform, server_paths, start_server_with, start_single, start_single_with, stop_server,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::revocation_support::{agent_serial, open_revocation, recorded_entries, write_revocations};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, heartbeat};
use agent_channel::error::{ChannelError, IdentityError, RevocationError};
use agent_channel::identity::serial_from_chain;
use agent_channel::model::{Revocations, REVOCATION_CLOSE_SECONDS};
use agent_channel::revocation::{canonical_serial, is_revoked, parse_serial, revocations_state};
use agent_channel::tls::client_config;
use core_audit::model::Outcome;
use core_config::reload::{reload, ReloadOutcome};
use std::time::Duration;
use tempfile::tempdir;
use tokio::time::timeout;


const SERIAL_COUNT: usize = 2;


const REFUSED_RELOADS: usize = 2;


#[test]
fn serials_are_normalised() -> TestResult {
    assert_eq!(parse_serial("0A:bC:01")?, "abc01");
    assert_eq!(parse_serial("  00ff ")?, "ff");
    assert_eq!(canonical_serial("00AB"), "ab");
    Ok(())
}


#[test]
fn bad_serials_are_refused() -> TestResult {
    assert!(matches!(parse_serial("xyz"), Err(RevocationError::NotHexadecimal(_))));
    assert!(matches!(parse_serial(""), Err(RevocationError::NotHexadecimal(_))));
    assert!(matches!(parse_serial("00:00"), Err(RevocationError::Zero(_))));
    Ok(())
}


#[test]
fn state_lists_one_line_per_serial() -> TestResult {
    let revocations = Revocations {
        serials: ["ab".to_owned(), "cd".to_owned()].into_iter().collect(),
    };
    let state = revocations_state(&revocations);
    assert_eq!(state.len(), SERIAL_COUNT);
    assert_eq!(state.get("revoked_serials.ab").map(String::as_str), Some("revoked"));
    assert!(is_revoked(&revocations, "cd"));
    assert!(!is_revoked(&revocations, "ef"));
    Ok(())
}


#[test]
fn chain_without_certificate_has_no_serial() -> TestResult {
    assert!(matches!(serial_from_chain(None), Err(IdentityError::NoCertificate)));
    Ok(())
}


#[test]
fn opening_with_an_invalid_file_fails() -> TestResult {
    let dir = tempdir()?;
    assert!(open_revocation(dir.path(), &["not-hex"]).is_err());
    Ok(())
}


#[tokio::test]
async fn revoked_serial_is_refused_at_the_handshake() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let serial = agent_serial(&paths)?;
    let server_files = server_paths(dir.path(), &platform)?;
    let server = start_single_with(&server_files, open_revocation(dir.path(), &[serial.as_str()])?).await?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Revoked { serial: refused }) if refused == serial));
    Ok(())
}


#[tokio::test]
async fn revoking_a_connected_agent_closes_its_connection_within_the_bound() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let serial = agent_serial(&paths)?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let channel = connect_channel(server.address, client_config(&paths)?, SERVER_NAME).await?;
    let reply = bounded(heartbeat(channel.clone(), "test")).await??;
    assert_eq!(reply.agent_id, "agent-1");
    write_revocations(&server.control.file, &[serial.as_str()])?;
    assert!(matches!(reload(&server.control.engine), ReloadOutcome::Applied { .. }));
    let closed = timeout(Duration::from_secs(REVOCATION_CLOSE_SECONDS), server.handle).await??;
    assert!(matches!(closed, Err(ChannelError::Revoked { serial: refused }) if refused == serial));
    assert!(bounded(heartbeat(channel, "test")).await?.is_err());
    Ok(())
}


#[tokio::test]
async fn invalid_file_keeps_the_old_list_and_is_audited_denied() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let serial = agent_serial(&paths)?;
    let server_files = server_paths(dir.path(), &platform)?;
    let server = start_server_with(&server_files, open_revocation(dir.path(), &[serial.as_str()])?).await?;
    write_revocations(&server.control.file, &["zz"])?;
    let outcome = reload(&server.control.engine);
    assert!(matches!(outcome, ReloadOutcome::Refused { .. }));
    std::fs::write(&server.control.file, "revoked_serials: [\n")?;
    assert!(matches!(reload(&server.control.engine), ReloadOutcome::Refused { .. }));
    let entries = recorded_entries(&server.control)?;
    assert_eq!(entries.len(), REFUSED_RELOADS);
    assert!(entries
        .iter()
        .all(|entry| entry.action == "config.reload" && entry.outcome == Outcome::Denied));
    assert!(bounded(attempt(server.address, &paths)).await?.is_err());
    stop_server(server).await
}


#[tokio::test]
async fn removing_the_serial_lets_the_agent_reconnect() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let serial = agent_serial(&paths)?;
    let server_files = server_paths(dir.path(), &platform)?;
    let server = start_server_with(&server_files, open_revocation(dir.path(), &[serial.as_str()])?).await?;
    assert!(bounded(attempt(server.address, &paths)).await?.is_err());
    write_revocations(&server.control.file, &[])?;
    assert!(matches!(reload(&server.control.engine), ReloadOutcome::Applied { .. }));
    let reply = bounded(attempt(server.address, &paths)).await??;
    assert_eq!(reply.agent_id, "agent-1");
    let entries = recorded_entries(&server.control)?;
    assert_eq!(entries.iter().filter(|entry| entry.outcome == Outcome::Success).count(), 1);
    stop_server(server).await
}


#[tokio::test]
async fn dropping_the_revocation_engine_closes_connections() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let channel = connect_channel(server.address, client_config(&paths)?, SERVER_NAME).await?;
    bounded(heartbeat(channel.clone(), "test")).await??;
    let handle = server.handle;
    drop(server.control);
    let closed = timeout(Duration::from_secs(REVOCATION_CLOSE_SECONDS), handle).await??;
    assert!(matches!(closed, Err(ChannelError::RevocationClosed(_))));
    drop(channel);
    Ok(())
}

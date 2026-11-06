use crate::harness::{client_paths, make_platform, server_paths};
use crate::pki::{agent_spec, issue, make_authority, server_spec, set_mode, write_file, write_leaf, AGENT_URI, PRIVATE_MODE, WORLD_READABLE_MODE};
use crate::types::TestResult;
use agent_channel::error::ChannelError;
use agent_channel::tls::{client_config, parse_private_key, read_certificates, read_private_key, root_store, server_config};
use secrecy::ExposeSecret;
use std::fs;
use tempfile::tempdir;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const BROKEN_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n";


const JUNK_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";


#[test]
fn key_file_readable_by_others_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let leaf = issue(&platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let path = write_file(dir.path(), "agent.key", &leaf.key_pem, WORLD_READABLE_MODE)?;
    assert!(matches!(read_private_key(&path), Err(ChannelError::KeyPermissions { .. })));
    Ok(())
}


#[test]
fn group_readable_key_is_refused_by_both_configurations() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let mut server = server_paths(dir.path(), &platform)?;
    let mut client = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    server.key = write_file(dir.path(), "loose-server.key", &fs::read_to_string(&server.key)?, WORLD_READABLE_MODE)?;
    client.key = write_file(dir.path(), "loose-agent.key", &fs::read_to_string(&client.key)?, WORLD_READABLE_MODE)?;
    assert!(matches!(server_config(&server), Err(ChannelError::KeyPermissions { .. })));
    assert!(matches!(client_config(&client), Err(ChannelError::KeyPermissions { .. })));
    Ok(())
}


#[test]
fn private_key_file_is_read_and_debug_is_redacted() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let leaf = issue(&platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let path = write_file(dir.path(), "agent.key", &leaf.key_pem, PRIVATE_MODE)?;
    let key = read_private_key(&path)?;
    let body = leaf.key_pem.lines().nth(1).ok_or("no key body")?;
    let rendered = format!("{key:?}");
    assert_eq!(key.pem.expose_secret(), leaf.key_pem.as_str());
    assert!(!rendered.contains(body));
    assert!(!rendered.contains("PRIVATE KEY"));
    assert!(rendered.contains("REDACTED"));
    Ok(())
}


#[test]
fn missing_and_non_utf8_key_files_are_io_errors() -> TestResult {
    let dir = tempdir()?;
    let binary = dir.path().join("binary.key");
    fs::write(&binary, INVALID_UTF8)?;
    set_mode(&binary, PRIVATE_MODE)?;
    assert!(matches!(read_private_key(&dir.path().join("absent.key")), Err(ChannelError::Io { .. })));
    assert!(matches!(read_private_key(&binary), Err(ChannelError::Io { .. })));
    Ok(())
}


#[test]
fn garbage_private_key_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = write_file(dir.path(), "garbage.key", "not a key", PRIVATE_MODE)?;
    let key = read_private_key(&path)?;
    assert!(matches!(parse_private_key(&key, &path), Err(ChannelError::Pem { .. })));
    Ok(())
}


#[test]
fn certificate_files_are_validated() -> TestResult {
    let dir = tempdir()?;
    let empty = write_file(dir.path(), "empty.pem", "", WORLD_READABLE_MODE)?;
    let broken = write_file(dir.path(), "broken.pem", BROKEN_CERTIFICATE_PEM, WORLD_READABLE_MODE)?;
    assert!(matches!(read_certificates(&dir.path().join("absent.pem")), Err(ChannelError::Pem { .. })));
    assert!(matches!(read_certificates(&empty), Err(ChannelError::NoCertificate { .. })));
    assert!(matches!(read_certificates(&broken), Err(ChannelError::Pem { .. })));
    Ok(())
}


#[test]
fn root_store_refuses_an_unparsable_certificate() -> TestResult {
    let dir = tempdir()?;
    let junk = write_file(dir.path(), "junk.pem", JUNK_CERTIFICATE_PEM, WORLD_READABLE_MODE)?;
    assert!(matches!(root_store(&junk), Err(ChannelError::Tls(_))));
    Ok(())
}


#[test]
fn mismatched_certificate_and_key_are_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let other = make_authority()?;
    let mut server = server_paths(dir.path(), &platform)?;
    let mut client = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let stranger = write_leaf(dir.path(), "stranger", &issue(&other, &server_spec())?)?;
    server.key = stranger.key.clone();
    client.key = stranger.key;
    assert!(matches!(server_config(&server), Err(ChannelError::Tls(_))));
    assert!(matches!(client_config(&client), Err(ChannelError::Tls(_))));
    Ok(())
}


#[test]
fn valid_files_build_both_configurations() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    server_config(&server_paths(dir.path(), &platform)?)?;
    client_config(&client_paths(
        dir.path(),
        "agent",
        &platform,
        &platform.agent_ca,
        &agent_spec(&[AGENT_URI]),
    )?)?;
    Ok(())
}

use crate::support::{captured_logs, scoped_logging};
use crate::types::TestResult;
use agent_channel::agent_app::AgentFile;
use agent_linux::shell::{
    broken_dial, fault_of, judge_bytes, prepared_dial, read_switch, read_switch_bytes, read_switch_with, shell_dial, store_path, switch_enabled,
    switch_fn, switch_path, SwitchCause, SwitchState, DISABLED_BYTES, ENABLED_BYTES, MAX_SWITCH_BYTES, SWITCH_FILE,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;


const PRIVATE_FILE: u32 = 0o600;


const GROUP_WRITABLE: u32 = 0o620;


const OTHER_WRITABLE: u32 = 0o602;


const READABLE_BY_ALL: u32 = 0o644;


const LONG_FACTOR: usize = 4;


const TWO_CAUSES: usize = 2;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


fn switch_with(directory: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join(SWITCH_FILE);
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}


fn owner_of(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(fs::metadata(path)?.uid())
}


fn fails(_file: &File) -> io::Result<fs::Metadata> {
    Err(io::Error::other("inspect failed"))
}


#[test]
fn only_the_two_exact_texts_count() -> TestResult {
    assert_eq!(judge_bytes(ENABLED_BYTES), SwitchState::Enabled);
    assert_eq!(judge_bytes(DISABLED_BYTES), SwitchState::Disabled);
    let refused = SwitchState::Refused(SwitchCause::Bytes);
    for text in [
        &b"enabled: yes\n"[..],
        b"enabled: true",
        b"\xef\xbb\xbfenabled: true\n",
        b"enabled: true\r\n",
        b"enabled: true\n\n",
        b"enabled: True\n",
        b"enabled:  true\n",
        b"",
    ] {
        assert_eq!(judge_bytes(text), refused, "{text:?}");
    }
    Ok(())
}


#[test]
fn the_switch_is_read_from_the_checked_handle() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let enabled = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    assert_eq!(read_switch(&enabled, owner), SwitchState::Enabled);
    switch_with(directory.path(), DISABLED_BYTES, PRIVATE_FILE)?;
    assert_eq!(read_switch(&enabled, owner), SwitchState::Disabled);
    switch_with(directory.path(), DISABLED_BYTES, READABLE_BY_ALL)?;
    assert_eq!(read_switch(&enabled, owner), SwitchState::Disabled);
    Ok(())
}


#[test]
fn an_absent_or_odd_file_is_disabled_and_the_others_are_named() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let path = directory.path().join(SWITCH_FILE);
    assert_eq!(read_switch(&path, owner), SwitchState::Disabled);
    switch_with(directory.path(), b"enabled: yes\n", PRIVATE_FILE)?;
    assert_eq!(read_switch(&path, owner), SwitchState::Refused(SwitchCause::Bytes));
    switch_with(directory.path(), ENABLED_BYTES, GROUP_WRITABLE)?;
    assert_eq!(read_switch(&path, owner), SwitchState::Refused(SwitchCause::Writable));
    switch_with(directory.path(), ENABLED_BYTES, OTHER_WRITABLE)?;
    assert_eq!(read_switch(&path, owner), SwitchState::Refused(SwitchCause::Writable));
    switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    assert_eq!(read_switch(&path, owner.wrapping_add(1)), SwitchState::Refused(SwitchCause::Owner));
    let oversized = vec![b'x'; usize::try_from(MAX_SWITCH_BYTES)? * LONG_FACTOR];
    switch_with(directory.path(), &oversized, PRIVATE_FILE)?;
    assert_eq!(read_switch(&path, owner), SwitchState::Refused(SwitchCause::Bytes));
    Ok(())
}


#[test]
fn a_link_a_directory_or_an_uninspectable_handle_is_refused_by_name() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let target = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    let link = directory.path().join("link.yaml");
    symlink(&target, &link)?;
    assert!(matches!(read_switch(&link, owner), SwitchState::Refused(SwitchCause::Unreadable(_))));
    assert_eq!(read_switch(directory.path(), owner), SwitchState::Refused(SwitchCause::NotRegular));
    assert!(matches!(
        read_switch_with(&target, owner, fails),
        SwitchState::Refused(SwitchCause::Unreadable(_))
    ));
    assert_eq!(read_switch_with(&target, owner, File::metadata), SwitchState::Enabled);
    Ok(())
}


#[test]
fn a_failing_read_and_a_long_read_are_bounded_and_named() -> TestResult {
    let _log = scoped_logging();
    assert!(matches!(read_switch_bytes(&mut Failing).err(), Some(SwitchCause::Unreadable(_))));
    let long = vec![b'a'; usize::try_from(MAX_SWITCH_BYTES)? * LONG_FACTOR];
    assert_eq!(
        read_switch_bytes(&mut long.as_slice()).map(|bytes| bytes.len()),
        Ok(usize::try_from(MAX_SWITCH_BYTES)? + 1)
    );
    Ok(())
}


#[test]
fn the_fault_names_the_kind_the_owner_and_the_mode() -> TestResult {
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let path = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    let metadata = fs::metadata(&path)?;
    assert_eq!(fault_of(&metadata, owner), None);
    assert_eq!(fault_of(&metadata, owner.wrapping_add(1)), Some(SwitchCause::Owner));
    assert_eq!(fault_of(&fs::metadata(directory.path())?, owner), Some(SwitchCause::NotRegular));
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(fault_of(&fs::metadata(&path)?, owner), Some(SwitchCause::Writable));
    Ok(())
}


#[test]
fn a_refusal_is_logged_once_per_distinct_cause() -> TestResult {
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let path = switch_with(directory.path(), ENABLED_BYTES, GROUP_WRITABLE)?;
    let seen = Mutex::new(None);
    let logged = captured_logs(|| {
        assert!(!switch_enabled(&path, owner, &seen));
        assert!(!switch_enabled(&path, owner, &seen));
        assert!(!switch_enabled(&path, owner.wrapping_add(1), &seen));
        assert!(!switch_enabled(&path, owner.wrapping_add(1), &seen));
    })?;
    assert_eq!(logged.matches("stays disabled").count(), TWO_CAUSES, "{logged}");
    assert!(logged.contains("Writable") && logged.contains("Owner"), "{logged}");
    fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE))?;
    let enabled_again = captured_logs(|| assert!(switch_enabled(&path, owner, &seen)))?;
    assert!(enabled_again.is_empty(), "{enabled_again}");
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    let refused_again = captured_logs(|| assert!(!switch_enabled(&path, owner, &seen)))?;
    assert_eq!(refused_again.matches("stays disabled").count(), 1, "{refused_again}");
    Ok(())
}


#[test]
fn a_poisoned_log_memory_does_not_stop_the_switch() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let path = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    let seen: Mutex<Option<SwitchCause>> = Mutex::new(None);
    let poisoned = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _held = seen.lock();
                std::panic::resume_unwind(Box::new("poison"))
            })
            .join()
            .is_err()
    });
    assert!(poisoned);
    assert!(switch_enabled(&path, owner, &seen));
    Ok(())
}


#[test]
fn the_production_switch_wants_a_root_owned_file_and_reads_it_afresh() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let path = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    let enabled = switch_fn(path.clone());
    let root_owned = owner_of(&path)? == 0;
    assert_eq!(enabled(), root_owned);
    fs::remove_file(&path)?;
    assert!(!enabled());
    Ok(())
}


#[test]
fn the_switch_and_the_store_sit_next_to_their_anchors() -> TestResult {
    assert_eq!(switch_path(Path::new("/etc/ostyr/linux.yaml")), PathBuf::from("/etc/ostyr/shell.yaml"));
    assert_eq!(store_path(Path::new("/var/lib/ostyr/cursor")), PathBuf::from("/var/lib/ostyr/shell"));
    Ok(())
}


fn write_mode(directory: &Path, name: &str, text: &str, mode: u32) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join(name);
    fs::write(&path, text)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}


fn agent_with(directory: &Path, server: &str) -> Result<AgentFile, Box<dyn std::error::Error>> {
    let authority_key = KeyPair::generate()?;
    let mut authority_params = CertificateParams::new(Vec::<String>::new())?;
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let authority = authority_params.self_signed(&authority_key)?;
    let issuer = Issuer::new(authority_params, authority_key);
    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec!["agent.test".to_owned()])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
    Ok(AgentFile {
        server: server.to_owned(),
        server_name: "localhost".to_owned(),
        certificate: write_mode(directory, "agent.crt", &leaf.pem(), READABLE_BY_ALL)?,
        key: write_mode(directory, "agent.key", &leaf_key.serialize_pem(), PRIVATE_FILE)?,
        platform_ca: write_mode(directory, "ca.crt", &authority.pem(), READABLE_BY_ALL)?,
        tenant: "t1".to_owned(),
        agent_id: "a1".to_owned(),
        keys_file: directory.join("keys"),
        state_file: directory.join("state"),
        audit_file: directory.join("audit"),
        spool_file: directory.join("spool"),
        sequence_file: directory.join("sequence"),
        executed_file: directory.join("executed"),
    })
}


#[tokio::test]
async fn the_shell_dial_is_built_once_from_the_agent_file() -> TestResult {
    let _log = scoped_logging();
    let directory = tempdir()?;
    let agent = agent_with(directory.path(), "127.0.0.1:1")?;
    assert!(prepared_dial(&agent).is_ok());
    drop(shell_dial(&agent));
    let wrong_address = agent_with(directory.path(), "not an address")?;
    assert!(prepared_dial(&wrong_address).is_err());
    let missing = AgentFile {
        certificate: directory.path().join("absent.crt"),
        ..agent_with(directory.path(), "127.0.0.1:1")?
    };
    assert!(prepared_dial(&missing).is_err());
    let broken = shell_dial(&missing);
    assert!(matches!(broken().await, Err(agent_channel::error::ChannelError::Io { .. })));
    let direct = broken_dial(&missing);
    assert!(direct().await.is_err());
    Ok(())
}


#[test]
fn an_unreadable_switch_is_logged_once_with_its_kind_and_never_per_read() -> TestResult {
    let directory = tempdir()?;
    let owner = owner_of(directory.path())?;
    let target = switch_with(directory.path(), ENABLED_BYTES, PRIVATE_FILE)?;
    let link = directory.path().join("link.yaml");
    symlink(&target, &link)?;
    let seen = Mutex::new(None);
    let logged = captured_logs(|| {
        assert!(!switch_enabled(&link, owner, &seen));
        assert!(!switch_enabled(&link, owner, &seen));
        assert!(!switch_enabled(&link, owner, &seen));
    })?;
    assert_eq!(logged.matches("stays disabled").count(), 1, "{logged}");
    assert_eq!(logged.matches("cannot be").count(), 0, "{logged}");
    assert!(logged.contains("Unreadable("), "{logged}");
    Ok(())
}

#![cfg(unix)]


#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{handle_facts, judge_handle, open_file_log, open_file_log_capped, HandleFacts};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use types::TestResult;


const OWN_UID: u32 = 1000;


const OTHER_UID: u32 = 1001;


const LIMIT: u64 = 10;


const GROUP_READABLE: u32 = 0o640;


const OWNER_ONLY: u32 = 0o600;


const PRIVATE_MODE: u32 = 0o100_600;


const TWO_LINKS: u64 = 2;


const OVER_CAP_LEN: u64 = 5;


const THREE_BYTES: u64 = 3;


const SMALL_CAP: u64 = 4;


const OVER_CAP_BYTES: &[u8] = b"12345";


fn facts() -> HandleFacts {
    HandleFacts {
        regular: true,
        owner: OWN_UID,
        links: 1,
        mode: PRIVATE_MODE,
        size: 0,
    }
}


fn fifo_at(path: &Path) -> TestResult {
    assert!(Command::new("mkfifo").arg("-m").arg("600").arg(path).status()?.success());
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    fifo_at(&path)?;
    assert!(matches!(open_file_log(&path), Err(AuditError::NotRegularFile)));
    Ok(())
}


#[test]
fn a_symlink_is_refused_whatever_it_points_at() -> TestResult {
    let dir = tempdir()?;
    let fifo = dir.path().join("fifo");
    fifo_at(&fifo)?;
    let to_fifo = dir.path().join("to_fifo.log");
    symlink(&fifo, &to_fifo)?;
    let to_device = dir.path().join("to_zero.log");
    symlink("/dev/zero", &to_device)?;
    let regular = dir.path().join("real.log");
    fs::write(&regular, b"")?;
    fs::set_permissions(&regular, fs::Permissions::from_mode(OWNER_ONLY))?;
    let to_regular = dir.path().join("to_real.log");
    symlink(&regular, &to_regular)?;
    for link in [&to_fifo, &to_device, &to_regular] {
        assert!(matches!(open_file_log(link), Err(AuditError::SymlinkRefused)));
    }
    Ok(())
}


#[test]
fn a_directory_or_a_missing_parent_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(open_file_log(dir.path()), Err(AuditError::Io(_))));
    assert!(matches!(
        open_file_log(&dir.path().join("absent").join("audit.log")),
        Err(AuditError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_file_with_two_links_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    fs::hard_link(&path, dir.path().join("second.log"))?;
    assert!(matches!(open_file_log(&path), Err(AuditError::LinkedFile { links: TWO_LINKS })));
    Ok(())
}


#[test]
fn a_group_readable_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_READABLE))?;
    assert!(matches!(
        open_file_log(&path),
        Err(AuditError::InsecurePermissions { mode: GROUP_READABLE })
    ));
    Ok(())
}


#[test]
fn a_log_over_the_cap_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    fs::write(&path, OVER_CAP_BYTES)?;
    assert!(matches!(
        open_file_log_capped(&path, SMALL_CAP),
        Err(AuditError::LogTooLarge {
            size: OVER_CAP_LEN,
            max: SMALL_CAP
        })
    ));
    Ok(())
}


#[test]
fn the_judgement_names_each_refusal() -> TestResult {
    assert!(judge_handle(&facts(), OWN_UID, LIMIT).is_ok());
    let not_regular = HandleFacts { regular: false, ..facts() };
    assert!(matches!(judge_handle(&not_regular, OWN_UID, LIMIT), Err(AuditError::NotRegularFile)));
    assert!(matches!(
        judge_handle(&facts(), OTHER_UID, LIMIT),
        Err(AuditError::ForeignOwner {
            owner: OWN_UID,
            expected: OTHER_UID
        })
    ));
    let linked = HandleFacts { links: 0, ..facts() };
    assert!(matches!(judge_handle(&linked, OWN_UID, LIMIT), Err(AuditError::LinkedFile { links: 0 })));
    let big = HandleFacts { size: LIMIT + 1, ..facts() };
    assert!(matches!(judge_handle(&big, OWN_UID, LIMIT), Err(AuditError::LogTooLarge { .. })));
    Ok(())
}


#[test]
fn the_facts_come_from_the_handle() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("plain");
    fs::write(&path, b"abc")?;
    let found = handle_facts(&fs::File::open(&path)?)?;
    assert!(found.regular && found.links == 1 && found.size == THREE_BYTES);
    Ok(())
}

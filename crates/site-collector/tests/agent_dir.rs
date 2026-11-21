#![cfg(unix)]
#[path = "support/types.rs"]
mod types;


use agent_channel::error::{AppError, SpoolDirReason};
use agent_channel::spool::{append_back, effective_uid};
use site_collector::agent_dir::{open_agent_spool, open_agent_spool_as, through_handle, user_fault, AgentSpool};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{chown, symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const PRIVATE_MODE: u32 = 0o700;


const READABLE_MODE: u32 = 0o755;


const GROUP_WRITABLE_MODE: u32 = 0o770;


const OTHER_USER: u32 = 65534;


const DESCRIPTOR: i32 = 7;


const LINE: &str = "{\"event\":1}";


fn private_directory(parent: &Path, name: &str) -> Result<PathBuf, std::io::Error> {
    let directory = parent.join(name);
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(directory)
}


fn refusal(result: Result<AgentSpool, AppError>) -> Option<SpoolDirReason> {
    match result {
        Err(AppError::SpoolDir { reason, .. }) => Some(reason),
        _ => None,
    }
}


#[test]
fn a_correct_layout_forwards_through_the_judged_handle() -> TestResult {
    let root = TempDir::new()?;
    let directory = private_directory(root.path(), "agent")?;
    let judged = open_agent_spool(&directory.join("spool"))?;
    assert!(append_back(std::iter::once(Ok(LINE.to_owned())), &judged.spool_path)?);
    assert_eq!(fs::read_to_string(directory.join("spool"))?, format!("{LINE}\n"));
    Ok(())
}


#[test]
fn a_group_writable_directory_is_refused_before_any_append() -> TestResult {
    let root = TempDir::new()?;
    let directory = private_directory(root.path(), "agent")?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(GROUP_WRITABLE_MODE))?;
    assert_eq!(refusal(open_agent_spool(&directory.join("spool"))), Some(SpoolDirReason::Writable));
    assert_eq!(fs::read_dir(&directory)?.count(), 0);
    Ok(())
}


#[test]
fn a_symlinked_directory_is_refused() -> TestResult {
    let root = TempDir::new()?;
    let real = private_directory(root.path(), "real")?;
    let link = root.path().join("link");
    symlink(&real, &link)?;
    assert_eq!(refusal(open_agent_spool(&link.join("spool"))), Some(SpoolDirReason::NotDirectory));
    assert_eq!(fs::read_dir(&real)?.count(), 0);
    Ok(())
}


#[test]
fn a_directory_of_another_user_is_refused() -> TestResult {
    let root = TempDir::new()?;
    let directory = private_directory(root.path(), "agent")?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(READABLE_MODE))?;
    chown(&directory, Some(OTHER_USER), None)?;
    assert_eq!(refusal(open_agent_spool(&directory.join("spool"))), Some(SpoolDirReason::WrongOwner));
    assert_eq!(fs::read_dir(&directory)?.count(), 0);
    Ok(())
}


#[test]
fn a_collector_user_other_than_the_owner_is_refused() -> TestResult {
    let root = TempDir::new()?;
    let directory = private_directory(root.path(), "agent")?;
    let other = effective_uid().wrapping_add(1);
    assert_eq!(
        refusal(open_agent_spool_as(&directory.join("spool"), other)),
        Some(SpoolDirReason::WrongOwner)
    );
    assert_eq!(fs::read_dir(&directory)?.count(), 0);
    Ok(())
}


#[test]
fn the_user_rule_names_only_a_mismatch() -> TestResult {
    assert_eq!(user_fault(0, 0), None);
    assert_eq!(user_fault(0, 1), Some(SpoolDirReason::WrongOwner));
    assert_eq!(user_fault(1, 0), Some(SpoolDirReason::WrongOwner));
    Ok(())
}


#[test]
fn a_missing_directory_and_a_nameless_path_are_refused() -> TestResult {
    let root = TempDir::new()?;
    assert_eq!(
        refusal(open_agent_spool(&root.path().join("absent").join("spool"))),
        Some(SpoolDirReason::Missing)
    );
    let directory = private_directory(root.path(), "agent")?;
    assert_eq!(refusal(open_agent_spool(&directory.join(".."))), Some(SpoolDirReason::NotDirectory));
    assert_eq!(refusal(open_agent_spool(Path::new("/"))), Some(SpoolDirReason::NotDirectory));
    Ok(())
}


#[test]
fn a_directory_swapped_for_a_symlink_after_the_check_is_not_followed() -> TestResult {
    let root = TempDir::new()?;
    let directory = private_directory(root.path(), "agent")?;
    let attacker = private_directory(root.path(), "attacker")?;
    let judged = open_agent_spool(&directory.join("spool"))?;
    let moved = root.path().join("moved");
    fs::rename(&directory, &moved)?;
    symlink(&attacker, &directory)?;
    assert!(append_back(std::iter::once(Ok(LINE.to_owned())), &judged.spool_path)?);
    assert_eq!(fs::read_to_string(moved.join("spool"))?, format!("{LINE}\n"));
    assert_eq!(fs::read_dir(&attacker)?.count(), 0);
    Ok(())
}


#[test]
fn the_handle_path_names_the_descriptor_and_the_file() -> TestResult {
    assert_eq!(through_handle(DESCRIPTOR, OsStr::new("spool")), Path::new("/proc/self/fd/7/spool"));
    Ok(())
}

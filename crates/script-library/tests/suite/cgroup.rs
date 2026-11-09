use crate::common::{refusal, refusal_io};
use crate::types::TestResult;
use script_library::cgroup::{
    create_cgroup, is_cgroup2, kill_cgroup, pause_briefly, place_in_cgroup, remove_cgroup, write_control, KILL_FILE, PROCS_FILE, REMOVE_ATTEMPTS,
};
use script_library::error::ScriptError;
use script_library::fsdir::open_directory;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;


pub const PID: u32 = 4242;


pub const BUSY_ATTEMPTS: u32 = 3;


pub fn accept(_directory: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(true)
}


pub fn reject(_directory: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(false)
}


pub fn fail(_directory: BorrowedFd<'_>) -> io::Result<bool> {
    Err(io::Error::other("injected check failure"))
}


#[test]
fn control_files_are_written_never_created() -> TestResult {
    let root = tempfile::tempdir()?;
    let guard = create_cgroup(root.path(), "one", accept)?;
    assert!(guard.path.ends_with("cg-one"));
    assert!(refusal_io(place_in_cgroup(&guard.path, PID))?.kind() == io::ErrorKind::NotFound);
    assert!(refusal_io(kill_cgroup(&guard.path))?.kind() == io::ErrorKind::NotFound);
    assert!(!guard.path.join(PROCS_FILE).exists());
    std::fs::write(guard.path.join(PROCS_FILE), "")?;
    std::fs::write(guard.path.join(KILL_FILE), "")?;
    place_in_cgroup(&guard.path, PID)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(PROCS_FILE))?, PID.to_string());
    kill_cgroup(&guard.path)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(KILL_FILE))?, "1");
    write_control(&guard.path, KILL_FILE, "1")?;
    assert!(matches!(
        refusal(create_cgroup(root.path(), "one", accept).map(drop))?,
        ScriptError::Io { .. }
    ));
    Ok(())
}


#[test]
fn a_directory_that_is_not_cgroup_v2_is_refused_and_nothing_is_created() -> TestResult {
    let root = tempfile::tempdir()?;
    assert!(matches!(
        refusal(create_cgroup(root.path(), "plain", is_cgroup2).map(drop))?,
        ScriptError::NotCgroupV2
    ));
    assert!(matches!(
        refusal(create_cgroup(root.path(), "plain", reject).map(drop))?,
        ScriptError::NotCgroupV2
    ));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    assert!(!is_cgroup2(open_directory(root.path())?.as_fd())?);
    assert!(matches!(
        refusal(create_cgroup(root.path(), "broken", fail).map(drop))?,
        ScriptError::Io { context, .. } if context.contains("cgroup")
    ));
    assert!(matches!(
        refusal(create_cgroup(&root.path().join("absent"), "x", accept).map(drop))?,
        ScriptError::Io { .. }
    ));
    Ok(())
}


#[test]
fn an_empty_cgroup_is_removed_on_drop_and_a_busy_one_is_only_logged() -> TestResult {
    let root = tempfile::tempdir()?;
    let removed = create_cgroup(root.path(), "empty", accept)?;
    let removed_path = removed.path.clone();
    drop(removed);
    assert!(!removed_path.exists());
    let stuck = create_cgroup(root.path(), "stuck", accept)?;
    let stuck_path = stuck.path.clone();
    std::fs::write(stuck_path.join("member"), "")?;
    drop(stuck);
    assert!(stuck_path.exists());
    Ok(())
}


#[test]
fn only_a_busy_cgroup_is_retried_and_the_attempts_are_capped() -> TestResult {
    let mut calls = 0;
    let mut pauses = 0;
    remove_cgroup(
        Path::new("/x"),
        &mut |_path| {
            calls += 1;
            if calls < BUSY_ATTEMPTS {
                Err(io::Error::from(io::ErrorKind::ResourceBusy))
            } else {
                Ok(())
            }
        },
        &mut || pauses += 1,
    )?;
    assert_eq!((calls, pauses), (BUSY_ATTEMPTS, BUSY_ATTEMPTS - 1));
    let mut pauses_when_stuck = 0;
    let stuck = refusal_io(remove_cgroup(
        Path::new("/x"),
        &mut |_path| Err(io::Error::from(io::ErrorKind::ResourceBusy)),
        &mut || pauses_when_stuck += 1,
    ))?;
    assert_eq!(stuck.kind(), io::ErrorKind::ResourceBusy);
    assert_eq!(pauses_when_stuck, REMOVE_ATTEMPTS);
    let mut other_calls = 0;
    let other = refusal_io(remove_cgroup(
        Path::new("/x"),
        &mut |_path| {
            other_calls += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        },
        &mut || (),
    ))?;
    assert_eq!((other.kind(), other_calls), (io::ErrorKind::PermissionDenied, 1));
    Ok(())
}


#[test]
fn the_pause_between_attempts_returns() -> TestResult {
    pause_briefly();
    Ok(())
}

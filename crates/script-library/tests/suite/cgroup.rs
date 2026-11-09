use crate::common::refusal_io;
use crate::types::TestResult;
use script_library::cgroup::{
    create_cgroup, kill_cgroup, pause_briefly, place_in_cgroup, remove_cgroup, write_control, KILL_FILE, PROCS_FILE, REMOVE_ATTEMPTS,
};
use std::io;
use std::path::Path;


pub const PID: u32 = 4242;


pub const BUSY_ATTEMPTS: u32 = 3;


#[test]
fn control_files_receive_the_pid_and_the_kill_request() -> TestResult {
    let root = tempfile::tempdir()?;
    let guard = create_cgroup(root.path(), "one")?;
    assert!(guard.path.ends_with("cg-one"));
    place_in_cgroup(&guard.path, PID)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(PROCS_FILE))?, PID.to_string());
    kill_cgroup(&guard.path)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(KILL_FILE))?, "1");
    write_control(&guard.path, KILL_FILE, "1")?;
    assert!(refusal_io(create_cgroup(root.path(), "one"))?.kind() == io::ErrorKind::AlreadyExists);
    assert!(refusal_io(kill_cgroup(&root.path().join("absent")))?.kind() == io::ErrorKind::NotFound);
    Ok(())
}


#[test]
fn an_empty_cgroup_is_removed_on_drop_and_a_busy_one_is_only_logged() -> TestResult {
    let root = tempfile::tempdir()?;
    let removed = create_cgroup(root.path(), "empty")?;
    let removed_path = removed.path.clone();
    drop(removed);
    assert!(!removed_path.exists());
    let stuck = create_cgroup(root.path(), "stuck")?;
    let stuck_path = stuck.path.clone();
    kill_cgroup(&stuck_path)?;
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

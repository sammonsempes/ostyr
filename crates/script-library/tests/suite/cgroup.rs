use crate::common::{refusal, refusal_io};
use crate::types::TestResult;
use script_library::cgroup::{
    apply_limits, create_cgroup, is_cgroup2, kill_cgroup, pause_briefly, place_in_cgroup, read_control, read_events, remove_cgroup, write_control,
    CPU_MAX_FILE, KILL_FILE, MAX_CONTROL_BYTES, MEMORY_EVENTS_FILE, MEMORY_MAX_FILE, PIDS_EVENTS_FILE, PIDS_MAX_FILE, PROCS_FILE, REMOVE_ATTEMPTS,
    SWAP_MAX_FILE,
};
use script_library::error::ScriptError;
use script_library::fsdir::open_directory;
use script_library::model::{LimitHit, Limits};
use std::io;
use std::os::fd::{AsFd, BorrowedFd};


pub const PID: u32 = 4242;


pub const BUSY_ATTEMPTS: u32 = 3;


pub const OVERSIZE_FACTOR: usize = 2;


pub const MEMORY: u64 = 4_194_304;


pub const PIDS: u64 = 8;


pub const CPU_PERCENT: u64 = 50;


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
    let leaf = guard.leaf.as_fd();
    assert!(guard.path.ends_with("cg-one"));
    assert!(refusal_io(place_in_cgroup(leaf, PID))?.kind() == io::ErrorKind::NotFound);
    assert!(refusal_io(kill_cgroup(leaf))?.kind() == io::ErrorKind::NotFound);
    assert!(!guard.path.join(PROCS_FILE).exists());
    std::fs::write(guard.path.join(PROCS_FILE), "")?;
    assert!(refusal_io(place_in_cgroup(leaf, PID))?.kind() == io::ErrorKind::NotFound);
    assert_eq!(std::fs::read_to_string(guard.path.join(PROCS_FILE))?, "");
    std::fs::write(guard.path.join(KILL_FILE), "")?;
    place_in_cgroup(leaf, PID)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(PROCS_FILE))?, PID.to_string());
    kill_cgroup(leaf)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(KILL_FILE))?, "1");
    write_control(leaf, KILL_FILE, "1")?;
    assert!(matches!(
        refusal(create_cgroup(root.path(), "one", accept).map(drop))?,
        ScriptError::Io { .. }
    ));
    Ok(())
}


#[test]
fn limits_are_written_to_the_leaf_and_a_missing_controller_fails() -> TestResult {
    let root = tempfile::tempdir()?;
    let guard = create_cgroup(root.path(), "limits", accept)?;
    let leaf = guard.leaf.as_fd();
    let limits = Limits {
        memory_bytes: MEMORY,
        pids: PIDS,
        cpu_percent: Some(CPU_PERCENT),
    };
    assert!(refusal_io(apply_limits(leaf, &limits))?.kind() == io::ErrorKind::NotFound);
    std::fs::write(guard.path.join(MEMORY_MAX_FILE), "")?;
    assert!(refusal_io(apply_limits(leaf, &limits))?.kind() == io::ErrorKind::NotFound);
    std::fs::write(guard.path.join(PIDS_MAX_FILE), "")?;
    apply_limits(leaf, &Limits { cpu_percent: None, ..limits })?;
    assert_eq!(std::fs::read_to_string(guard.path.join(MEMORY_MAX_FILE))?, MEMORY.to_string());
    assert_eq!(std::fs::read_to_string(guard.path.join(PIDS_MAX_FILE))?, PIDS.to_string());
    assert!(!guard.path.join(SWAP_MAX_FILE).exists());
    std::fs::write(guard.path.join(SWAP_MAX_FILE), "")?;
    apply_limits(leaf, &Limits { cpu_percent: None, ..limits })?;
    assert_eq!(std::fs::read_to_string(guard.path.join(SWAP_MAX_FILE))?, "0");
    assert!(refusal_io(apply_limits(leaf, &limits))?.kind() == io::ErrorKind::NotFound);
    std::fs::write(guard.path.join(CPU_MAX_FILE), "")?;
    apply_limits(leaf, &limits)?;
    assert_eq!(std::fs::read_to_string(guard.path.join(CPU_MAX_FILE))?, "50000 100000");
    let odd = create_cgroup(root.path(), "odd", accept)?;
    std::fs::write(odd.path.join(MEMORY_MAX_FILE), "")?;
    std::fs::create_dir(odd.path.join(SWAP_MAX_FILE))?;
    assert!(apply_limits(odd.leaf.as_fd(), &limits).is_err());
    Ok(())
}


#[test]
fn events_report_a_memory_kill_before_a_refused_fork() -> TestResult {
    let root = tempfile::tempdir()?;
    let guard = create_cgroup(root.path(), "events", accept)?;
    let leaf = guard.leaf.as_fd();
    assert!(refusal_io(read_events(leaf))?.kind() == io::ErrorKind::NotFound);
    let write = |memory: &str, pids: &str| -> TestResult {
        std::fs::write(guard.path.join(MEMORY_EVENTS_FILE), format!("low 0\nmax 9\noom_kill {memory}\n"))?;
        std::fs::write(guard.path.join(PIDS_EVENTS_FILE), format!("max {pids}\n"))?;
        Ok(())
    };
    write("0", "0")?;
    assert_eq!(read_events(leaf)?, None);
    write("0", "3")?;
    assert_eq!(read_events(leaf)?, Some(LimitHit::Pids));
    write("1", "0")?;
    assert_eq!(read_events(leaf)?, Some(LimitHit::Memory));
    write("1", "3")?;
    assert_eq!(read_events(leaf)?, Some(LimitHit::Memory));
    std::fs::write(guard.path.join(PIDS_EVENTS_FILE), "")?;
    assert!(refusal_io(read_events(leaf))?.kind() == io::ErrorKind::InvalidData);
    std::fs::write(guard.path.join(PIDS_EVENTS_FILE), "max many\n")?;
    assert!(refusal_io(read_events(leaf))?.kind() == io::ErrorKind::Other);
    Ok(())
}


#[test]
fn control_files_are_read_bounded() -> TestResult {
    let root = tempfile::tempdir()?;
    let guard = create_cgroup(root.path(), "bounded", accept)?;
    std::fs::write(guard.path.join("big"), "a".repeat(MAX_CONTROL_BYTES as usize * OVERSIZE_FACTOR))?;
    assert_eq!(read_control(guard.leaf.as_fd(), "big")?.len(), MAX_CONTROL_BYTES as usize);
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
        &mut || {
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
    let stuck = refusal_io(remove_cgroup(&mut || Err(io::Error::from(io::ErrorKind::ResourceBusy)), &mut || {
        pauses_when_stuck += 1
    }))?;
    assert_eq!(stuck.kind(), io::ErrorKind::ResourceBusy);
    assert_eq!(pauses_when_stuck, REMOVE_ATTEMPTS);
    let mut other_calls = 0;
    let other = refusal_io(remove_cgroup(
        &mut || {
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
